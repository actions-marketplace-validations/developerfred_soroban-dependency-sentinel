//! Output formats + top-level orchestration.

use crate::{
    analyzer, config::Config, crates_io, pg_atlas, planner, scanner, scorer, DependencyReport,
    PonySource,
};
use anyhow::Result;
use serde_json::json;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default)]
pub struct ScanOptions {
    pub deep_pony: bool,
    pub include_local: bool,
    pub offline: bool,
}

pub fn scan_project(path: &Path) -> Result<Vec<DependencyReport>> {
    scan_project_with(path, ScanOptions::default())
}

pub fn scan_project_with(path: &Path, opts: ScanOptions) -> Result<Vec<DependencyReport>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(scan_project_async(path, opts))
}

async fn scan_project_async(path: &Path, opts: ScanOptions) -> Result<Vec<DependencyReport>> {
    let cfg = Config::load(path).unwrap_or_default();
    let deps = scanner::read_lockfile(path)?;
    let local_name = read_local_package_name(path).ok();
    let mut reports = Vec::with_capacity(deps.len());

    for (name, version) in deps {
        if !opts.include_local && Some(&name) == local_name.as_ref() {
            continue;
        }
        if cfg.is_crate_ignored(&name) {
            tracing::debug!(crate_name = %name, "skipping ignored crate");
            continue;
        }

        let mut vulns = scanner::query_osv(&name, &version, opts.offline)
            .await
            .unwrap_or_default();
        vulns.retain(|v| !cfg.is_advisory_ignored(&v.id));

        let (pony_factor, pony_source) = resolve_pony(&name, opts.deep_pony, opts.offline).await;

        let worst = vulns
            .iter()
            .map(|v| v.severity.as_str())
            .max_by_key(|s| severity_rank(s))
            .unwrap_or("NONE");

        let (risk_score, classification) = scorer::score(worst, pony_factor);

        let mitigation = if !vulns.is_empty() || pony_factor == Some(1) {
            Some(planner::plan_for(!vulns.is_empty(), false, pony_factor))
        } else {
            None
        };

        reports.push(DependencyReport {
            crate_name: name,
            version,
            vulnerabilities: vulns,
            pony_factor,
            pony_source,
            risk_score,
            classification,
            mitigation,
        });
    }

    Ok(reports)
}

async fn resolve_pony(name: &str, deep: bool, offline: bool) -> (Option<u32>, PonySource) {
    if offline {
        // Offline: skip network; assume Unknown.
        return (None, PonySource::Unknown);
    }

    if let Ok(m) = pg_atlas::fetch_project(name).await {
        if let Some(f) = m.pony_factor {
            return (Some(f), PonySource::PgAtlas);
        }
    }

    if let Ok(Some(f)) = crates_io::estimate_pony_factor_from_owners(name).await {
        return (Some(f), PonySource::CratesIoOwners);
    }

    if deep {
        if let Ok(Some(repo)) = crates_io::fetch_repository_url(name).await {
            if let Ok(f) = analyzer::pony_factor_local(&repo) {
                return (Some(f), PonySource::LocalFallback);
            }
        }
    }

    (None, PonySource::Unknown)
}

fn read_local_package_name(root: &Path) -> Result<String> {
    let content = std::fs::read_to_string(root.join("Cargo.toml"))?;
    let value: toml::Value = toml::from_str(&content)?;
    Ok(value
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .ok_or_else(|| anyhow::anyhow!("no [package] name"))?
        .to_string())
}

fn severity_rank(s: &str) -> u8 {
    let s = s.to_ascii_uppercase();
    if s.contains("CRITICAL") {
        4
    } else if s.contains("HIGH") {
        3
    } else if s.contains("MEDIUM") {
        2
    } else if s.contains("LOW") {
        1
    } else {
        0
    }
}

pub fn to_sarif(reports: &[DependencyReport]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = reports
        .iter()
        .flat_map(|r| {
            r.vulnerabilities.iter().map(move |v| {
                json!({
                    "ruleId": v.id,
                    "level": if severity_rank(&v.severity) >= 3 { "error" } else { "warning" },
                    "message": {"text": format!("{} in {}@{}", v.summary, r.crate_name, r.version)},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "Cargo.lock"}}}]
                })
            })
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Soroban Dependency Sentinel",
                "version": env!("CARGO_PKG_VERSION")
            }},
            "results": results
        }]
    })
}

pub fn print_text(reports: &[DependencyReport]) {
    if reports.is_empty() {
        println!("(no dependencies found)");
        return;
    }
    println!(
        "{:<30} {:<12} {:>6} {:<10} {:>6} {:<16}",
        "crate", "version", "score", "class", "pony", "source"
    );
    for r in reports {
        println!(
            "{:<30} {:<12} {:>6.2} {:<10} {:>6} {:<16}",
            r.crate_name,
            r.version,
            r.risk_score,
            format!("{:?}", r.classification),
            r.pony_factor
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
            format!("{:?}", r.pony_source),
        );
    }
}

pub async fn explain_advisory(id: &str) -> Result<()> {
    let url = format!("https://api.osv.dev/v1/vulns/{id}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("advisory {id} not found (HTTP {})", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::{Action, MitigationPlan};
    use crate::scanner::Vulnerability;

    fn sample_report() -> DependencyReport {
        DependencyReport {
            crate_name: "serde".into(),
            version: "1.0.0".into(),
            vulnerabilities: vec![Vulnerability {
                id: "RUSTSEC-2026-0001".into(),
                summary: "test".into(),
                severity: "HIGH".into(),
                patched_versions: vec![],
            }],
            pony_factor: Some(2),
            pony_source: PonySource::PgAtlas,
            risk_score: 2.6,
            classification: scorer::Classification::High,
            mitigation: Some(MitigationPlan {
                immediate: Action {
                    action: "bump".into(),
                    rationale: "patch".into(),
                    effort: "low".into(),
                    hours: 1,
                },
                medium_term: None,
                alternatives: vec![],
            }),
        }
    }

    #[test]
    fn sarif_shape_is_valid_envelope() {
        let s = to_sarif(&[sample_report()]);
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn severity_rank_orders_correctly() {
        assert!(severity_rank("CRITICAL") > severity_rank("HIGH"));
        assert!(severity_rank("HIGH") > severity_rank("MEDIUM"));
    }
}
