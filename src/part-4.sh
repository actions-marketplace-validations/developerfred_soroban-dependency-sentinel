#!/usr/bin/env bash
# =============================================================
# Soroban Dependency Sentinel — Part 4 (fix definitivo)
# Executar DENTRO de soroban-dependency-sentinel/
# =============================================================
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
  echo "❌ Rode isso dentro de soroban-dependency-sentinel/"
  exit 1
fi

echo "🔧 [1/4] Reescrevendo Cargo.toml (deps completas)..."
cat > Cargo.toml <<'CARGO_EOF'
[package]
name = "soroban-dependency-sentinel"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"
license = "Apache-2.0"
description = "Supply-chain security scanner for Soroban projects (CVE + pony factor + mitigation)"
repository = "https://github.com/scf-public-goods/soroban-dependency-sentinel"
keywords = ["stellar", "soroban", "security", "supply-chain", "rustsec"]
categories = ["command-line-utilities", "development-tools"]

[[bin]]
name = "sentinel"
path = "src/main.rs"

[lib]
name = "sentinel"
path = "src/lib.rs"

[dependencies]
anyhow = "1"
chrono = { version = "0.4", features = ["serde"] }
clap = { version = "4", features = ["derive"] }
hex = "0.4"
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
tempfile = "3"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
assert_cmd = "2"
predicates = "3"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
CARGO_EOF
echo "  ✓ Cargo.toml reescrito"

echo "🔧 [2/4] Reescrevendo src/scanner.rs (OsvResponse com Serialize)..."
cat > src/scanner.rs <<'SCANNER_EOF'
//! RustSec / OSV.dev CVE scanner + Cargo.lock reader.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub severity: String,
    pub patched_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

/// Parse `Cargo.lock` at `<root>/Cargo.lock` into a list of (name, version).
pub fn read_lockfile(root: &Path) -> Result<Vec<(String, String)>> {
    let lock_path = root.join("Cargo.lock");
    if !lock_path.exists() {
        return Ok(vec![]);
    }

    let content = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("reading {}", lock_path.display()))?;
    let lock: toml::Value =
        toml::from_str(&content).with_context(|| "invalid Cargo.lock TOML")?;

    let packages = lock
        .get("package")
        .and_then(|v| v.as_array())
        .context("no [[package]] section in Cargo.lock")?;

    let mut out = Vec::with_capacity(packages.len());
    for pkg in packages {
        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or_default();
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !name.is_empty() && !version.is_empty() {
            out.push((name.to_string(), version.to_string()));
        }
    }
    Ok(out)
}

/// Query OSV.dev for a single crate version.
///
/// Results are cached for 24h under `~/.cache/soroban-dependency-sentinel/`.
pub async fn query_osv(crate_name: &str, version: &str) -> Result<Vec<Vulnerability>> {
    let cache_key = format!("osv:{crate_name}@{version}");

    // Try cache first
    if let Some(payload) = crate::cache::get(&cache_key) {
        if let Ok(resp) = serde_json::from_value::<OsvResponse>(payload) {
            return Ok(parse_osv_response(resp));
        }
    }

    let body = serde_json::json!({
        "package": {"name": crate_name, "ecosystem": "crates.io"},
        "version": version
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let resp: OsvResponse = client
        .post("https://api.osv.dev/v1/query")
        .json(&body)
        .send()
        .await
        .context("OSV request failed")?
        .json()
        .await?;

    // Persist to cache (best-effort)
    if let Ok(value) = serde_json::to_value(&resp) {
        let _ = crate::cache::put(&cache_key, value);
    }

    Ok(parse_osv_response(resp))
}

fn parse_osv_response(resp: OsvResponse) -> Vec<Vulnerability> {
    resp.vulns
        .into_iter()
        .map(|v| Vulnerability {
            id: v.id,
            summary: v.summary,
            severity: v
                .severity
                .first()
                .map(|s| format!("{}:{}", s.kind, s.score))
                .unwrap_or_else(|| "UNKNOWN".into()),
            patched_versions: vec![],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_lockfile_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let deps = read_lockfile(dir.path()).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parses_minimal_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.lock");
        std::fs::write(
            &path,
            r#"
[[package]]
name = "serde"
version = "1.0.100"

[[package]]
name = "anyhow"
version = "1.0.0"
"#,
        )
        .unwrap();
        let deps = read_lockfile(dir.path()).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].0, "serde");
        assert_eq!(deps[0].1, "1.0.100");
    }
}
SCANNER_EOF
echo "  ✓ scanner.rs reescrito"

echo "🔧 [3/4] Reescrevendo src/reporter.rs (sem format! inútil, sem pony contra crates.io)..."
cat > src/reporter.rs <<'REPORTER_EOF'
//! Output formats: JSON (native), SARIF (GitHub), plain text.
//! Also hosts the top-level orchestration: scanner -> pg_atlas -> analyzer -> scorer -> planner.

use crate::{analyzer, pg_atlas, planner, scanner, scorer, DependencyReport, PonySource};
use anyhow::Result;
use serde_json::json;
use std::path::Path;

/// Orchestrate the full scan pipeline for a project directory.
pub fn scan_project(path: &Path) -> Result<Vec<DependencyReport>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(scan_project_async(path))
}

async fn scan_project_async(path: &Path) -> Result<Vec<DependencyReport>> {
    let deps = scanner::read_lockfile(path)?;
    let mut reports = Vec::with_capacity(deps.len());

    for (name, version) in deps {
        // 1. CVE lookup
        let vulns = scanner::query_osv(&name, &version).await.unwrap_or_default();

        // 2. Pony factor: PG Atlas first, local fallback second
        let (pony_factor, pony_source) = match pg_atlas::fetch_project(&name).await {
            Ok(m) if m.pony_factor.is_some() => (m.pony_factor, PonySource::PgAtlas),
            _ => match analyzer::pony_factor_local(&format!(
                "https://github.com/rust-lang/{name}"
            )) {
                Ok(f) => (Some(f), PonySource::LocalFallback),
                Err(_) => (None, PonySource::Unknown),
            },
        };

        // 3. Worst severity across all CVEs of this crate
        let worst = vulns
            .iter()
            .map(|v| v.severity.as_str())
            .max_by_key(|s| severity_rank(s))
            .unwrap_or("NONE");

        // 4. Score + classify
        let (risk_score, classification) = scorer::score(worst, pony_factor);

        // 5. Mitigation plan when warranted
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

/// Render a dependency report list as SARIF 2.1.0.
pub fn to_sarif(reports: &[DependencyReport]) -> serde_json::Value {
    let results: Vec<serde_json::Value> = reports
        .iter()
        .flat_map(|r| {
            r.vulnerabilities.iter().map(move |v| {
                json!({
                    "ruleId": v.id,
                    "level": if severity_rank(&v.severity) >= 3 { "error" } else { "warning" },
                    "message": {
                        "text": format!("{} in {}@{}", v.summary, r.crate_name, r.version)
                    },
                    "locations": [{
                        "physicalLocation": {"artifactLocation": {"uri": "Cargo.lock"}}
                    }]
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

/// Plain text output for humans.
pub fn print_text(reports: &[DependencyReport]) {
    if reports.is_empty() {
        println!("(no dependencies found)");
        return;
    }
    println!(
        "{:<30} {:<12} {:>6} {:<10} {:>6} {:<14}",
        "crate", "version", "score", "class", "pony", "source"
    );
    for r in reports {
        println!(
            "{:<30} {:<12} {:>6.2} {:<10} {:>6} {:<14}",
            r.crate_name,
            r.version,
            r.risk_score,
            format!("{:?}", r.classification),
            r.pony_factor.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            format!("{:?}", r.pony_source),
        );
    }
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
                summary: "test vuln".into(),
                severity: "HIGH".into(),
                patched_versions: vec![],
            }],
            pony_factor: Some(2),
            pony_source: PonySource::PgAtlas,
            risk_score: 2.6,
            classification: scorer::Classification::High,
            mitigation: Some(MitigationPlan {
                immediate: Action {
                    action: "bump_version".into(),
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
        assert_eq!(s["runs"][0]["tool"]["driver"]["name"], "Soroban Dependency Sentinel");
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn severity_rank_orders_correctly() {
        assert!(severity_rank("CRITICAL") > severity_rank("HIGH"));
        assert!(severity_rank("HIGH") > severity_rank("MEDIUM"));
        assert!(severity_rank("LOW") > severity_rank("NONE"));
    }
}
REPORTER_EOF
echo "  ✓ reporter.rs reescrito"

echo "🔧 [4/4] Sanity check de arquivos-chave..."
for f in src/lib.rs src/cache.rs src/analyzer.rs src/scorer.rs src/planner.rs src/pg_atlas.rs src/cli.rs src/main.rs; do
  [[ -f "$f" ]] || { echo "❌ faltando: $f"; exit 1; }
done
echo "  ✓ todos os arquivos presentes"

echo ""
echo "🧪 Rodando QA final..."
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all

echo ""
echo "✅ parte-4.sh concluído."
echo ""
echo "Valide com:"
echo "  cargo run -- scan --path examples/demo-project --format text"
echo "  cargo run -- scan --path examples/demo-project --format json"
echo ""
