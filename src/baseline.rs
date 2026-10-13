//! Baseline comparison: detect regressions between two scans.

use crate::DependencyReport;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Regression {
    pub crate_name: String,
    pub new_advisories: Vec<String>,
    pub old_score: f32,
    pub new_score: f32,
}

/// Load a previous scan from a JSON file.
pub fn load(path: &Path) -> Result<Vec<DependencyReport>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading baseline {}", path.display()))?;
    let reports: Vec<DependencyReport> =
        serde_json::from_str(&content).with_context(|| "invalid baseline JSON")?;
    Ok(reports)
}

/// Diff current against baseline: return regressions (new advisories,
/// or risk score increased by more than 0.5).
pub fn diff(current: &[DependencyReport], baseline: &[DependencyReport]) -> Vec<Regression> {
    let baseline_by_name: std::collections::HashMap<&str, &DependencyReport> = baseline
        .iter()
        .map(|r| (r.crate_name.as_str(), r))
        .collect();

    let mut out = Vec::new();
    for cur in current {
        let Some(base) = baseline_by_name.get(cur.crate_name.as_str()) else {
            // New crate, not a regression per se; skip.
            continue;
        };

        let base_ids: HashSet<&str> = base.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        let new_advisories: Vec<String> = cur
            .vulnerabilities
            .iter()
            .filter(|v| !base_ids.contains(v.id.as_str()))
            .map(|v| v.id.clone())
            .collect();

        let score_up = cur.risk_score - base.risk_score;

        if !new_advisories.is_empty() || score_up > 0.5 {
            out.push(Regression {
                crate_name: cur.crate_name.clone(),
                new_advisories,
                old_score: base.risk_score,
                new_score: cur.risk_score,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Vulnerability;
    use crate::scorer::Classification;
    use crate::PonySource;

    fn rep(name: &str, score: f32, advisories: &[&str]) -> DependencyReport {
        DependencyReport {
            crate_name: name.into(),
            version: "1.0.0".into(),
            vulnerabilities: advisories
                .iter()
                .map(|id| Vulnerability {
                    id: (*id).into(),
                    summary: "x".into(),
                    severity: "HIGH".into(),
                    patched_versions: vec![],
                })
                .collect(),
            pony_factor: Some(2),
            pony_source: PonySource::PgAtlas,
            risk_score: score,
            classification: Classification::High,
            mitigation: None,
        }
    }

    #[test]
    fn detects_new_advisory() {
        let baseline = vec![rep("a", 1.0, &[])];
        let current = vec![rep("a", 1.0, &["RUSTSEC-2026-0001"])];
        let regs = diff(&current, &baseline);
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].new_advisories, vec!["RUSTSEC-2026-0001"]);
    }

    #[test]
    fn no_regression_when_same() {
        let baseline = vec![rep("a", 1.0, &["RUSTSEC-2026-0001"])];
        let current = vec![rep("a", 1.0, &["RUSTSEC-2026-0001"])];
        assert!(diff(&current, &baseline).is_empty());
    }
}
