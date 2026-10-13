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

pub fn read_lockfile(root: &Path) -> Result<Vec<(String, String)>> {
    let lock_path = root.join("Cargo.lock");
    if !lock_path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(&lock_path)
        .with_context(|| format!("reading {}", lock_path.display()))?;
    let lock: toml::Value = toml::from_str(&content).with_context(|| "invalid Cargo.lock TOML")?;
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
/// When `offline` is true, only the local cache is consulted; no network
/// requests are made. Cached results are reused for 24h.
pub async fn query_osv(
    crate_name: &str,
    version: &str,
    offline: bool,
) -> Result<Vec<Vulnerability>> {
    let cache_key = format!("osv:{crate_name}@{version}");

    // Try cache first (always)
    if let Some(payload) = crate::cache::get(&cache_key) {
        if let Ok(resp) = serde_json::from_value::<OsvResponse>(payload) {
            return Ok(parse_osv_response(resp));
        }
    }

    if offline {
        return Ok(vec![]);
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
        assert!(read_lockfile(dir.path()).unwrap().is_empty());
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
    }
}
