//! Project configuration via `sentinel.toml`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level configuration, read from `sentinel.toml` if present.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub ignore: IgnoreConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Fail threshold: none | watch | high | critical.
    #[serde(default = "default_fail_on")]
    pub fail_on: String,
    /// Enable git clone fallback for pony factor.
    #[serde(default)]
    pub deep_pony: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            fail_on: default_fail_on(),
            deep_pony: false,
        }
    }
}

fn default_fail_on() -> String {
    "none".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IgnoreConfig {
    /// Crate names to skip entirely.
    #[serde(default)]
    pub crates: Vec<String>,
    /// Advisory IDs to suppress.
    #[serde(default)]
    pub advisories: Vec<String>,
}

impl Config {
    /// Load from `<root>/sentinel.toml`, or return defaults if absent.
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join("sentinel.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&content).with_context(|| "invalid sentinel.toml")
    }

    /// True if `crate_name` is on the ignore list.
    pub fn is_crate_ignored(&self, crate_name: &str) -> bool {
        self.ignore.crates.iter().any(|c| c == crate_name)
    }

    /// True if `advisory_id` is suppressed.
    pub fn is_advisory_ignored(&self, advisory_id: &str) -> bool {
        self.ignore.advisories.iter().any(|a| a == advisory_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::load(dir.path()).unwrap();
        assert_eq!(cfg.scan.fail_on, "none");
        assert!(!cfg.scan.deep_pony);
    }

    #[test]
    fn parses_ignore_list() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("sentinel.toml"),
            r#"
[scan]
fail_on = "high"

[ignore]
crates = ["old-crate"]
advisories = ["RUSTSEC-2020-0071"]
"#,
        )
        .unwrap();
        let cfg = Config::load(dir.path()).unwrap();
        assert_eq!(cfg.scan.fail_on, "high");
        assert!(cfg.is_crate_ignored("old-crate"));
        assert!(cfg.is_advisory_ignored("RUSTSEC-2020-0071"));
    }
}
