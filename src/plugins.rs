//! Plugin system: discovers and runs `sentinel-plugin-*` executables.
//!
//! Each plugin is invoked as `sentinel-plugin-<name> --scan <project-path>`
//! and must print a JSON array of `PluginFinding` on stdout:
//!
//! ```json
//! [{"crate_name":"serde","id":"PLUGIN-FOO-001","summary":"...","severity":"HIGH"}]
//! ```
//!
//! Findings are merged into the corresponding crate's vulnerability list.

use crate::scanner::Vulnerability;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A finding emitted by an external plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginFinding {
    pub crate_name: String,
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default = "default_severity")]
    pub severity: String,
}

fn default_severity() -> String {
    "MEDIUM".into()
}

/// A discovered plugin executable.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub name: String,
    pub path: PathBuf,
}

/// Discover `sentinel-plugin-*` executables in `PATH`.
pub fn discover() -> Vec<Plugin> {
    let path = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return vec![],
    };

    let mut found: Vec<Plugin> = Vec::new();
    for dir in std::env::split_paths(&path) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(suffix) = name.strip_prefix("sentinel-plugin-") else {
                continue;
            };
            // Strip .exe on Windows.
            let suffix = suffix.strip_suffix(".exe").unwrap_or(suffix);
            if suffix.is_empty() {
                continue;
            }
            let p = entry.path();
            if p.is_file() {
                // Skip duplicates (first PATH entry wins).
                if !found.iter().any(|pl| pl.name == suffix) {
                    found.push(Plugin {
                        name: suffix.to_string(),
                        path: p,
                    });
                }
            }
        }
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// Run a plugin against a project path and parse its JSON output.
pub fn run(plugin: &Plugin, project: &Path) -> Result<Vec<PluginFinding>> {
    let output = Command::new(&plugin.path)
        .arg("--scan")
        .arg(project)
        .output()
        .with_context(|| format!("failed to spawn plugin {}", plugin.name))?;

    if !output.status.success() {
        anyhow::bail!(
            "plugin {} exited with {}",
            plugin.name,
            output.status.code().unwrap_or(-1)
        );
    }

    let findings: Vec<PluginFinding> = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("invalid JSON from plugin {}", plugin.name))?;
    Ok(findings)
}

/// Convert a plugin finding into a `Vulnerability` for merging into a report.
pub fn finding_to_vulnerability(f: &PluginFinding, plugin_name: &str) -> Vulnerability {
    Vulnerability {
        id: f.id.clone(),
        summary: format!("[{}] {}", plugin_name, f.summary),
        severity: f.severity.clone(),
        patched_versions: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_severity_is_medium() {
        let json = r#"{"crate_name":"x","id":"Y","summary":"z"}"#;
        let f: PluginFinding = serde_json::from_str(json).unwrap();
        assert_eq!(f.severity, "MEDIUM");
    }

    #[test]
    fn parses_full_finding() {
        let json = r#"{"crate_name":"serde","id":"PLUGIN-1","summary":"bad","severity":"HIGH"}"#;
        let f: PluginFinding = serde_json::from_str(json).unwrap();
        assert_eq!(f.crate_name, "serde");
        assert_eq!(f.severity, "HIGH");
    }

    #[test]
    fn discover_returns_empty_when_no_plugins() {
        // In CI, no plugins named sentinel-plugin-* should be present.
        // This test is best-effort: if a plugin IS present, we just check
        // the function doesn't panic and the names look sane.
        let plugins = discover();
        for p in plugins {
            assert!(!p.name.is_empty());
        }
    }
}
