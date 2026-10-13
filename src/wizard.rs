//! Interactive setup: generates `sentinel.toml` and a GitHub Action workflow.

use anyhow::{Context, Result};
use std::io::{self, Write};
use std::path::Path;

const ACTION_YAML: &str = r#"name: Sentinel supply-chain scan
on:
  pull_request:
    paths:
      - "Cargo.toml"
      - "Cargo.lock"
      - "**/Cargo.toml"
      - "**/Cargo.lock"
  schedule:
    - cron: "0 6 * * 1"

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: developerfred/soroban-dependency-sentinel@v1
        with:
          fail-on: high
          upload-sarif: "true"
"#;

/// Run the interactive wizard in `root`.
///
/// Creates `root` if it does not exist. When `non_interactive` is true,
/// writes defaults without prompting.
pub fn run(root: &Path, non_interactive: bool) -> Result<()> {
    // Ensure the target directory exists.
    std::fs::create_dir_all(root)
        .with_context(|| format!("creating target directory {}", root.display()))?;

    if non_interactive {
        return write_defaults(root);
    }

    println!("🧙 Soroban Dependency Sentinel — Setup Wizard");
    println!();

    let fail_on = prompt_choice(
        "Fail CI on which risk level?",
        &["none", "watch", "high", "critical"],
        "high",
    )?;
    let deep_pony = prompt_bool("Enable deep pony factor (clones repos)?", false)?;
    let install_action = prompt_bool("Install GitHub Action workflow?", true)?;

    let config = format!(
        "[scan]\nfail_on = \"{fail_on}\"\ndeep_pony = {deep_pony}\n\n\
         [ignore]\ncrates = []\nadvisories = []\n"
    );
    std::fs::write(root.join("sentinel.toml"), config)
        .with_context(|| format!("writing {}/sentinel.toml", root.display()))?;
    println!("  ✓ sentinel.toml written");

    if install_action {
        let wf_dir = root.join(".github/workflows");
        std::fs::create_dir_all(&wf_dir)
            .with_context(|| format!("creating {}", wf_dir.display()))?;
        std::fs::write(wf_dir.join("sentinel.yml"), ACTION_YAML)
            .with_context(|| format!("writing {}/sentinel.yml", wf_dir.display()))?;
        println!("  ✓ .github/workflows/sentinel.yml written");
    }

    println!();
    println!("Next steps:");
    println!("  1. Commit sentinel.toml and .github/workflows/sentinel.yml");
    println!("  2. Push and watch the Action run");
    println!("  3. Tune the ignore list in sentinel.toml as needed");
    Ok(())
}

fn write_defaults(root: &Path) -> Result<()> {
    let config = "[scan]\nfail_on = \"high\"\ndeep_pony = false\n\n\
                  [ignore]\ncrates = []\nadvisories = []\n";
    std::fs::write(root.join("sentinel.toml"), config)
        .with_context(|| format!("writing {}/sentinel.toml", root.display()))?;

    let wf_dir = root.join(".github/workflows");
    std::fs::create_dir_all(&wf_dir).with_context(|| format!("creating {}", wf_dir.display()))?;
    std::fs::write(wf_dir.join("sentinel.yml"), ACTION_YAML)
        .with_context(|| format!("writing {}/sentinel.yml", wf_dir.display()))?;
    Ok(())
}

fn prompt_choice(prompt: &str, choices: &[&str], default: &str) -> Result<String> {
    print!("{prompt} [{}] (default: {default}): ", choices.join("/"));
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(default.to_string());
    }
    if choices.contains(&trimmed) {
        Ok(trimmed.to_string())
    } else {
        println!("  ⚠ invalid choice, using default ({default})");
        Ok(default.to_string())
    }
}

fn prompt_bool(prompt: &str, default: bool) -> Result<bool> {
    let d = if default { "Y/n" } else { "y/N" };
    print!("{prompt} [{d}]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Ok(default);
    }
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_defaults_to_nonexistent_dir() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("does-not-exist-yet");

        // Should create the directory and both files.
        run(&root, true).unwrap();

        assert!(root.join("sentinel.toml").exists());
        assert!(root.join(".github/workflows/sentinel.yml").exists());

        let cfg = std::fs::read_to_string(root.join("sentinel.toml")).unwrap();
        assert!(cfg.contains("fail_on = \"high\""));
    }

    #[test]
    fn writes_defaults_to_existing_dir() {
        let root = tempfile::tempdir().unwrap();
        run(root.path(), true).unwrap();
        assert!(root.path().join("sentinel.toml").exists());
    }
}
