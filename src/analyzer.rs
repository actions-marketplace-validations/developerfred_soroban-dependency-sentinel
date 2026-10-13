//! Local pony factor fallback (git log).

use anyhow::{Context, Result};
use std::process::Command;

/// Compute pony factor by cloning `repo_url` (shallow) and analyzing the
/// git log. Fails fast if the repository is unreachable.
pub fn pony_factor_local(repo_url: &str) -> Result<u32> {
    let tmp = tempfile::tempdir()?;

    // Silent clone: use output() so git's stderr is captured, not printed.
    let output = Command::new("git")
        .args(["clone", "--depth", "1", "--quiet", repo_url])
        .arg(tmp.path())
        .output()
        .context("failed to spawn git")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr.lines().next().unwrap_or("(no stderr)");
        anyhow::bail!("git clone failed for {repo_url}: {first}");
    }

    let out = Command::new("git")
        .arg("-C")
        .arg(tmp.path())
        .args(["log", "--format=%aN"])
        .output()
        .context("git log failed")?;

    let authors: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if authors.len() < 10 {
        anyhow::bail!("too few commits to compute pony factor");
    }

    // Count commits per author.
    let mut sorted = authors.clone();
    sorted.sort();
    let mut counts: Vec<(String, usize)> = vec![];
    for a in sorted {
        match counts.last_mut() {
            Some((name, c)) if *name == a => *c += 1,
            _ => counts.push((a, 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1));

    let total: usize = counts.iter().map(|(_, c)| c).sum();
    let mut acc = 0usize;
    for (i, (_, c)) in counts.iter().enumerate() {
        acc += c;
        if acc * 2 >= total {
            return Ok((i + 1) as u32);
        }
    }
    Ok(counts.len() as u32)
}
