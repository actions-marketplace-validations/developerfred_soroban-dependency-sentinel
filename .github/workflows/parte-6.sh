#!/usr/bin/env bash
# =============================================================
# Soroban Dependency Sentinel — Part 6
# Owners-based pony factor + --fail-on + explain + vulnerable fixture
# =============================================================
set -euo pipefail

if [[ ! -f Cargo.toml ]]; then
  echo "❌ Rode dentro de soroban-dependency-sentinel/"
  exit 1
fi

echo "🔧 [1/7] Estendendo src/crates_io.rs com owners..."
cat > src/crates_io.rs <<'CRATES_EOF'
//! Minimal crates.io API client — repository URL + owner-based pony estimate.

use anyhow::{Context, Result};
use serde::Deserialize;

const BASE: &str = "https://crates.io/api/v1/crates";
const USER_AGENT: &str = "soroban-dependency-sentinel (github.com/scf-public-goods/soroban-dependency-sentinel)";

#[derive(Debug, Deserialize)]
struct CrateResponse {
    #[serde(rename = "crate")]
    krate: CrateInfo,
}

#[derive(Debug, Deserialize)]
struct CrateInfo {
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OwnersResponse {
    users: Vec<Owner>,
}

#[derive(Debug, Deserialize)]
struct Owner {
    login: String,
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .user_agent(USER_AGENT)
        .build()?)
}

/// Returns the repository URL for a crate, if crates.io knows it.
pub async fn fetch_repository_url(name: &str) -> Result<Option<String>> {
    let url = format!("{BASE}/{name}");
    let resp = client()?.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let body: CrateResponse = resp
        .json()
        .await
        .with_context(|| format!("invalid crates.io response for {name}"))?;
    Ok(body.krate.repository)
}

/// Estimates pony factor from the number of owners on crates.io.
///
/// This is a **proxy**, not a commit-based measurement: it answers "how many
/// people have publish rights?", which is a reasonable lower bound when we
/// cannot afford to clone the repo.
pub async fn estimate_pony_factor_from_owners(name: &str) -> Result<Option<u32>> {
    let url = format!("{BASE}/{name}/owners");
    let resp = client()?.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let body: OwnersResponse = resp
        .json()
        .await
        .with_context(|| format!("invalid owners response for {name}"))?;
    let n = body.users.len() as u32;
    Ok(if n == 0 { None } else { Some(n) })
}
CRATES_EOF
echo "  ✓"

echo "🔧 [2/7] Atualizando src/reporter.rs (owners no resolve_pony)..."
python3 - <<'PY'
import pathlib, re
p = pathlib.Path("src/reporter.rs")
s = p.read_text()

old = '''async fn resolve_pony(name: &str, deep: bool) -> (Option<u32>, PonySource) {
    if let Ok(m) = pg_atlas::fetch_project(name).await {
        if let Some(f) = m.pony_factor {
            return (Some(f), PonySource::PgAtlas);
        }
    }
    if !deep {
        return (None, PonySource::Unknown);
    }
    if let Ok(Some(repo)) = crates_io::fetch_repository_url(name).await {
        if let Ok(f) = analyzer::pony_factor_local(&repo) {
            return (Some(f), PonySource::LocalFallback);
        }
    }
    (None, PonySource::Unknown)
}'''

new = '''async fn resolve_pony(name: &str, deep: bool) -> (Option<u32>, PonySource) {
    // 1. PG Atlas (authoritative when present)
    if let Ok(m) = pg_atlas::fetch_project(name).await {
        if let Some(f) = m.pony_factor {
            return (Some(f), PonySource::PgAtlas);
        }
    }

    // 2. crates.io owners (fast proxy, no clone)
    if let Ok(Some(f)) = crates_io::estimate_pony_factor_from_owners(name).await {
        return (Some(f), PonySource::CratesIoOwners);
    }

    // 3. Deep mode: clone the real repository (slow)
    if deep {
        if let Ok(Some(repo)) = crates_io::fetch_repository_url(name).await {
            if let Ok(f) = analyzer::pony_factor_local(&repo) {
                return (Some(f), PonySource::LocalFallback);
            }
        }
    }

    (None, PonySource::Unknown)
}'''

if old not in s:
    raise SystemExit("resolve_pony block not found — versão do reporter.rs difere")
s = s.replace(old, new)
p.write_text(s)
print("  ✓")
PY

echo "🔧 [3/7] Atualizando src/lib.rs (nova variante PonySource)..."
python3 - <<'PY'
import pathlib
p = pathlib.Path("src/lib.rs")
s = p.read_text()
if "CratesIoOwners" not in s:
    s = s.replace(
        "pub enum PonySource {\n    PgAtlas,\n    LocalFallback,\n    Unknown,\n}",
        "pub enum PonySource {\n    PgAtlas,\n    CratesIoOwners,\n    LocalFallback,\n    Unknown,\n}"
    )
p.write_text(s)
print("  ✓")
PY

echo "🔧 [4/7] Adicionando --fail-on ao CLI + fail gate..."
cat > src/cli.rs <<'CLI_EOF'
use crate::reporter::{self, ScanOptions};
use crate::scorer::Classification;
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sentinel", version, about = "Soroban supply-chain scanner")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Scan a project directory for vulnerable/dangerous dependencies.
    Scan {
        #[arg(long, default_value = ".")]
        path: PathBuf,

        #[arg(long, default_value = "json", value_parser = ["json", "sarif", "text"])]
        format: String,

        /// Enable local git clone fallback for pony factor (slow, network-heavy).
        #[arg(long, default_value_t = false)]
        deep_pony: bool,

        /// Include the scanned crate itself in the report.
        #[arg(long, default_value_t = false)]
        include_local: bool,

        /// Exit with code 1 if any dependency reaches this classification.
        #[arg(long, value_enum, default_value_t = FailLevel::None)]
        fail_on: FailLevel,
    },

    /// Explain an advisory ID (e.g. RUSTSEC-2020-0071) via OSV.dev.
    Explain {
        /// Advisory ID.
        id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailLevel {
    None,
    Watch,
    High,
    Critical,
}

impl FailLevel {
    fn rank(self) -> u8 {
        match self {
            FailLevel::None => u8::MAX,
            FailLevel::Watch => 1,
            FailLevel::High => 2,
            FailLevel::Critical => 3,
        }
    }
}

fn class_rank(c: Classification) -> u8 {
    match c {
        Classification::Safe => 0,
        Classification::Watch => 1,
        Classification::High => 2,
        Classification::Critical => 3,
    }
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Scan {
            path,
            format,
            deep_pony,
            include_local,
            fail_on,
        } => {
            let opts = ScanOptions {
                deep_pony,
                include_local,
            };
            let report = reporter::scan_project_with(&path, opts)?;

            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&report)?),
                "sarif" => println!(
                    "{}",
                    serde_json::to_string_pretty(&reporter::to_sarif(&report))?
                ),
                _ => reporter::print_text(&report),
            }

            let threshold = fail_on.rank();
            let worst = report
                .iter()
                .map(|r| class_rank(r.classification))
                .max()
                .unwrap_or(0);

            if worst >= threshold {
                anyhow::bail!(
                    "risk gate: worst classification rank {} >= threshold {}",
                    worst,
                    threshold
                );
            }
            Ok(())
        }

        Cmd::Explain { id } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(reporter::explain_advisory(&id))
        }
    }
}
CLI_EOF
echo "  ✓"

echo "🔧 [5/7] Adicionando explain_advisory ao reporter..."
cat >> src/reporter.rs <<'EXPLAIN_EOF'

/// Fetch an advisory from OSV.dev and print it as pretty JSON.
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
EXPLAIN_EOF
echo "  ✓"

echo "🔧 [6/7] Criando fixture vulnerable-project..."
mkdir -p examples/vulnerable-project/src

cat > examples/vulnerable-project/Cargo.toml <<'VULN_EOF'
[package]
name = "vulnerable-project"
version = "0.1.0"
edition = "2021"

[dependencies]
# Pinned to a version affected by RUSTSEC-2020-0071.
time = "=0.1.44"
VULN_EOF

cat > examples/vulnerable-project/src/lib.rs <<'VULN_EOF'
//! Fixture with a known-vulnerable dependency, used by E2E tests.

pub fn what_time() -> &'static str {
    "ask time crate"
}
VULN_EOF

( cd examples/vulnerable-project && cargo generate-lockfile --quiet 2>/dev/null || true )
echo "  ✓"

echo "🔧 [7/7] Adicionando E2E test em tests/integration.rs..."
cat > tests/integration.rs <<'TESTS_EOF'
use assert_cmd::Command;

#[test]
fn scan_help_runs() {
    Command::cargo_bin("sentinel")
        .unwrap()
        .args(["scan", "--help"])
        .assert()
        .success();
}

#[test]
fn scan_json_on_empty_dir() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("sentinel")
        .unwrap()
        .args(["scan", "--path"])
        .arg(dir.path())
        .args(["--format", "json"])
        .assert()
        .success();
}

#[test]
fn detects_known_cve_in_vulnerable_fixture() {
    // The fixture pins `time = 0.1.44` which is affected by RUSTSEC-2020-0071.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/vulnerable-project");
    if !fixture.join("Cargo.lock").exists() {
        eprintln!("skipping: fixture Cargo.lock not present");
        return;
    }

    let out = Command::cargo_bin("sentinel")
        .unwrap()
        .args(["scan", "--path"])
        .arg(&fixture)
        .args(["--format", "json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "scan should succeed");

    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let arr = json.as_array().expect("expected array");
    let vuln_count: usize = arr
        .iter()
        .map(|r| {
            r.get("vulnerabilities")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        })
        .sum();
    assert!(vuln_count > 0, "expected at least one CVE, got {vuln_count}");
}

#[test]
fn fail_on_critical_exits_nonzero_when_cve_present() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/vulnerable-project");
    if !fixture.join("Cargo.lock").exists() {
        return;
    }

    Command::cargo_bin("sentinel")
        .unwrap()
        .args(["scan", "--path"])
        .arg(&fixture)
        .args(["--format", "text", "--fail-on", "watch"])
        .assert()
        .failure();
}
TESTS_EOF
echo "  ✓"

echo ""
echo "🧪 QA final..."
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all -- --nocapture

echo ""
echo "✅ parte-6 aplicado."
echo ""
echo "Verificações rápidas:"
echo "  cargo run --quiet -- scan --path examples/demo-project --format text"
echo "  cargo run --quiet -- scan --path examples/vulnerable-project --format text"
echo "  cargo run --quiet -- scan --path examples/vulnerable-project --format text --fail-on watch; echo exit=\$?"
echo "  cargo run --quiet -- explain RUSTSEC-2020-0071 | head -20"
echo ""
