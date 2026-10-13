# Soroban Dependency Sentinel

[![CI](https://github.com/developerfred/soroban-dependency-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/developerfred/soroban-dependency-sentinel/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/soroban-dependency-sentinel.svg)](https://crates.io/crates/soroban-dependency-sentinel)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Supply-chain security scanner for Soroban projects. Combines CVE scanning
(RustSec / OSV.dev), PG Atlas pony-factor integration, unified risk scoring,
and actionable mitigation plans.

## Why

Two systemic risks are not mitigated by any existing tool:

1. **CVEs in transitive dependencies** — an advisory two levels deep can
   compromise every contract that depends on it.
2. **Pony factor = 1** — a critical dependency maintained by a single person
   is a single point of failure.

Existing tools cover the extremes:

| Tool | What it does | What it does **not** do |
|------|--------------|-------------------------|
| Scout / Soroban Guard | Analyze *contract code* | Dependencies |
| PG Atlas | *Measures* pony factor and criticality | Action in CI |
| cargo-audit | Scans CVEs | Pony factor, mitigation plans, SARIF |

**Sentinel fills the gap**: it turns measured risk into CI gates and
mitigation plans.

## Install

```bash
cargo install soroban-dependency-sentinel
```

Or from source:

```bash
git clone https://github.com/developerfred/soroban-dependency-sentinel
cd soroban-dependency-sentinel
cargo install --path .
```

## Quick start

```bash
sentinel scan --path . --format text
```

Output:

```
crate                          version       score class      pony source
itoa                           1.0.18         0.00 Safe        1    CratesIoOwners
serde                          1.0.229        0.00 Safe        1    CratesIoOwners
```

With a vulnerable dependency:

```
time                           0.1.44        1.80 Watch       2    CratesIoOwners
```

## CLI

| Command | Purpose |
|---------|---------|
| `sentinel scan` | Scan a project for CVEs and pony risks |
| `sentinel explain <ID>` | Fetch an advisory from OSV.dev |
| `sentinel wizard` | Generate `sentinel.toml` + GitHub Action |

### Common flags

| Flag | Description |
|------|-------------|
| `--path <DIR>` | Project directory (default: `.`) |
| `--format <FMT>` | `json`, `sarif`, `markdown`, `text` |
| `--fail-on <LEVEL>` | `none`, `watch`, `high`, `critical` |
| `--offline` | Cache-only, no network |
| `--baseline <FILE>` | Fail only on regressions |
| `--deep-pony` | Clone repos to compute real pony factor |
| `--include-local` | Include the scanned crate in the report |

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: developerfred/soroban-dependency-sentinel@v1
    with:
      fail-on: high
      upload-sarif: "true"
```

See [docs/CI-INTEGRATION.md](docs/CI-INTEGRATION.md) for GitLab, baseline,
and offline modes.

## Configuration (`sentinel.toml`)

```toml
[scan]
fail_on = "high"
deep_pony = false

[ignore]
crates = ["some-deprecated-crate"]
advisories = ["RUSTSEC-2020-0071"]
```

Generate it interactively:

```bash
sentinel wizard
```

## Output formats

- **text** — human-readable table
- **json** — machine-readable, stable schema
- **sarif** — SARIF 2.1.0, compatible with GitHub Code Scanning
- **markdown** — for PR comments

## Development

This project is developed with an agentic harness:

- `AGENTS.md` — persistent context for AI agents and humans
- `.agents/skills/` — 8 reusable `SKILL.md` files
- `workflows/` — 5 slash commands (`/spec`, `/plan`, `/build`, `/test`, `/ship`)

See [`AGENTS.md`](AGENTS.md) for details.

## Documentation

- [Install](docs/INSTALL.md)
- [CI integration](docs/CI-INTEGRATION.md)
- [API reference](docs/API.md)
- [ADR 0001 — Architecture](docs/ADR/0001-architecture.md)
- [Feature spec](docs/specs/FEATURE-001.md)

## License

Apache-2.0
