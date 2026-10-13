# FEATURE-001 — Soroban Dependency Sentinel

**Status**: MVP complete
**Owner**: SCF Public Goods Maintenance Working Group
**Category**: Developer Tooling / Security Infrastructure
**Target**: Public Goods Award (Q1 2027)

## Problem

Soroban projects depend on a deep tree of Rust crates. Two systemic risks
are not mitigated by any existing tool:

1. **CVEs in transitive dependencies** — an advisory in a crate two levels
   deep can compromise every contract that depends on it. The ecosystem has
   `cargo-audit`, but it is not Soroban-aware and does not produce
   mitigation plans.
2. **Pony factor = 1 (abandonment risk)** — a critical dependency maintained
   by a single person is a single point of failure. PG Atlas measures this,
   but does not act on it in a developer's CI.

Existing tools cover the extremes:
- **Scout** / **Soroban Guard** — analyze *contract code*, not dependencies.
- **PG Atlas** — *measures* pony factor and criticality, but is passive.
- **cargo-audit** — scans CVEs, but no pony factor, no mitigation plan,
  no Soroban integration.

## Solution

**Soroban Dependency Sentinel** is a Rust CLI + GitHub Action that:

1. Parses `Cargo.lock` and queries OSV.dev (RustSec mirror) for CVEs.
2. Resolves pony factor via PG Atlas → crates.io owners → (deep) git log.
3. Combines both signals into a unified risk score.
4. Generates a concrete mitigation plan (bump / fork / replace).
5. Emits JSON, SARIF 2.1.0 (GitHub Code Scanning), markdown, or human text.
6. Fails CI when risk crosses a configurable threshold.

## Acceptance Criteria

- [x] CLI `sentinel scan` with `--path`, `--format`, `--fail-on`.
- [x] Offline mode (`--offline`) for hermetic CI.
- [x] Baseline diff (`--baseline`) to fail only on regressions.
- [x] Project config via `sentinel.toml` (ignore crates/advisories).
- [x] SARIF output valid against schema 2.1.0.
- [x] Markdown output for PR comments.
- [x] Pony factor via PG Atlas, crates.io owners, and git-log fallback.
- [x] E2E test detecting a known CVE in a fixture.
- [x] GitHub Actions: CI, QA gate, scheduled security scan.

## Success Metrics (next 3 months)

- **Adoption**: 10+ Soroban projects install the GitHub Action.
- **Coverage**: 100% of scanned projects surface their dependency risk score.
- **Detection**: at least 1 real advisory detected and patched in a
  downstream project during the period.
- **Ecosystem**: PG Atlas citations of Sentinel as a complementary action layer.

## Out of Scope

- Contract-level static analysis (covered by Scout / Soroban Guard).
- Runtime monitoring (covered by OBSRVR Radar).
- Wallet or transaction security (covered by other tooling).

## Dependencies

- OSV.dev API (public, no key required).
- crates.io API (public).
- PG Atlas API (public).

## Risks

| Risk | Mitigation |
|------|------------|
| PG Atlas API changes | Fallback to crates.io owners |
| OSV.dev rate limits | 24h local cache |
| Pony factor proxy imprecision | `--deep-pony` uses real git log |
