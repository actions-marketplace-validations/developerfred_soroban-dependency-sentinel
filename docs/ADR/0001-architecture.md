# ADR 0001 — Architecture Overview

- **Status**: Accepted
- **Date**: 2026-10-13
- **Deciders**: @architect, @lead-agent

## Context

Soroban projects depend on a deep tree of Rust crates. CVEs in those crates
and abandonment (pony factor = 1) are two systemic risks the SCF Public Goods
program explicitly wants to reduce.

Existing tools cover the extremes:
- **Scout** / **Soroban Guard** analyze *contract code*, not dependencies.
- **PG Atlas** measures pony factor and criticality at the ecosystem level,
  but only *reports* — it does not act inside a developer's CI.

There is no tool that turns PG Atlas data + RustSec advisories into a
**CI gate with a mitigation plan**.

## Decision

We will build **Soroban Dependency Sentinel** as:

1. A **Rust CLI** (`sentinel`) using a modular pipeline:
   - `scanner` — parse `Cargo.lock`, query OSV.dev for CVEs.
   - `pg_atlas` — consume PG Atlas API for authoritative pony factor.
   - `analyzer` — local git-log fallback for pony factor.
   - `scorer` — combine CVE severity and pony factor into one score.
   - `planner` — produce an actionable mitigation plan.
   - `reporter` — emit JSON, SARIF 2.1.0, or human text.

2. A **GitHub Action** consuming `--format sarif` and uploading to Code
   Scanning, so risky dependencies block merges.

3. An **agentic development harness** (`AGENTS.md`, `.agents/`, `workflows/`)
   so both humans and AI agents follow identical rules.

## Consequences

### Positive
- Complementary to PG Atlas (consumes, doesn't duplicate).
- Complementary to Scout (dependencies, not contract code).
- SARIF integration → first-class in GitHub Security tab.
- Agentic harness → scalable maintenance by AI agents.

### Negative
- Depends on OSV.dev and PG Atlas availability (mitigated by local fallback).
- Pony factor from PG Atlas may lag behind upstream reality.

### Neutral
- Requires network access during CI by default; `--offline` disables lookups.

## Alternatives considered

1. **Fork cargo-audit and patch it** — rejected: cargo-audit has no pony factor
   and no mitigation planning; forking creates maintenance burden.
2. **Extend Scout** — rejected: Scout focuses on contract semantics, not the
   build-time dependency tree.
3. **Pure PG Atlas extension** — rejected: PG Atlas is passive by design.

## References

- PG Atlas API: https://api.pgatlas.xyz
- OSV.dev API: https://api.osv.dev
- SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
