# Soroban Dependency Sentinel — Agent Instructions

## Overview
CLI + GitHub Action scanning Rust dependencies in Soroban projects,
integrating with PG Atlas for authoritative pony factor metrics and
producing actionable mitigation plans.

## Stack
- Rust 1.85+ (MSRV)
- RustSec / OSV.dev API
- PG Atlas REST API (api.pgatlas.xyz)
- GitHub Actions + SARIF

## Mandatory Conventions
- TDD: write the failing test first.
- Atomic commits: one logical change per commit.
- `cargo clippy --all-targets -- -D warnings` must pass.
- Coverage >= 80% on new modules.
- Public APIs must have doc comments.
- Always prefer PG Atlas data for pony factor; local analysis is fallback.

## Agent Behavior Rules
- Never commit without running `cargo fmt` and `cargo clippy`.
- Always write tests before implementation.
- Never merge without a green QA gate.
- If input is ambiguous, mark blocked instead of guessing.

## Definition of Done
- [ ] Test written and passing
- [ ] Coverage >= 80% on new module
- [ ] Clippy clean
- [ ] Docs updated
- [ ] QA gate green
- [ ] PR approved by @review-agent
