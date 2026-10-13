# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Part 10
- `--format html` — standalone HTML report (no external assets).
- `sentinel schema` — emit JSON Schema (draft 2020-12) of the scan output.
- `sentinel plugins` — list `sentinel-plugin-*` executables in `PATH`.
- Plugin system: findings auto-merged into the report (`src/plugins.rs`).
- `--no-plugins` flag to disable plugin discovery.
- `.github/workflows/docs.yml` — publish docs to GitHub Pages.
- New modules: `src/report_html.rs`, `src/schema.rs`, `src/plugins.rs`.

### Part 9
- Interactive `sentinel wizard`.
- Composite GitHub Action (`action.yml`) — reusable in one line.
- `release.yml` workflow: tag validation, dry-run, `cargo publish`.
- `docs/INSTALL.md` and `docs/CI-INTEGRATION.md`.
- README with badges, install, usage and API links.
- crates.io metadata (`readme`, `homepage`, `documentation`).
- SCF proposal docs kept locally, excluded from version control.

### Part 8
- `--offline` mode (cache-only, no network).
- `--baseline <file>` to fail only on regressions.
- `sentinel.toml` config (ignore crates/advisories, default fail-on).
- `--format markdown` for PR comments.
- `src/config.rs`, `src/baseline.rs`, `src/markdown.rs`.
- SCF documentation: `docs/specs/FEATURE-001.md`, `docs/scf/PG-PROPOSAL.md`, `docs/scf/INTAKE-FORM.md`, `docs/scf/METRICS.md`.

### Added
- Initial project scaffolding with agentic structure (`AGENTS.md`, `.agents/`).
- `scanner` module: `Cargo.lock` parser + OSV.dev query.
- `pg_atlas` module: PG Atlas API client for pony factor.
- `analyzer` module: local pony factor fallback via git log.
- `scorer` module: unified risk score (CVE + pony factor).
- `planner` module: mitigation plan generator.
- `reporter` module: JSON, SARIF 2.1.0 and plain text output.
- CLI `sentinel scan --path . --format {json,sarif,text}`.
- 8 reusable skills under `.agents/skills/`.
- 5 agentic workflows under `workflows/`.
- 3 GitHub Actions workflows (CI, QA gate, scheduled security scan).

[Unreleased]: https://github.com/scf-public-goods/soroban-dependency-sentinel
