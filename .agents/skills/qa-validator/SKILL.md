---
name: qa-validator
description: Run the project quality gate on every commit/PR.
allowed-tools: Read, Bash, Glob, Grep
---

# QA Validator Skill

## Steps
```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo llvm-cov --json --output-path coverage.json
```

## Gates
- [ ] fmt clean
- [ ] clippy clean
- [ ] tests pass
- [ ] coverage >= 80% (new modules) / 70% (global)
- [ ] CLI produces valid JSON on fixture project
- [ ] Zero doc warnings
