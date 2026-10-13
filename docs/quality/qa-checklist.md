# QA Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test --all`
- [ ] `cargo llvm-cov` coverage >= 80% on new modules
- [ ] CLI `--format json` produces valid JSON
- [ ] CLI `--format sarif` produces valid SARIF 2.1.0
- [ ] `cargo doc --no-deps` warning-free
- [ ] README quick start works on a fresh machine
- [ ] CHANGELOG updated
- [ ] PR reviewed by @review-agent
