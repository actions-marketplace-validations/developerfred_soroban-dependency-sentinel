# CI Integration Guide

## GitHub Actions

### Minimal (fail on high or critical)

```yaml
- uses: developerfred/soroban-dependency-sentinel@v1
  with:
    fail-on: high
```

### With SARIF upload (shows findings in the Security tab)

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

### Deep pony factor (slow, clones repositories)

```yaml
- uses: developerfred/soroban-dependency-sentinel@v1
  with:
    fail-on: high
    deep-pony: "true"
```

## GitLab CI

```yaml
sentinel:
  image: rust:1.85
  script:
    - cargo install soroban-dependency-sentinel
    - sentinel scan --path . --format sarif --fail-on high > sentinel.sarif
  artifacts:
    reports:
      sast: sentinel.sarif
```

## Generic CI

1. Install: `cargo install soroban-dependency-sentinel`
2. Run: `sentinel scan --format sarif --fail-on high > sentinel.sarif`
3. Upload `sentinel.sarif` to your security dashboard.

### Baseline mode (fail only on regressions)

```bash
# First run: create baseline
sentinel scan --format json > baseline.json

# Subsequent runs: fail only if new advisories appear or risk increases
sentinel scan --baseline baseline.json
```

### Offline mode (hermetic CI)

```bash
# Populate cache once
sentinel scan --format json > /dev/null

# Subsequent runs: no network
sentinel scan --offline --format text
```
