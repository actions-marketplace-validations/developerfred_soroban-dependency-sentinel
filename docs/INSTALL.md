# Installation

## From crates.io

```bash
cargo install soroban-dependency-sentinel
```

Installs the `sentinel` binary.

## From source

```bash
git clone https://github.com/developerfred/soroban-dependency-sentinel
cd soroban-dependency-sentinel
cargo install --path .
```

## GitHub Action

Add `.github/workflows/sentinel.yml` to your project:

```yaml
name: Sentinel
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: developerfred/soroban-dependency-sentinel@v1
        with:
          fail-on: high
          upload-sarif: "true"
```

Or run the wizard inside your repository:

```bash
sentinel wizard
```

## Requirements

- Rust 1.85+ (MSRV)
- Network access to `api.osv.dev`, `crates.io`, `api.pgatlas.xyz`
  (disabled with `--offline`)
