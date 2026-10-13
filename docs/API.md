# CLI Reference

## `sentinel scan`

Scan a project directory for vulnerable or dangerous dependencies.

### Synopsis

    sentinel scan --path <DIR> [--format <FMT>]

### Options

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--path` | path | `.` | Project directory containing `Cargo.lock`. |
| `--format` | `json` \| `sarif` \| `text` | `json` | Output format. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully. |
| `1` | Invalid arguments, unreadable lockfile, or unrecoverable error. |

### Examples

    sentinel scan --path . --format json
    sentinel scan --path ./examples/demo-project --format sarif

## Output schemas

### `DependencyReport` (JSON)

```json
{
  "crate_name": "serde",
  "version": "1.0.0",
  "vulnerabilities": [
    {"id": "RUSTSEC-...", "summary": "...", "severity": "HIGH", "patched_versions": []}
  ],
  "pony_factor": 2,
  "pony_source": "pg_atlas",
  "risk_score": 2.6,
  "classification": "high",
  "mitigation": null
}
```

### SARIF 2.1.0

Produced by `--format sarif`. Valid against the OASIS SARIF 2.1.0 schema.
