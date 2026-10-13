---
name: rustsec-scanner
description: Scan Cargo.lock for known CVEs via OSV.dev (RustSec advisories).
allowed-tools: Read, Bash, WebFetch
---

# RustSec Scanner Skill

## When to use
Whenever auditing a `Cargo.lock` for known vulnerabilities.

## Procedure

### Step 1 — Locate lockfile
Use `Glob` to find `Cargo.lock` in the target project.

### Step 2 — Extract dependencies
```bash
cargo metadata --format-version 1 --no-deps \
  | jq -r '.packages[] | "\(.name)@\(.version)"'
```

### Step 3 — Query OSV.dev
```bash
curl -s https://api.osv.dev/v1/query \
  -X POST \
  -d "{\"package\":{\"name\":\"$CRATE\",\"ecosystem\":\"crates.io\"},\"version\":\"$VER\"}"
```

### Step 4 — Output schema
```json
{
  "crate": "name",
  "version": "1.2.3",
  "vulnerabilities": [
    {"id": "RUSTSEC-2026-0001", "severity": "HIGH", "patched": [">=1.2.4"]}
  ]
}
```

## Quality Gates
- [ ] Every lockfile dep queried
- [ ] 5s timeout, 3 retries, exponential backoff
- [ ] 24h local advisory cache
- [ ] Output validated against JSON Schema

## Evidence of success
- deps_scanned > 0
- output JSON parses
