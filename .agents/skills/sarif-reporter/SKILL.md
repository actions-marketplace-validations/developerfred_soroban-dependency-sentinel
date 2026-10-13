---
name: sarif-reporter
description: Emit SARIF 2.1.0 for GitHub Code Scanning.
allowed-tools: Read, Write, Bash
---

# SARIF Reporter Skill

## Minimum structure
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "Soroban Dependency Sentinel", "version": "0.1.0", "rules": []}},
    "results": []
  }]
}
```

## Validate
```bash
npx ajv-cli validate -s sarif-schema-2.1.0.json -d out.sarif
```

## Quality Gates
- [ ] Valid against SARIF 2.1.0
- [ ] Every vuln → rule
- [ ] Correct severity levels
