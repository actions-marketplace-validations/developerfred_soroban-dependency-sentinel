---
name: pg-atlas-integrator
description: Consume PG Atlas API for pony factor, criticality and dependency graph.
allowed-tools: Read, Bash, WebFetch
---

# PG Atlas Integrator Skill

## When to use
After locating dependencies, before any local pony factor calculation.

## Procedure

### Step 1 — Fetch project metrics
```bash
curl -s "https://api.pgatlas.xyz/projects/{canonical_id}" \
  | jq '{display_name, pony_factor, criticality_score}'
```

### Step 2 — Fetch repo metrics
```bash
curl -s "https://api.pgatlas.xyz/projects/{canonical_id}/repos" \
  | jq '.items[] | {repo_name, pony_factor}'
```

### Step 3 — Fallback
If not found, delegate to `pony-factor-analyzer` (local git log).

### Step 4 — Merge output
```json
{"crate": "some-crate", "pony_factor": 2, "source": "pg_atlas", "criticality": "high"}
```

## Quality Gates
- [ ] PG Atlas response < 5s
- [ ] Fallback only on miss
- [ ] `source` field populated
- [ ] No unhandled timeouts
