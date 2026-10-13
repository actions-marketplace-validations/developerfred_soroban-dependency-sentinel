---
name: pony-factor-analyzer
description: Local fallback — compute pony factor from git log when PG Atlas has no data.
allowed-tools: Read, Bash
---

# Pony Factor Analyzer (fallback)

## Procedure

### Step 1 — Clone
```bash
git clone --depth 1 https://github.com/$OWNER/$REPO /tmp/$REPO
```

### Step 2 — Compute
```bash
git -C /tmp/$REPO log --format='%aN' | sort | uniq -c | sort -rn \
 | awk '{c[NR]=$1; tot+=$1} END{s=0; for(i=1;i<=NR;i++){s+=c[i]; if(s>=tot/2){print i; exit}}}'
```

### Step 3 — Classify
| Pony | Risk |
|------|------|
| 1 | critical |
| 2 | high |
| 3-5 | medium |
| >5 | low |

## Quality Gates
- [ ] Repo cloned
- [ ] >= 10 commits (else "indeterminate")
- [ ] 30s timeout
