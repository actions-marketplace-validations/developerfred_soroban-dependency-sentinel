---
name: mitigation-planner
description: Generate actionable mitigation plans for high-risk dependencies.
allowed-tools: Read, Write, WebSearch
---

# Mitigation Planner Skill

## Decision matrix
| Scenario | Action | Effort |
|----------|--------|--------|
| CVE with patch | bump_version | low |
| CVE, no patch | fork_hotfix | high |
| Pony=1, no CVE | find co-maintainer / fork | medium |
| Pony=1 + CVE | replace crate | high |
| Abandoned | migrate alternative | high |

## Output
```json
{
  "crate": "x",
  "risk_score": 3.2,
  "mitigation_plan": {
    "immediate": {"action":"bump_version","target":">=2.1.4","effort":"low","hours":2},
    "medium_term": {"action":"fork_and_maintain","effort":"high","hours":40},
    "alternatives": [{"crate":"y","last_commit":"2026-09-15"}]
  }
}
```

## Quality Gates
- [ ] Plan for every score >= 2
- [ ] Alternatives verified (recent commits)
- [ ] Effort estimate present
