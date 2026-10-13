---
name: risk-scorer
description: Combine CVE severity and pony factor into a unified risk score.
allowed-tools: Read
---

# Risk Scorer Skill

## Formula
```
risk_score = 0.6 * cve_weight + 0.4 * pony_weight
cve_weight:  0=none, 1=low, 2=medium, 3=high, 4=critical
pony_weight: 0=low, 1=medium, 2=high, 3=critical
```

## Classification
| Score | Class | Action |
|-------|-------|--------|
| 0-1 | safe | none |
| 1-2 | watch | monitor |
| 2-3 | high | mitigation plan |
| 3-4 | critical | immediate action |

## Output
```json
{"crate":"x","risk_score":3.2,"classification":"critical"}
```

## Quality Gates
- [ ] Inputs parsed
- [ ] Score for 100% of deps
- [ ] Plan for score >= 2
