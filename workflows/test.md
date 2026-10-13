# /test — Full QA

## Agents
@qa-agent, @e2e-agent

## Steps
1. Run qa-validator skill
2. @e2e-agent: run CLI against 5 real Soroban projects
3. Emit QA report

## Gates
- [ ] Coverage >= 80%
- [ ] 5/5 fixture projects pass
- [ ] Zero clippy warnings
