# /plan — Decompose into Atomic Tasks

## Agents
@architect, @orchestrator

## Steps
1. Split feature into chunks <= 200 LoC
2. Build dependency DAG (acyclic)
3. Emit checklist

## Gates
- [ ] Every chunk has acceptance criteria
- [ ] No cycle
- [ ] Max 200 LoC per chunk
