# /build — Implement

## Agents
@dev-rust, @sec-agent, @qa-agent

## Steps
1. @qa-agent writes failing tests (TDD)
2. @dev-rust implements
3. @sec-agent reviews each commit
4. Atomic commits per chunk

## Gates
- [ ] All tests pass
- [ ] No vuln from @sec-agent
- [ ] Every commit green in CI
