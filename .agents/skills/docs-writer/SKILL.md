---
name: docs-writer
description: Maintain README, API docs, CHANGELOG (Keep a Changelog).
allowed-tools: Read, Write, Edit, WebSearch
---

# Docs Writer Skill

## Steps
1. Update README: install, quick start, features, badges.
2. Update docs/API.md: every CLI command, exit codes.
3. Update CHANGELOG.md (Keep a Changelog).
4. `find docs -name '*.md' -exec markdown-link-check {} \;`

## Gates
- [ ] Functional quick start
- [ ] All CLI commands documented
- [ ] Zero broken links
- [ ] `cargo doc` warning-free
