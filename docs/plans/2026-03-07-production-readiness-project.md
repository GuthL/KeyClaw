# KeyClaw Production Readiness Project

Source plan: `docs/plans/2026-03-07-production-readiness.md`

This file is the in-repo mirror for production-readiness acceptance criteria. GitHub is the source of truth for live issue state, assignees, project fields, priority, and target dates.

Run `scripts/sync-production-readiness-project.py` to refresh this mirror from GitHub when the backlog changes.

## Backlog

### Issue #1

Title: Lock v0.x release decisions

GitHub is the source of truth for live issue state, assignees, project fields, priority, and target dates for this issue.

- [x] The supported platform matrix is explicitly documented.
- [x] The supported client-flow scope is explicitly documented.
- [x] The vault/key-management approach for v0.x is explicitly decided and recorded.
- [x] The documentation format decision is recorded.
- [x] The logging-scope decision is recorded.
- [x] The notice-mode decision is recorded.
- [x] The plan and project backlog reflect the final decisions with no remaining release-blocking ambiguity.

Decision summary:

- Supported release binaries are `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`.
- `OpenAI` and `Anthropic` support remains in scope when traffic reaches the `KeyClaw proxy` from `Claude Code` and `Codex`.
- v0.x vault protection remains machine-local with a generated `vault.key`.
- Documentation stays README-first with no dedicated docs site.
- Structured logging is not a launch blocker for v0.x.
- `KEYCLAW_NOTICE_MODE` keeps `verbose`, `minimal`, and `off`.

### Issue #2

Title: Complete remaining production-readiness work

GitHub is the source of truth for live issue state, assignees, project fields, priority, and target dates for this issue.

- Keep follow-on production-readiness tasks synchronized from GitHub rather than maintaining duplicate manual status fields in-repo.
