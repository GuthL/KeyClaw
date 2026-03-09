# KeyClaw Production Readiness Project

Source plan: `docs/plans/2026-03-07-production-readiness.md`  
GitHub Project: https://github.com/users/GuthL/projects/1  
Repository: https://github.com/GuthL/KeyClaw

This file is the in-repo acceptance-criteria mirror for production-readiness work. GitHub is the source of truth for live issue state, assignees, project status, priority, and target dates.

Run `scripts/sync-production-readiness-project.py` to refresh this mirror from GitHub.

This mirror intentionally preserves only milestone association, labels, issue text, and acceptance criteria that are useful during release work.

## Milestone Map

| Milestone | Focus |
| --- | --- |
| M0 | Lock release scope and open decisions |
| M1 | Security closure |
| M2 | Reliability and operator UX closure |
| M3 | Release engineering and documentation closure |
| M4 | Release candidate verification and sign-off |

## Backlog

| Issue | Milestone | Labels | Task |
| --- | --- | --- | --- |
| [#1](https://github.com/GuthL/KeyClaw/issues/1) | M0 | `production-readiness` | Lock release scope and open decisions |
| [#2](https://github.com/GuthL/KeyClaw/issues/2) | M1 | `production-readiness` | Remaining security closure follow-up |

## Task Details

### Issue #1

Title: [Production Readiness] Lock release scope and open decisions  
Link: https://github.com/GuthL/KeyClaw/issues/1  
Milestone: M0  
Labels: `production-readiness`

GitHub is the source of truth for live issue state, assignees, project fields, priority, and target dates for this issue.

- [x] The supported platform matrix is explicitly documented.
- [x] The supported client-flow scope is explicitly documented.
- [x] The vault/key-management approach for v0.x is explicitly decided and recorded.
- [x] The documentation format decision is recorded.
- [x] The logging-scope decision is recorded.
- [x] The notice-mode decision is recorded.
- [x] The plan and project backlog reflect the final decisions with no remaining release-blocking ambiguity.

Decision summary:

- Supported release binaries are fixed to `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`.
- v0.x client-flow scope includes local Claude Code and Codex traffic plus direct OpenAI and Anthropic API traffic, provided the client actually routes through the KeyClaw proxy and trusts the generated local CA.
- v0.x vault protection defaults to a generated machine-local `vault.key`; `KEYCLAW_VAULT_PASSPHRASE` remains an explicit override only.
- README-first documentation plus `SECURITY.md`, `CONTRIBUTING.md`, and the maintainer release checklist is the complete v0.x docs surface; no separate docs site is required before launch.
- The current scrubbed leveled logging contract is sufficient for v0.x; a full structured logging migration is not a launch blocker.
- `KEYCLAW_NOTICE_MODE` now ships `verbose`, `minimal`, and `off`; v0.x keeps the current provider-specific injection points while letting operators pick the notice verbosity.

### Issue #2

Title: [Production Readiness] Remaining security closure follow-up  
Link: https://github.com/GuthL/KeyClaw/issues/2  
Milestone: M1  
Labels: `production-readiness`

GitHub is the source of truth for live issue state, assignees, project fields, priority, and target dates for this issue.

Security follow-up details remain tracked on GitHub; this mirror exists only to keep the milestone and acceptance context available in-repo during release work.
