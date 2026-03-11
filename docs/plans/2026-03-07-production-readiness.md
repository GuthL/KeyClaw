# KeyClaw Production Readiness Plan

This document records the release-scope decisions that were locked for the v0.x line.

## Locked v0.x Decisions

- Supported release binaries are fixed to `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`.
- Supported client flows are `Claude Code` and `Codex` requests for `OpenAI` and `Anthropic` traffic when the request routes through the KeyClaw proxy.
- Vault protection for v0.x stays machine-local with a generated `vault.key`; operators can still override it explicitly when needed.
- Documentation remains README-first, with no dedicated docs site required before launch.
- The current scrubbed logging surface is sufficient for v0.x; structured logging is not a launch blocker.
- The operator notice decision is locked to `KEYCLAW_NOTICE_MODE` with `verbose`, `minimal`, and `off`.
