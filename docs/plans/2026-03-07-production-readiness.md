# KeyClaw Production Readiness

This note locks the v0.x release scope and the final readiness decisions that remain relevant during release work.

## Locked v0.x Decisions

- Supported release binaries are fixed to `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`.
- Supported client flows for v0.x are local Claude Code and Codex traffic plus direct OpenAI and Anthropic API traffic, as long as the client actually routes through the KeyClaw proxy and trusts the generated local CA.
- Vault/key management stays machine-local for v0.x. KeyClaw generates and reuses `vault.key` by default; `KEYCLAW_VAULT_PASSPHRASE` remains an explicit override only.
- Documentation stays README-first, with `SECURITY.md`, `CONTRIBUTING.md`, and the maintainer release checklist as the complete v0.x docs surface; there is no dedicated docs site before launch.
- The current scrubbed leveled logging contract is sufficient for v0.x. structured logging is not a launch blocker.
- The provider-specific redaction notice behavior remains the v0.x contract, and `KEYCLAW_NOTICE_MODE` ships `verbose`, `minimal`, and `off` notice modes for v0.x.
