# Security Policy

## Reporting A Vulnerability

Do not open a public issue for security reports.

Use GitHub's private advisory flow instead:

1. open a [private security advisory](https://github.com/GuthL/KeyClaw/security/advisories/new)
2. describe the issue, impact, and reproduction path
3. include whether the issue requires local compromise, proxy bypass, or a
   supported KeyClaw traffic path

We aim to acknowledge reports within 48 hours.

## Scope

In scope:

- detection bypasses for supported traffic routed through KeyClaw
- placeholder reinjection failures that expose raw values or break strict
  resolution guarantees
- proxy bypasses that defeat the documented CLI or daemon flow
- CA generation or trust wiring flaws
- audit, hook, or log scrubbing failures that leak raw sensitive values

Out of scope:

- a fully compromised workstation
- traffic that never routes through KeyClaw
- social engineering
- general local denial-of-service

## Supported Versions

| Version | Supported |
| ------- | --------- |
| Latest on `master` or `main` | Yes |

## Security Model

KeyClaw is a local interception layer, not a hosted secret manager.

- sensitive values are rewritten before they leave the machine
- placeholders are resolved locally from a session-scoped store
- the current runtime does not use a long-lived persistent vault
- logs and hook payloads are supposed to stay sanitized by default

The core trust boundary is local. Remote providers, models, prompt content, and
tool output are all treated as untrusted.

## Design Principles

1. Fail closed when a rewrite should happen but cannot complete safely.
2. Keep the sensitive-data engine in process in `src/sensitive.rs`.
3. Use a session-scoped store instead of a long-lived vault.
4. Keep audit logs and hooks metadata-only in the normal path.
5. Make unsafe debugging explicit through `KEYCLAW_UNSAFE_LOG=true`.
6. Keep the inspected host set narrow and operator-controlled.

## Limits

KeyClaw does not guarantee:

- perfect detection precision or recall
- binary or multipart inspection
- safe behavior on a compromised workstation
- protection for traffic outside the configured proxy path

For the detailed runtime threat framing, see
[`docs/threat-model.md`](./docs/threat-model.md).
