# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in KeyClaw, **please do not open a public issue.**

Instead, please report it privately:

1. Email: Open a [private security advisory](https://github.com/GuthL/KeyClaw/security/advisories/new) on GitHub
2. Include a description of the vulnerability, steps to reproduce, and potential impact

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

KeyClaw's security model is documented in the [README](README.md#security-model). In scope:

- Bypass of sensitive-data detection (a value that should be caught but isn't)
- Proxy bypass techniques (traffic that avoids interception)
- CA certificate generation weaknesses
- Log scrubbing failures (sensitive values appearing in log output)

Out of scope:

- Attacks requiring local machine compromise (KeyClaw's trust boundary is the local machine)
- Traffic or secrets that never pass through KeyClaw's configured local proxy path
- Social engineering
- Denial of service against the local proxy

## Trust Boundary

KeyClaw is a local developer tool, not a hosted secret manager.

- It only protects supported Claude/Codex traffic that actually routes through the KeyClaw proxy on your machine.
- The CA certificate and session-scoped placeholder store stay local to the machine running KeyClaw.
- Sensitive-data detection, placeholder generation, and placeholder reinjection run in-process on the local machine.

## Non-Goals And Limits

- Protecting a compromised workstation
- Guaranteeing perfect detection coverage across every provider or credential format
- Preventing side channels such as secret length leakage
- Protecting traffic sent to hosts outside the configured intercept lists

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `master` | Yes |

## Security Design Principles

1. **Fail closed** — If detection fails, requests are blocked, not passed through
2. **No embedded secrets** — CA certificates are generated per-machine at runtime
3. **Session-scoped storage** — Placeholder mappings live in a TTL-bound local store instead of a long-lived secret vault
4. **Log sanitization** — All log output is scrubbed for known sensitive patterns
5. **Minimal trust** — The proxy only intercepts configured hosts; all other traffic passes through untouched
6. **In-process detection** — Detection runs inside `src/sensitive.rs`; there is no required external detector subprocess in the runtime trust boundary
7. **Strict local resolution** — Missing or expired placeholders are treated as operator-visible errors in strict paths instead of being silently resolved to empty values
8. **Unsafe logging is explicit** — `KEYCLAW_UNSAFE_LOG=true` is the only intentional way to bypass normal log scrubbing, and it is for local debugging only
