# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in KeyClaw, **please do not open a public issue.**

Instead, please report it privately:

1. Email: Open a [private security advisory](https://github.com/GuthL/KeyClaw/security/advisories/new) on GitHub
2. Include a description of the vulnerability, steps to reproduce, and potential impact

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

KeyClaw's security model is documented in the [README](README.md#security-model). In scope:

- Bypass of secret detection (a secret that should be caught but isn't)
- Vault encryption weaknesses
- Proxy bypass techniques (traffic that avoids interception)
- CA certificate generation weaknesses
- Log scrubbing failures (secrets appearing in log output)

Out of scope:

- Attacks requiring local machine compromise (KeyClaw's trust boundary is the local machine)
- Social engineering
- Denial of service against the local proxy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `master` | Yes |

## Security Design Principles

1. **Fail closed** — If detection fails, requests are blocked, not passed through
2. **No embedded secrets** — CA certificates are generated per-machine at runtime
3. **Encrypted at rest** — The vault uses AES-256-GCM with scrypt key derivation, keyed by either an explicit `KEYCLAW_VAULT_PASSPHRASE` override or a generated machine-local `vault.key`
4. **Log sanitization** — All log output is scrubbed for known secret patterns
5. **Minimal trust** — The proxy only intercepts configured hosts; all other traffic passes through untouched
6. **In-process detection** — Secret detection uses the bundled gitleaks rules compiled into the binary; there is no external gitleaks subprocess in the runtime trust boundary
7. **Fail closed on bad key material** — Missing, mismatched, or corrupt vault key material is treated as an operator-visible error, not as an empty vault
8. **Unsafe logging is explicit** — `KEYCLAW_UNSAFE_LOG=true` is the only intentional way to bypass normal log scrubbing, and it is for local debugging only
