# Threat Model

KeyClaw is a local developer-security tool. Its goal is to keep raw sensitive values out of model prompts and responses that traverse supported proxied traffic.

## Protected Assets

- Opaque tokens and credentials that would otherwise be sent to upstream providers
- Typed structured data such as passwords, emails, phone numbers, IDs, passport numbers, payment cards, and CVV values
- Placeholder mappings kept in the session-scoped store
- Operator confidence that the proxy path is actually effective

## What KeyClaw Protects Against

- Accidental transmission of sensitive values to upstream LLM providers
- Prompt payloads that include credentials, `.env` snippets, or structured personal data
- Model responses that echo placeholders and need local reinjection
- Silent proxy bypass when `KEYCLAW_REQUIRE_MITM_EFFECTIVE=true`

## Trust Boundary

The trust boundary is the local machine running KeyClaw and the AI client.

- Detection runs locally.
- Placeholder generation runs locally.
- The session-scoped store lives locally in memory.
- Upstream providers only see sanitized placeholder forms, not raw values.

## Assumptions

- The workstation itself is not already compromised.
- The client is configured to route the relevant traffic through KeyClaw.
- The client trusts the KeyClaw-generated CA.
- Operators do not intentionally disable safety features such as log scrubbing without understanding the risk.

## Out Of Scope

- Protection against local malware or a compromised developer workstation
- Traffic that never traverses the KeyClaw proxy
- Hosts outside the built-in provider lists and any operator-supplied `include` patterns
- Side channels such as exact secret-length leakage
- Perfect detection across every possible prompt shape or value format

## Failure Modes To Watch

- `NO_PROXY` or direct client configuration bypasses the proxy
- Broken CA trust makes the client talk around KeyClaw or fail TLS entirely
- `KEYCLAW_UNSAFE_LOG=true` can leak raw values to local logs
- Short session TTLs can cause placeholder resolution misses if a long-running conversation refers back to old placeholders
- Overbroad allowlist entries can intentionally suppress needed redactions

## Operational Guidance

- Run `keyclaw doctor` after setup changes.
- Keep `KEYCLAW_REQUIRE_MITM_EFFECTIVE=true` enabled.
- Leave `KEYCLAW_UNSAFE_LOG` unset outside short-lived debugging.
- Review allowlist entries carefully; they are explicit escapes from normal protection.
- Treat the local CA material and proxy host machine as sensitive local state.

## Summary

KeyClaw is strongest when treated as a local inline control for supported traffic, not as a universal data-loss-prevention platform. It reduces accidental exposure to model providers, but it does not replace workstation security, credential hygiene, or offline scanning.
