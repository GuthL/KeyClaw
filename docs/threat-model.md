# Threat Model

KeyClaw is a local developer-security tool. Its goal is to keep raw secrets out of model prompts and responses that traverse supported proxied traffic.

## Protected Assets

- API keys and cloud credentials in prompts or request bodies
- Secret-bearing config fragments such as `.env` content
- Tokens repeated back by the model in HTTP, SSE, or WebSocket responses
- Local operator confidence that the proxy path is actually effective

## What KeyClaw Protects Against

- Accidental transmission of secrets to upstream LLM providers
- Prompt payloads that include API keys, access tokens, or private key material
- Model responses that echo placeholders and need local secret reinjection
- Silent proxy bypass when `KEYCLAW_REQUIRE_MITM_EFFECTIVE=true`

## Trust Boundary

The trust boundary is the local machine running KeyClaw and the AI client.

- Secret detection runs locally.
- Placeholder generation runs locally.
- The encrypted vault and local CA are stored locally.
- Upstream providers only see the sanitized placeholder form, not the raw secret.

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
- Perfect secret detection across every possible format

## Failure Modes To Watch

- `NO_PROXY` or direct client configuration bypasses the proxy
- Broken CA trust makes the client talk around KeyClaw or fail TLS entirely
- Invalid custom rulesets reduce or prevent detection
- `KEYCLAW_UNSAFE_LOG=true` can leak raw secrets to local logs
- Incorrect vault key material prevents placeholder resolution

## Operational Guidance

- Run `keyclaw doctor` after setup changes.
- Keep `KEYCLAW_REQUIRE_MITM_EFFECTIVE=true` enabled.
- Leave `KEYCLAW_UNSAFE_LOG` unset outside of short-lived debugging.
- Review allowlist entries carefully; they are explicit escapes from normal protection.
- Treat the local vault, CA material, and home directory as sensitive local state.

## Summary

KeyClaw is strongest when it is treated as a local inline control for supported traffic, not as a universal secret-management system. It reduces accidental exposure to model providers, but it does not replace workstation security, credential hygiene, or offline secret scanning.
