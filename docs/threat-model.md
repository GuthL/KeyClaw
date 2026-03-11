# Threat Model

KeyClaw is a local protective layer for supported AI traffic. Its main purpose
is to keep raw sensitive values from reaching remote models, providers, logs,
and downstream tools when those values travel through the configured proxy path.

## Assets

The primary assets are:

- opaque tokens that may act like credentials
- passwords
- PII such as emails, phones, national IDs, and passports
- payment cards and CVV
- prompt content that may contain sensitive business data
- audit metadata
- placeholder mappings held in the session-scoped store
- the local CA private key

## Trust Boundary

Trusted local components:

- the rewrite engine in `src/pipeline.rs`
- the detector and session-scoped store in `src/sensitive.rs`
- placeholder parsing in `src/placeholder.rs`
- the local filesystem state under `~/.keyclaw/`

Untrusted or semi-trusted components:

- remote providers and hosted models
- retrieved web content and prompt content
- model output
- tool output
- request hooks that execute arbitrary commands
- the optional local classifier, because it can misclassify even when it runs on
  the same machine

KeyClaw assumes the workstation itself is trusted enough to run the local
process. A fully compromised workstation is out of scope.

## Main Adversaries

- a remote model or provider that logs or misuses raw input
- prompt injection that tries to force tool-based exfiltration
- accidental logging or telemetry that captures raw sensitive values
- local misconfiguration that causes traffic to bypass the proxy
- malformed payloads that try to confuse rewrite or reinjection logic
- a user or tool that replays stale placeholders after the session-scoped store
  has expired them

## Security Goals

1. Replace sensitive values before they leave the machine.
2. Keep placeholder mappings in a session-scoped store instead of a long-lived
   persistent secret database.
3. Prevent raw sensitive values from appearing in normal logs, audit records,
   and hook payloads.
4. Fail clearly when traffic bypasses the proxy or when placeholder resolution
   cannot be completed safely.

## Controls

### Pre-Provider Redaction

The core control is local request rewriting before the request reaches the
provider. If redaction succeeds, the model sees only placeholders such as
`{{KEYCLAW_...}}`.

### Session-Scoped Store

Placeholder mappings live in a session-scoped store with TTL behavior. This
limits the lifetime of locally stored sensitive material and reduces the blast
radius of restart-time state leakage.

### Fail-Closed Defaults

The normal posture is fail closed:

- rewrite failures block the request
- `KEYCLAW_REQUIRE_MITM_EFFECTIVE=true` can block wrapped CLI sessions if the
  proxy never sees traffic
- strict placeholder resolution treats unknown or expired placeholders as
  operator-visible failures

### Sanitized Observability

Audit logs, stats, and hook records are meant to carry metadata only:

- rule id
- kind
- subtype
- policy
- placeholder
- request host

They should not contain raw secrets or PII in the normal path.

### Narrow Host Scope

KeyClaw only inspects configured provider hosts plus explicit includes. This
keeps the proxy from acting as a general machine-wide inspection layer.

## Known Limits

- Detection is probabilistic. False negatives and false positives are possible.
- The system does not inspect multipart uploads or arbitrary binary files.
- Some desktop apps may bypass KeyClaw unless system proxy settings are correct.
- Shape-preserving placeholders intentionally leak visible structure such as
  length class and punctuation pattern.
- Expired placeholders cannot be resolved after the session-scoped store drops
  them.
- `KEYCLAW_UNSAFE_LOG=true` weakens the normal logging safety model and should be
  used only for local debugging.

## Out Of Scope

- protecting a fully compromised workstation
- protecting traffic that never routes through KeyClaw
- social engineering
- perfect semantic classification of every random-looking token
- guaranteeing availability against local denial-of-service

## Reporting

If you find a security issue, follow the private reporting instructions in
[`../SECURITY.md`](../SECURITY.md).
