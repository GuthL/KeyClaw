# Supported Sensitive-Data Detection

KeyClaw now uses a single in-process engine in `src/sensitive.rs` to decide what to redact from live traffic.

## What Gets Detected

The runtime has two detector families:

- **Opaque tokens:** high-entropy credential-like spans. The `opaque token` class is the default fallback for random-looking secrets that still need reversible replacement.
- **Typed structured data:** `password`, `email`, `phone`, `national_id`, `passport`, `payment_card`, and `cvv`

## Detection Pipeline

1. `src/pipeline.rs` finds user-controlled text inside JSON payloads, nested stringified JSON, and supported base64-wrapped content.
2. `src/sensitive.rs` runs typed structured detectors first.
3. The opaque-token entropy detector runs next.
4. Local allowlists are applied last.
5. An optional local classifier can reject ambiguous low-confidence matches, but it is not the primary detector.

## Placeholder Shape

KeyClaw rewrites each value into an opaque typed placeholder:

```text
{{KEYCLAW_OPAQUE_<16 hex chars>}}
{{KEYCLAW_EMAIL_<16 hex chars>}}
{{KEYCLAW_PASSWORD_<16 hex chars>}}
```

The IDs are session-scoped and do not expose prefixes from the original value.

## Adding A New Detector

1. Edit `src/sensitive.rs`.
2. Add targeted tests:

```bash
cargo test placeholder
cargo test --test pipeline
cargo test --test integration_proxy
```

3. Update reporting or notices if the new detector changes operator-visible metadata.

## What This Does Not Guarantee

- Perfect coverage for every provider or credential format
- Protection for sensitive values that never enter proxied traffic
- Protection if the client bypasses the proxy entirely

For the trust boundary and deployment assumptions, see [threat-model.md](threat-model.md).
