# Detector Coverage

KeyClaw no longer treats detection as a provider-specific "secret catalog"
problem. The current runtime in `src/sensitive.rs` uses two detector families:

- `opaque token` detection for high-entropy random-looking spans
- typed structured detectors for low-entropy sensitive values

That design intentionally favors practical redaction over trying to prove that a
string is definitely a secret.

## Opaque Token Detection

The `opaque token` path is enabled by default.

It targets values that look random enough to be worth replacing, such as:

- API keys
- bearer tokens
- session tokens
- random identifiers that could act like credentials
- opaque encoded blobs that appear credential-like

High entropy is a signal, not proof. KeyClaw treats that as acceptable because
the runtime goal is reversible protection, not perfect semantic
classification.

The relevant controls are:

- `KEYCLAW_ENTROPY_ENABLED`
- `KEYCLAW_ENTROPY_THRESHOLD`
- `KEYCLAW_ENTROPY_MIN_LEN`

## Typed Structured Detectors

These detectors are off by default and can be enabled per class:

- password
- email
- phone
- national ID
- passport
- payment card
- CVV

Each typed detector is rules-first and validator-heavy. Examples:

- payment cards use card-number validation instead of regex alone
- CVV detection is gated by card context
- email and phone detection are stricter than a naive "find every symbol"
  pattern

The goal is to catch low-entropy sensitive values that an entropy-only model
would miss.

## Placeholder Contract

Every match is rewritten into the same format-preserving placeholder family:

```text
{{KEYCLAW_<shape>~<kind><id>}}
```

Where:

- `<shape>` preserves visible structure without preserving the value
- `<kind>` is a one-character tag
- `<id>` is a 16-hex opaque identifier in the current session

Example:

```text
sk-prod-ABCD1234EFGH5678
{{KEYCLAW_aa-aaaa-A0000A0A0000A000~o1c33f6b24d10f6c8}}
```

Kind tags currently used by `src/sensitive.rs`:

- `o`: opaque token
- `p`: password
- `e`: email
- `h`: phone
- `i`: national ID
- `s`: passport
- `c`: payment card
- `v`: CVV

## Recursive Rewriting

Detection is not limited to shallow JSON fields. KeyClaw also walks:

- nested stringified JSON
- base64-wrapped text that decodes into supported payloads
- message content embedded inside standard chat structures

That behavior is orchestrated by `src/pipeline.rs` and `src/redaction.rs`.

## Allowlist Behavior

KeyClaw supports three allowlist strategies:

- rule id
- regex pattern
- exact SHA-256 digest

Use the allowlist when you intentionally want a value or class to survive
rewriting. This is safer than globally disabling the detector family.

## Optional Classifier

The optional local classifier is a secondary disambiguation layer, not the core
detector. It should be used for low-confidence ambiguous matches only.

The runtime expects an OpenAI-compatible `/v1/chat/completions` endpoint. A
small local model can be useful for ambiguity filtering, but `src/sensitive.rs`
is still designed to function without a model at all.

## Testing Guidance

If you change detector behavior in `src/sensitive.rs`, also update:

- `tests/placeholder.rs`
- `tests/pipeline.rs`
- `tests/integration_proxy.rs` when end-to-end rewrite or reinjection behavior
  changes

Useful commands:

```bash
cargo test placeholder
cargo test --test pipeline
cargo test --test integration_proxy
```

## Non-Goals

The current detector model is not trying to:

- prove that every opaque value is a true credential
- classify every provider-specific key family by brand
- scan multipart uploads or arbitrary binary files
- keep placeholder mappings alive across daemon restarts
