# Architecture

KeyClaw is a local interception layer for supported AI client traffic. It does
three things on the hot path:

1. rewrites outbound JSON payloads before they leave the machine
2. teaches the model that `{{KEYCLAW_...}}` placeholders are safe to use
3. resolves those placeholders back to the original values locally before
   requests to external systems are emitted

The current runtime is intentionally centered on a small set of in-process
modules instead of external detector subprocesses or a persistent vault.

## Runtime Flow

### 1. Intercept

Traffic reaches KeyClaw through one of two paths:

- `keyclaw codex ...` or `keyclaw claude ...` for an ephemeral wrapper around a
  child process
- `keyclaw proxy start` for a detached local proxy daemon

Only requests sent to configured provider hosts are inspected. Other traffic is
passed through untouched.

### 2. Parse And Walk JSON

The request body is parsed as JSON and only user-authored content is rewritten.
Hidden prompt fields that belong to the client or provider are intentionally not
treated the same as user message content.

String values are walked recursively, including:

- top-level prompt or instructions fields when the API surface uses them
- message content arrays
- nested stringified JSON
- base64-wrapped payloads that decode into supported text content

The JSON walking and notice injection logic lives in `src/redaction.rs`.

### 3. Detect Sensitive Values

`src/sensitive.rs` is the current center of the detection runtime.

The detection engine combines two detector families:

- `opaque_token`: high-entropy tokens that look random enough to be worth
  replacing even if they are not tied to a provider-specific secret catalog
- typed structured detectors: passwords, emails, phones, national IDs,
  passports, payment cards, and CVV

The optional local classifier is secondary. It only participates when enabled
and when a candidate is ambiguous enough to benefit from a second opinion.

### 4. Replace With Format-Preserving Placeholders

Matches are rewritten into the format-preserving placeholder contract:

```text
{{KEYCLAW_<shape>~<kind><id>}}
```

`<shape>` preserves the visible character layout without exposing the actual
value. `<kind>` is a one-character sensitive-data tag. `<id>` is an opaque
session identifier.

Placeholder parsing and rendering live in `src/placeholder.rs`.

### 5. Store The Mapping Locally

The rewritten value is stored in a session-scoped store with TTL semantics.
There is no long-lived encrypted vault in the current runtime.

The session-scoped store is held in process memory and is designed to support:

- response reinjection
- SSE and supported WebSocket reinjection
- short-lived local recovery after a placeholder appears in later turns

Because the mapping is session-scoped, a restart intentionally breaks the old
mapping once the process and its TTL state are gone.

### 6. Inject The Redaction Notice

After rewriting, KeyClaw injects a short operator-controlled notice so the model
knows it is seeing placeholders rather than the original values.

The notice:

- explains that the real values never reached the model
- describes the format-preserving placeholder syntax
- instructs the model to use placeholders normally

The notice is injected differently depending on the target payload shape:

- Anthropic-style traffic gets the notice in the trusted `system` context
- OpenAI/Codex-style traffic gets the notice as a `developer` message

### 7. Reinject On The Way Back

When the model returns text, KeyClaw scans for placeholders and resolves them
locally. The resolved value is never looked up remotely.

Strict resolution paths raise operator-visible errors if a placeholder is
unknown or expired. The goal is to fail clearly rather than silently turn a
placeholder into an empty string.

## Main Modules

- `src/launcher.rs`: CLI entrypoint and command wiring
- `src/proxy/`: HTTP, SSE, and WebSocket interception and forwarding
- `src/pipeline.rs`: request rewrite and response resolution orchestration
- `src/sensitive.rs`: detector engine, match metadata, and session-scoped store
- `src/placeholder.rs`: placeholder rendering, parsing, and replacement records
- `src/redaction.rs`: JSON walking and notice injection
- `src/config.rs`: defaults, config-file loading, and env overrides
- `src/hooks.rs`: request-side hook dispatch for log, exec, and block actions
- `src/audit.rs`: sanitized JSONL audit log output
- `src/stats.rs`: aggregated stats for `keyclaw proxy stats`

## Configuration Boundaries

Configuration precedence is:

1. built-in defaults
2. `~/.keyclaw/config.toml`
3. environment variable overrides

The runtime intentionally separates:

- host scoping
- detection settings
- operator logging and notice settings
- hook actions

That keeps operational policy visible without burying it inside detector code.

## Fail-Closed Posture

By default, KeyClaw treats rewrite failures as blocking failures. If a request
should have been inspected but the rewrite path cannot safely complete, the
request is rejected instead of being silently forwarded.

Two related operator controls matter here:

- `fail_closed`
- `KEYCLAW_REQUIRE_MITM_EFFECTIVE`

The first controls rewrite-time behavior. The second controls whether wrapped
CLI sessions should fail when traffic appears to have bypassed the local proxy.

## Observability

The runtime has three main observability surfaces:

- sanitized JSONL audit logs
- hook dispatch events
- aggregated proxy stats derived from the audit log

None of these are supposed to contain raw secrets or PII in the normal path.
`KEYCLAW_UNSAFE_LOG=true` is the explicit escape hatch for local debugging.

## Design Consequences

The current architecture is optimized for:

- local-first operation
- reversible placeholders
- clear operator failure modes
- a small, understandable trust boundary

It is not optimized for:

- binary file inspection
- arbitrary desktop-app traffic without proxy cooperation
- indefinite placeholder persistence across restarts
- perfect classification of every random-looking token
