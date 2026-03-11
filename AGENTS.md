# AGENTS.md — Agent Guide to KeyClaw

This guide gives coding agents the minimum context needed to work in the KeyClaw repository without rediscovering the runtime model from scratch.

## What KeyClaw Is

KeyClaw is a local MITM proxy for AI developer tools. It strips sensitive values out of outbound HTTP, SSE, and WebSocket traffic before it reaches the remote model, then resolves placeholders back into inbound responses on the local machine.

The v2 runtime is built around:

- `opaque_token` replacement for high-entropy credential-like spans
- typed structured detectors for `password`, `email`, `phone`, `national_id`, `passport`, `payment_card`, and `cvv`
- a session-scoped in-memory store instead of the old encrypted vault

## Build And Test

```bash
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Use focused loops when you change sensitive-data behavior:

```bash
cargo test placeholder
cargo test --test pipeline
cargo test --test integration_proxy
```

## Runtime Shape

### Request path

```text
Client -> KeyClaw proxy -> detect sensitive values -> replace with {{KEYCLAW_<KIND>_<id>}}
-> store in session-scoped resolver -> forward sanitized request upstream
```

### Response path

```text
Provider response -> KeyClaw proxy -> detect placeholders -> resolve from session store
-> reinject real values -> forward resolved response to the local client
```

### Important design decisions

1. Placeholders are opaque and typed, for example `{{KEYCLAW_OPAQUE_<id>}}` or `{{KEYCLAW_EMAIL_<id>}}`.
2. Placeholder IDs are session-scoped and do not expose prefixes from the original value.
3. `src/sensitive.rs` is the detector center. Do not add new runtime detection paths outside it unless there is a clear architectural reason.
4. `src/pipeline.rs` owns recursive request rewriting and response-side placeholder resolution.
5. SSE and WebSocket resolution must preserve streaming semantics instead of flattening the whole exchange into one buffer.
6. Fail-closed remains the default.

## Module Map

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `sensitive.rs` | Typed detection engine, optional local classifier, session store | `DetectionEngine`, `SensitiveKind`, `SessionStore` |
| `pipeline.rs` | Request rewrite and response resolution orchestration | `Processor`, `RewriteResult` |
| `placeholder.rs` | Placeholder generation, parsing, and resolution helpers | `make_typed()`, `resolve_placeholders_typed()` |
| `redaction.rs` | JSON walking and notice injection | `walk_json_strings()`, `inject_redaction_notice()` |
| `hooks.rs` | Hook parsing and request-side dispatch | `HookRunner` |
| `audit.rs` | Structured audit logging without raw values | `append_redactions()` |
| `stats.rs` | Audit-log summarization for CLI reporting | `summarize_audit_log()` |
| `proxy/common.rs` | Shared host checks and response helpers | `allowed()`, `request_host()` |
| `proxy/http.rs` | HTTP interception | `HttpHandler for KeyclawHttpHandler` |
| `proxy/streaming.rs` | SSE chunk buffering and placeholder resolution | `SseStreamResolver` |
| `proxy/websocket.rs` | WebSocket message rewriting and resolution | `WebSocketHandler for KeyclawHttpHandler` |
| `launcher/bootstrap.rs` | Runtime bootstrap and launched-tool wiring | `build_processor()`, `Runner` |
| `launcher/doctor.rs` | Operator health checks | `run_doctor()` |
| `config.rs` | Config-file and env parsing | `Config` |

## Common Tasks

### Adding a new sensitive-data detector

Edit `src/sensitive.rs` first. Add or adjust the detector, then extend:

- `tests/placeholder.rs` for placeholder contract checks
- `tests/pipeline.rs` for JSON rewrite behavior
- `tests/integration_proxy.rs` when the change affects end-to-end proxy behavior

If the change affects request notices or reporting, update `src/redaction.rs`, `src/audit.rs`, `src/hooks.rs`, or `src/stats.rs` as needed.

### Changing proxy behavior

Edit the focused modules under `src/proxy/` rather than the thin `src/proxy.rs` entrypoint:

- `src/proxy/http.rs`
- `src/proxy/streaming.rs`
- `src/proxy/websocket.rs`
- `src/proxy/common.rs`

### Changing configuration or CLI setup

Edit `src/config.rs` for config/env parsing and the split launcher modules under `src/launcher/` for command behavior. `keyclaw doctor` and `keyclaw init` should stay aligned with the documented runtime model.

## Placeholder Contract

Examples:

```text
{{KEYCLAW_OPAQUE_<16 hex chars>}}
{{KEYCLAW_EMAIL_<16 hex chars>}}
{{KEYCLAW_PASSWORD_<16 hex chars>}}
```

Use the shared helpers in `src/placeholder.rs` rather than hard-coding raw string checks in runtime code or tests.

## Error Handling

All CLI/runtime errors use `KeyclawError` with optional stable codes:

- `mitm_not_effective`
- `body_too_large`
- `invalid_json`
- `request_timeout`
- `strict_resolve_failed`
- `hook_blocked`

## Notes

- `keyclaw doctor` is the first place to look for operator-facing configuration and trust-boundary problems.
- The local classifier is optional and must remain secondary to deterministic detection.
- Keep raw sensitive values out of logs, hooks, audit records, and tests unless a test is explicitly proving scrubbing behavior.
