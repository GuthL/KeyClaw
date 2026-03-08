# CLAUDE.md — Agent Guide to KeyClaw

This file helps AI coding agents (Claude, Codex, Cursor, etc.) understand and work with the KeyClaw codebase effectively.

## What Is KeyClaw?

KeyClaw is a **local MITM proxy** written in Rust that sits between AI coding CLI tools and their APIs. It intercepts HTTP/HTTPS/WebSocket traffic, detects secrets in request payloads, replaces them with safe placeholders, and reinjects the real values in responses — all transparently.

## Build & Test

```bash
cargo build --release      # Build optimized binary
cargo test                 # Run all tests
cargo build                # Debug build (faster compilation)
```

The binary is at `./target/release/keyclaw`. No external services needed for building or testing.

## Architecture Overview

### Request Flow (outbound)

```
User CLI → KeyClaw Proxy → detect secrets → replace with {{KEYCLAW_SECRET_<prefix>_<16 hex chars>}}
→ store mapping in encrypted vault → forward sanitized request to API
```

### Response Flow (inbound)

```
API response → KeyClaw Proxy → scan for {{KEYCLAW_SECRET_<prefix>_<16 hex chars>}} placeholders
→ resolve from vault → reinject real secrets → forward to CLI
```

### Key Design Decisions

1. **hudsucker** is the MITM proxy engine (HTTP/HTTPS/WebSocket)
2. **Placeholders are deterministic** — same secret always produces same placeholder ID (SHA-256 based)
3. **Vault is AES-GCM encrypted** with scrypt key derivation, atomic writes via temp file + rename
4. **Fail-closed by default** — if detection errors occur, requests are blocked, not silently passed
5. **WebSocket compression is stripped** — `Sec-WebSocket-Extensions` header is removed because tungstenite can't handle permessage-deflate (RSV1 bits)
6. **SSE streams are not buffered** — placeholders are resolved per-chunk via `map_frame` to preserve streaming behavior
7. **CA certs are generated at runtime** — no embedded certs, each machine generates its own on first run

## Module Map

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `proxy.rs` | MITM proxy server, HTTP/WS handlers | `Server`, `KeyclawHttpHandler` |
| `pipeline.rs` | Orchestrates rewrite + policy evaluation | `Processor`, `RewriteResult` |
| `placeholder.rs` | Placeholder parsing, generation, and resolution | `make_id()`, `resolve_placeholders()` |
| `redaction.rs` | JSON tree walker, notice injection | `walk_json_strings()`, `inject_redaction_notice()` |
| `vault.rs` | AES-GCM encrypted secret↔placeholder storage | `Store` |
| `certgen.rs` | Runtime CA cert/key generation via rcgen | `ensure_ca()`, `CaPair` |
| `policy.rs` | Block/warn/allow decisions from detector findings | `Executor`, `Decision`, `Action` |
| `detector/embedded.rs` | Built-in regex + entropy secret detection | `EmbeddedDetector` |
| `detector/gitleaks.rs` | Gitleaks subprocess wrapper | `GitleaksDetector` |
| `launcher.rs` | CLI subcommands (proxy, mitm, doctor, rewrite-json) | `Runner`, `run_cli()` |
| `config.rs` | Environment variable configuration | `Config` |
| `errors.rs` | Error types with deterministic codes | `KeyclawError` |
| `logscrub.rs` | Sanitizes secrets from log output | `scrub()` |

## Common Tasks

### Adding a new secret pattern

Edit `gitleaks.toml` to add or adjust the bundled rule, then use `tests/placeholder.rs` and `tests/integration_proxy.rs` to confirm the rewritten placeholder and round-trip resolution behavior. If the loading or compilation behavior itself needs to change, edit `src/gitleaks_rules.rs`.

### Changing proxy behavior

Edit `src/proxy.rs`. The `HttpHandler` impl on `KeyclawHttpHandler` has:
- `handle_request` — intercepts outbound requests, redacts secrets
- `handle_response` — intercepts inbound responses, resolves placeholders (both streaming and non-streaming)
- `should_intercept` — decides which CONNECT tunnels to MITM

The `WebSocketHandler` impl handles WS message interception (client→server redaction, server→client resolution).

### Adding a new CLI subcommand

Edit `src/launcher.rs` → `run_cli()` match block. Add a new arm and corresponding function.

### Changing the redaction notice

Edit `src/redaction.rs` → `inject_redaction_notice()`. The notice is injected differently for Anthropic (appended to `system` field) vs OpenAI (added as `developer` role message).

## Important Patterns

### Placeholder format
```
{{KEYCLAW_SECRET_<prefix>_<16 hex chars>}}
```
The prefix is up to 5 visible characters derived from the secret, followed by a 16-hex SHA-256 digest fragment.
Example: `{{KEYCLAW_SECRET_api_k_77dc0005c514277d}}`

### Vault path
```
~/.keyclaw/vault.enc
```

### CA cert/key (auto-generated)
```
~/.keyclaw/ca.crt
~/.keyclaw/ca.key
```

### Proxy env integration
```bash
source ~/.keyclaw/env.sh   # Sets HTTP_PROXY, SSL_CERT_FILE, etc.
```

## Error Handling

All errors use `KeyclawError` with optional deterministic codes:
- `blocked_by_leak_policy` — secret found, request blocked
- `gitleaks_unavailable` — gitleaks binary missing
- `mitm_not_effective` — proxy bypass detected

Check errors with `code_of(&err)` to get the code string.

## Testing

Tests are in `tests/`. Integration tests in `tests/integration_proxy.rs` spin up a real proxy. Unit tests cover detection, placeholder logic, policy decisions, and vault operations.

```bash
cargo test                          # All tests
cargo test placeholder              # Just placeholder tests
cargo test --test integration_proxy # Just proxy integration tests
```

## Dependencies to Know

- **hudsucker 0.24** — MITM proxy engine (wraps hyper + rustls + tungstenite)
- **rcgen 0.14** — CA certificate generation (via hudsucker re-export)
- **aes-gcm** — Vault encryption
- **aho-corasick** — Fast multi-pattern string matching for secret detection
- **scrypt** — Key derivation for vault passphrase
