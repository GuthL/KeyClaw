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
User CLI → KeyClaw Proxy → detect secrets (gitleaks rules) → replace with {{KEYCLAW_SECRET_xxx}}
→ store mapping in encrypted vault → forward sanitized request to API
```

### Response Flow (inbound)

```
API response → KeyClaw Proxy → scan for {{KEYCLAW_SECRET_xxx}} placeholders
→ resolve from vault → reinject real secrets → forward to CLI
```

### Key Design Decisions

1. **hudsucker** is the MITM proxy engine (HTTP/HTTPS/WebSocket)
2. **Gitleaks rules are compiled natively** — 220+ rules from `gitleaks.toml` parsed at startup into Rust regex. No subprocess needed.
3. **Placeholders are deterministic** — same secret always produces same placeholder ID (5-char prefix + SHA-256 hash)
4. **Vault is AES-GCM encrypted** with scrypt key derivation, atomic writes via temp file + rename
5. **WebSocket compression is stripped** — `Sec-WebSocket-Extensions` header is removed because tungstenite can't handle permessage-deflate (RSV1 bits)
6. **SSE streams are not buffered** — placeholders are resolved per-chunk via `map_frame` to preserve streaming behavior
7. **CA certs are generated at runtime** — no embedded certs, each machine generates its own on first run
8. **Custom rules** can be loaded from a file via `KEYCLAW_GITLEAKS_CONFIG` env var

## Module Map

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `gitleaks_rules.rs` | Parse gitleaks.toml, compile regex rules natively | `RuleSet`, `Rule`, `SecretMatch` |
| `proxy.rs` | MITM proxy server, HTTP/WS handlers | `Server`, `KeyclawHttpHandler` |
| `pipeline.rs` | Orchestrates rewrite pipeline | `Processor`, `RewriteResult` |
| `placeholder.rs` | Secret replacement using RuleSet, placeholder generation | `replace_secrets()`, `resolve_placeholders()` |
| `redaction.rs` | JSON tree walker, notice injection | `walk_json_strings()`, `inject_redaction_notice()` |
| `vault.rs` | AES-GCM encrypted secret↔placeholder storage | `Store` |
| `certgen.rs` | Runtime CA cert/key generation via rcgen | `ensure_ca()`, `CaPair` |
| `launcher.rs` | CLI subcommands (proxy, mitm, doctor, rewrite-json) | `Runner`, `run_cli()` |
| `config.rs` | Environment variable configuration | `Config` |
| `errors.rs` | Error types with deterministic codes | `KeyclawError` |
| `logscrub.rs` | Sanitizes secrets from log output | `scrub()` |

## Common Tasks

### Adding a new secret pattern

Add a `[[rules]]` entry to `gitleaks.toml` at the repo root. The rule needs `id`, `regex`, and optionally `keywords` (for fast pre-filtering) and `secretGroup` (capture group index). Rules are compiled at startup via `include_str!`.

For custom per-deployment rules, set `KEYCLAW_GITLEAKS_CONFIG=/path/to/custom.toml`.

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
Example: `{{KEYCLAW_SECRET_ghp_A_edc439282b0de94f}}`

The prefix is the first 5 characters of the secret (for human readability in logs).

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
- `mitm_not_effective` — proxy bypass detected
- `body_too_large` — request exceeds max body size
- `invalid_json` — JSON parse/rewrite failed
- `strict_resolve_failed` — placeholder resolution failed in strict mode

Check errors with `code_of(&err)` to get the code string.

## Testing

Tests are in `tests/`. Integration tests in `tests/integration_proxy.rs` spin up a real proxy. E2E tests in `tests/e2e_cli.rs` test the full binary. Unit tests cover placeholder logic, pipeline, and vault operations.

```bash
cargo test                          # All tests
cargo test placeholder              # Just placeholder tests
cargo test --test integration_proxy # Just proxy integration tests
cargo test --test e2e_cli           # Just e2e CLI tests
```

## Dependencies to Know

- **hudsucker 0.24** — MITM proxy engine (wraps hyper + rustls + tungstenite)
- **rcgen 0.14** — CA certificate generation (via hudsucker re-export)
- **aes-gcm** — Vault encryption
- **toml** — Parsing gitleaks.toml rules
- **regex** — Native regex compilation of gitleaks rules (with 50MB size limit for complex patterns)
- **scrypt** — Key derivation for vault passphrase

## Development Workflow

This project uses a **multi-agent dev team** workflow via the skill at `.claude/skills/multi-agent-dev-team/`.

### Required Roles (every non-trivial change)

1. **Product Manager** — Specs out the feature, defines acceptance criteria
2. **Dev Lead** — Implements the change
3. **PR Reviewer** — Reviews the code for correctness, performance, security, and architecture compliance before merge

### Optional Roles (as needed)

- **Architect** — System design decisions for major features
- **Security Reviewer** — Mandatory for any code touching secrets, vault, crypto, or proxy interception
- **QA Engineer** — Write tests for complex logic

### Ralph Loop Integration

For iterative development, use `/ralph-loop` with the dev team:

```
/ralph-loop "Implement [feature]. Follow multi-agent dev team workflow:
1. Check .claude/dev-team-state.md for current phase
2. If no spec, act as PM and create one
3. If spec exists, act as Dev Lead and implement
4. If implemented, act as PR Reviewer and review
5. If review has issues, fix them as Dev Lead
6. If all good, run cargo test && cargo build --release
7. If all green, commit and output <promise>APPROVED</promise>
Track state in .claude/dev-team-state.md" --completion-promise "APPROVED" --max-iterations 15
```

### Pre-commit Checklist

Always run before committing:
```bash
cargo test
cargo build --release
```
