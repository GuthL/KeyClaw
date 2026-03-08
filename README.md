<div align="center">

```
 ╦╔═╔═╗╦ ╦╔═╗╦  ╔═╗╦ ╦
 ╠╩╗║╣ ╚╦╝║  ║  ╠═╣║║║
 ╩ ╩╚═╝ ╩ ╚═╝╩═╝╩ ╩╚╩╝
```

**Detected secrets are swapped locally before they leave your machine.**

A transparent MITM proxy that intercepts AI coding assistant traffic,<br>
redacts secrets before they reach the cloud, and reinjects them on the way back.

[Getting Started](#getting-started) •
[How It Works](#how-it-works) •
[Configuration](#configuration) •
[Contributing](CONTRIBUTING.md)

---

</div>

## The Problem

AI coding assistants like **Claude Code** and **OpenAI Codex** are incredibly powerful — but they see everything. API keys, tokens, credentials, and secrets in your codebase get sent to remote servers as part of every request.

**KeyClaw fixes this.** It sits between your CLI tool and the API, automatically detecting and replacing secrets with safe placeholders before they leave your machine. The AI never sees your real credentials, but everything still works — because KeyClaw reinjects the real values on the fly.

## How It Works

```
┌─────────────┐     ┌──────────────────────────────────┐     ┌─────────────┐
│             │     │           KeyClaw Proxy           │     │             │
│  Claude CLI ├────►│                                   ├────►│ Anthropic   │
│  Codex CLI  │     │  1. Intercept request             │     │ OpenAI      │
│             │◄────┤  2. Detect secrets (gitleaks rules)│◄────┤ API         │
│             │     │  3. Replace with {{KEYCLAW_xxx}}   │     │             │
│             │     │  4. Store in encrypted vault       │     │             │
│             │     │  5. Forward sanitized request      │     │             │
│             │     │  6. Reinject secrets in response   │     │             │
│             │     │                                   │     │             │
└─────────────┘     └──────────────────────────────────┘     └─────────────┘
                              ▲
                              │
                    ┌─────────┴─────────┐
                    │  ~/.keyclaw/       │
                    │  ├── vault.enc     │  AES-GCM encrypted
                    │  ├── vault.key     │  Machine-local key
                    │  ├── ca.crt        │  Auto-generated
                    │  ├── ca.key        │  Per-machine
                    │  └── env.sh        │  Shell integration
                    └───────────────────┘
```

### Detection

KeyClaw bundles the full [Gitleaks](https://github.com/gitleaks/gitleaks) ruleset (220+ rules) compiled natively into Rust regex at startup. No subprocess, no external binary needed.

Rules cover:
- **Provider keys** — OpenAI, Anthropic, AWS, GitHub, GitLab, Slack, Stripe, GCP, and 200+ more
- **Generic patterns** — `api_key=...`, `secret_key=...`, `access_token=...`
- **Private keys** — RSA, EC, OPENSSH, PGP, age

Custom rules can be loaded from a file via `KEYCLAW_GITLEAKS_CONFIG`.

### What Makes It Different

- **Transparent** — Works as a drop-in proxy. No code changes, no wrapper SDKs.
- **Bidirectional** — Redacts secrets in requests, reinjects them in responses (including SSE streams and WebSocket).
- **Machine-agnostic** — Generates its own CA certificate on first run. Clone, build, run.
- **No external deps** — Gitleaks rules are compiled natively; no subprocess or binary needed.
- **Vault-backed** — Secrets are stored in an AES-GCM encrypted vault with atomic writes. Placeholders are deterministic per-secret.

## Getting Started

### Prerequisites

- Rust 1.75+ and Cargo

### Install

```bash
git clone https://github.com/GuthL/KeyClaw.git
cd KeyClaw
cargo build --release
```

Check the installed entrypoint before wiring it into your shell:

```bash
./target/release/keyclaw --help
./target/release/keyclaw --version
```

### Supported Surface (v0.x)

KeyClaw's first public release intentionally keeps the support matrix narrow:

- Official release binaries: `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`
- Supported client flows: local Claude Code and Codex traffic that actually routes through the KeyClaw proxy
- Deferred from v0.x: Windows support, extra protocol families, and configurable notice-injection modes

### Quick Start — Global Proxy

The simplest way to use KeyClaw. Start the proxy, source the env, and use your CLI tools as normal:

```bash
# Terminal 1: Start the proxy
./target/release/keyclaw proxy

# Terminal 2: Source the env and use your tools
source ~/.keyclaw/env.sh
claude "what API keys are in my .env?"   # secrets are redacted automatically
codex "deploy using my AWS credentials"  # same protection for Codex
```

The `env.sh` script validates that the recorded `keyclaw proxy` process is still the active instance before exporting proxy variables, and it ignores stale PID state safely — safe to add to your `.bashrc`.
It also exports `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `NODE_EXTRA_CA_CERTS` so supported CLI tools route through KeyClaw and trust the local CA.

### Quick Start — MITM Wrapper

Wraps a single CLI session with automatic proxy setup and teardown:

```bash
# Wrap a Codex session
./target/release/keyclaw mitm codex -- codex

# Wrap a Claude session
./target/release/keyclaw mitm claude -- claude
```

The `mitm` wrapper injects the proxy and CA trust environment for the child process automatically. Use it when you want a single protected session without sourcing shell-wide proxy variables.

### Verify It Works

```bash
./target/release/keyclaw doctor
```

`keyclaw doctor` is the first thing to run after changing local config or before debugging a failed `mitm` session. It checks the proxy bind address, proxy URL, CA readiness, vault path, vault key material, custom gitleaks config, proxy-bypass risk, and other operator-facing safety knobs.

Interpret the output like this:

- `PASS` — the check is ready for normal use
- `WARN` — KeyClaw can still run, but the config is risky or non-standard
- `FAIL` — fix this before relying on the proxy; `doctor` exits non-zero
- `hint:` — the next operator action to take for that specific check

## Troubleshooting

Start with `./target/release/keyclaw doctor`. It is the fastest way to catch broken CA files, proxy bypass, custom ruleset problems, and missing vault key material before you debug the CLI itself.

### Certificate Trust Or TLS Errors

- Use either `source ~/.keyclaw/env.sh` from `keyclaw proxy` or the `keyclaw mitm ...` wrapper so the child process sees the local proxy URL and CA bundle variables.
- Confirm `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, or `NODE_EXTRA_CA_CERTS` point at `~/.keyclaw/ca.crt` if you are wiring the environment manually.
- If `doctor` reports a broken or partial CA pair, remove the bad files in `~/.keyclaw/` and rerun `keyclaw proxy` to regenerate them locally.

### Proxy Bypass Or No Intercepted Traffic

- Unset `NO_PROXY` or remove intercepted hosts such as `api.openai.com`, `chatgpt.com`, `api.anthropic.com`, or `claude.ai`.
- Leave `KEYCLAW_REQUIRE_MITM_EFFECTIVE=true` enabled so `mitm` fails loudly instead of silently running without interception.
- Set `KEYCLAW_LOG_LEVEL=debug` when you need to see per-request intercept and rewrite activity.

### Custom Ruleset Or Vault Key Problems

- If `doctor` fails the `ruleset` check, fix `KEYCLAW_GITLEAKS_CONFIG` or unset it to go back to the bundled rules.
- If `doctor` fails the `vault-key` check, restore `~/.keyclaw/vault.key` or set `KEYCLAW_VAULT_PASSPHRASE` explicitly to the correct value.

## Configuration

KeyClaw is configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYCLAW_PROXY_ADDR` | `127.0.0.1:8877` | Proxy listen address |
| `KEYCLAW_PROXY_URL` | `http://127.0.0.1:8877` | Proxy URL exported to child processes |
| `KEYCLAW_CA_CERT` | (auto-generated `~/.keyclaw/ca.crt`) | Override CA cert path passed to clients |
| `KEYCLAW_VAULT_PATH` | `~/.keyclaw/vault.enc` | Encrypted vault location |
| `KEYCLAW_VAULT_PASSPHRASE` | (unset; KeyClaw creates `~/.keyclaw/vault.key`) | Explicit vault key override |
| `KEYCLAW_CODEX_HOSTS` | `api.openai.com,chat.openai.com,chatgpt.com` | Codex/OpenAI hosts to intercept |
| `KEYCLAW_CLAUDE_HOSTS` | `api.anthropic.com,claude.ai` | Claude/Anthropic hosts to intercept |
| `KEYCLAW_MAX_BODY_BYTES` | `2097152` (2MB) | Maximum request body size |
| `KEYCLAW_DETECTOR_TIMEOUT` | `4s` | Timeout for request-body secret detection and streamed body reads (`250ms`, `4s`, `1m` formats supported) |
| `KEYCLAW_GITLEAKS_CONFIG` | (bundled rules) | Path to custom gitleaks.toml rule file |
| `KEYCLAW_LOG_LEVEL` | `info` | Operator log verbosity for stderr runtime messages (`error`, `warn`, `info`, `debug`) |
| `KEYCLAW_UNSAFE_LOG` | `false` | Disable normal log scrubbing and log raw secret material for debugging only; unsafe and opt-in |
| `KEYCLAW_FAIL_CLOSED` | `true` | Fail closed on errors |
| `KEYCLAW_REQUIRE_MITM_EFFECTIVE` | `true` | Fail if proxy bypass is detected |

KeyClaw does not use or require `KEYCLAW_GITLEAKS_BIN`. Secret detection uses the bundled gitleaks rules compiled natively into the binary; set `KEYCLAW_GITLEAKS_CONFIG` only when you want to override those rules with your own TOML file.

By default, KeyClaw creates a machine-local vault key next to the encrypted vault and reuses it on later runs. Set `KEYCLAW_VAULT_PASSPHRASE` only when you need to override that key material explicitly. Existing vaults written with the removed built-in default are migrated to a generated local key on the next successful write. If an existing vault cannot be decrypted or its key material is missing, KeyClaw fails closed and tells you how to recover.

The only intentional exception to scrubbed runtime logging is `KEYCLAW_UNSAFE_LOG=true`. When enabled, KeyClaw may write raw request fragments to stderr or `~/.keyclaw/mitm.log` to help debug interception problems. Leave it unset for normal use.

## Logging

Operator-facing runtime messages use leveled stderr prefixes:

- `keyclaw info:` startup, shutdown, CA/ruleset initialization, and other lifecycle summaries
- `keyclaw debug:` per-request proxy activity such as interception, rewrite, and placeholder resolution
- `keyclaw warn:` risky but non-fatal conditions such as unsafe logging or bypass risk
- `keyclaw error:` fatal CLI errors before exit

Set `KEYCLAW_LOG_LEVEL=error`, `warn`, `info`, or `debug` to reduce or expand stderr verbosity. The default is `info`, which stays lifecycle-focused and avoids emitting a line for every proxied request. Use `debug` when troubleshooting live traffic. The `doctor` subcommand is intentionally separate: it writes its `doctor: PASS|WARN|FAIL ...` report to stdout so it can be piped or parsed cleanly.

## Error Codes

KeyClaw uses deterministic error codes for programmatic handling:

| Code | Meaning |
|------|---------|
| `mitm_not_effective` | Proxy bypass detected (e.g., `NO_PROXY=*`) |
| `body_too_large` | Request body exceeds `KEYCLAW_MAX_BODY_BYTES` |
| `invalid_json` | Failed to parse/rewrite request JSON |
| `request_timeout` | Request body read timed out before inspection completed |
| `strict_resolve_failed` | Placeholder resolution failed in strict mode |

## Request Handling Notes

- Oversized JSON request bodies are rejected with `413 body_too_large` and are not forwarded upstream.
- Request bodies that do not finish streaming before `KEYCLAW_DETECTOR_TIMEOUT` are rejected with `408 request_timeout`.
- Malformed JSON request bodies are passed through unchanged; KeyClaw only rewrites payloads it can parse safely.

## Security Model

### What KeyClaw Protects Against

- Secrets in your codebase being sent to AI APIs
- API keys, tokens, and credentials leaking through CLI tool traffic
- Accidental exposure of `.env` files, config files, and hardcoded credentials

### Non-Goals And Limits

- A compromised local machine (KeyClaw runs locally — if your machine is compromised, all bets are off)
- Traffic that never uses the KeyClaw proxy or targets hosts outside the configured intercept lists
- Perfect secret detection across every provider, credential format, or prompt phrasing
- Side-channel leakage (e.g., secret length is preserved in placeholders)

### Trust Boundary

The trust boundary is your machine. KeyClaw only protects traffic that a supported CLI actually routes through the local proxy. The CA certificate is generated locally and never leaves your machine. The encrypted vault and its machine-local key stay on disk locally unless you explicitly override the key with `KEYCLAW_VAULT_PASSPHRASE`. Secret detection, placeholder generation, and reinjection all happen in-process.

## Project Structure

```
src/
├── main.rs            # Entry point
├── lib.rs             # Module declarations
├── certgen.rs         # Runtime CA certificate generation
├── config.rs          # Environment-based configuration
├── gitleaks_rules.rs  # Bundled gitleaks rule loading + native regex compilation
├── proxy.rs           # MITM proxy (HTTP, SSE, WebSocket)
├── pipeline.rs        # Request rewrite pipeline
├── placeholder.rs     # Placeholder parsing, generation, and resolution
├── redaction.rs       # JSON walker + notice injection
├── vault.rs           # AES-GCM encrypted secret storage
├── launcher.rs        # CLI launcher (mitm/proxy/doctor)
├── logscrub.rs        # Log sanitization
└── errors.rs          # Error types and codes
gitleaks.toml          # Bundled detection rules compiled by gitleaks_rules.rs
```

## Agent Guides

This repository includes dedicated guide files for AI coding agents:

| File | Agent | Purpose |
|------|-------|---------|
| [`CLAUDE.md`](CLAUDE.md) | Claude Code | Helps Claude understand the codebase architecture, module map, build commands, and common tasks |
| [`AGENTS.md`](AGENTS.md) | OpenAI Codex | Same guide in the format expected by Codex CLI |

These files are automatically picked up by their respective agents when working in the repository, giving them context about the project structure, key design decisions, and how to navigate the code.

## Tests

```bash
cargo test
```

## License

[MIT](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

<div align="center">
<sub>Built for developers who use AI assistants but take security seriously.</sub>
</div>
