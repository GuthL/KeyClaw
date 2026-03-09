<div align="center">

<pre>
 ╦╔═╔═╗╦ ╦╔═╗╦  ╔═╗╦ ╦
 ╠╩╗║╣ ╚╦╝║  ║  ╠═╣║║║
 ╩ ╩╚═╝ ╩ ╚═╝╩═╝╩ ╩╚╩╝
</pre>

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

**KeyClaw fixes this.** It sits between your CLI tool or API client and the upstream API, automatically detecting and replacing secrets with safe placeholders before they leave your machine. The AI never sees your real credentials, but everything still works — because KeyClaw reinjects the real values on the fly.

## How It Works

```
┌─────────────┐     ┌──────────────────────────────────────┐     ┌─────────────┐
│             │     │            KeyClaw Proxy             │     │             │
│  Claude CLI ├────►│                                      ├────►│ Anthropic   │
│  Codex CLI  │     │  1. Intercept request                │     │ OpenAI      │
│             │◄────┤  2. Detect secrets (gitleaks rules)  │◄────┤ API         │
│             │     │  3. Replace with {{KEYCLAW_xxx}}     │     │             │
│             │     │  4. Store in encrypted vault         │     │             │
│             │     │  5. Forward sanitized request        │     │             │
│             │     │  6. Reinject secrets in response     │     │             │
│             │     │                                      │     │             │
└─────────────┘     └──────────────────────────────────────┘     └─────────────┘
                                       ▲
                                       │
                            ┌──────────┴──────────┐
                            │  ~/.keyclaw/        │
                            │  ├── vault.enc      │  AES-GCM encrypted
                            │  ├── vault.key      │  Machine-local key
                            │  ├── ca.crt         │  Auto-generated
                            │  ├── ca.key         │  Per-machine
                            │  └── env.sh         │  Shell integration
                            └─────────────────────┘
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
cargo install --path .
```

Check the installed entrypoint before wiring it into your shell:

```bash
keyclaw --help
keyclaw --version
```

For a guided first-run setup, run:

```bash
keyclaw init
```

That generates the local CA and env script, creates the machine-local vault key when needed, offers to patch your shell rc file, and finishes by running `keyclaw doctor`.

### Supported Surface (v0.x)

KeyClaw's first public release intentionally keeps the support matrix narrow:

- Official release binaries: `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`
- Supported client flows: local Claude Code and Codex traffic, plus direct OpenAI and Anthropic API traffic, that actually routes through the KeyClaw proxy and trusts the local CA
- Deferred from v0.x: Windows support and extra protocol families

Direct OpenAI and Anthropic API clients are in scope for v0.x as long as they honor `HTTP_PROXY` / `HTTPS_PROXY` and trust the KeyClaw-generated CA. KeyClaw does not rely on a wrapper SDK; it protects the traffic that actually traverses the local MITM proxy.

### Quick Start — Global Proxy

The simplest way to use KeyClaw is still the source-based flow.

One terminal:

```bash
keyclaw proxy
source ~/.keyclaw/env.sh
claude "what API keys are in my .env?"   # secrets are redacted automatically
codex "deploy using my AWS credentials"  # same protection for Codex
```

Two terminals:

```bash
# Terminal 1
keyclaw proxy

# Terminal 2
source ~/.keyclaw/env.sh
claude
```

`keyclaw proxy` detaches and keeps running in the background. It prints `source ~/.keyclaw/env.sh` on stdout, and that script exports `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE`, and related variables so CLI tools route through KeyClaw and trust the local CA.

Starting the daemon does not reconfigure the current shell automatically. A child process cannot mutate its parent shell environment, so the current shell only routes through KeyClaw after `source ~/.keyclaw/env.sh`.

> **Warning:** `eval "$(keyclaw proxy)"` still works as a shortcut if you trust the local `keyclaw` binary and the generated `~/.keyclaw/env.sh`, but it executes shell code emitted by the command. The documented path is to run `keyclaw proxy` first and then `source ~/.keyclaw/env.sh` yourself.

Manage the proxy lifecycle with:

```bash
keyclaw proxy status   # check if the proxy is running
keyclaw proxy stop     # graceful shutdown
```

On Linux with `systemd --user`, you can also keep the daemon coming back after login or reboot:

```bash
keyclaw proxy autostart enable   # install + enable user autostart service
keyclaw proxy autostart status   # show autostart service status
keyclaw proxy autostart disable  # disable + remove user autostart service
```

Autostart only keeps the daemon alive. Shells still need `source ~/.keyclaw/env.sh` to route CLI traffic through it.

If you want the proxy attached to the current terminal instead, use `keyclaw proxy start --foreground`.

> **Tip:** Add `[ -f ~/.keyclaw/env.sh ] && source ~/.keyclaw/env.sh` to your `~/.bashrc` to auto-route through KeyClaw in every new shell while the proxy is already running. By default KeyClaw does not auto-start after reboot; either start `keyclaw proxy` again after login or use `keyclaw proxy autostart enable` on Linux `systemd --user`. The sourced env script will safely no-op until the daemon is back.

### Quick Start — MITM Wrapper

Wraps a single CLI session with automatic proxy setup and teardown:

```bash
# Short form
keyclaw codex exec --model gpt-5
keyclaw claude --resume latest

# Explicit equivalent
keyclaw mitm codex exec --model gpt-5
keyclaw mitm claude --resume latest
```

The shorthand `keyclaw codex ...` and `keyclaw claude ...` forms are just aliases for `keyclaw mitm codex ...` and `keyclaw mitm claude ...`. In all of those forms, KeyClaw launches the selected CLI binary for you, so you only pass the child CLI arguments.

### Verify It Works

```bash
keyclaw doctor
```

`keyclaw doctor` is the first thing to run after changing local config or before debugging a failed `mitm` session. It checks `~/.keyclaw/config.toml`, the proxy bind address, proxy URL, CA readiness, vault path, vault key material, custom gitleaks config, allowlist status, proxy-bypass risk, and other operator-facing safety knobs.

Interpret the output like this:

- `PASS` — the check is ready for normal use
- `WARN` — KeyClaw can still run, but the config is risky or non-standard
- `FAIL` — fix this before relying on the proxy; `doctor` exits non-zero
- `hint:` — the next operator action to take for that specific check

## Troubleshooting

Start with `keyclaw doctor`. It is the fastest way to catch broken CA files, proxy bypass, invalid `~/.keyclaw/config.toml`, broken allowlist entries, custom ruleset problems, and missing vault key material before you debug the CLI itself.

### Certificate Trust Or TLS Errors

- Use either `source ~/.keyclaw/env.sh` from `keyclaw proxy` or the `keyclaw codex` / `keyclaw claude` / `keyclaw mitm ...` wrappers so the child process sees the local proxy URL and CA bundle variables.
- Confirm `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, or `NODE_EXTRA_CA_CERTS` point at `~/.keyclaw/ca.crt` if you are wiring the environment manually.
- If `doctor` reports a broken or partial CA pair, remove the bad files in `~/.keyclaw/` and rerun `keyclaw proxy` to regenerate them locally.

### Proxy Bypass Or No Intercepted Traffic

- Unset `NO_PROXY` or remove intercepted hosts such as `api.openai.com`, `chatgpt.com`, `api.anthropic.com`, or `claude.ai`.
- Leave `KEYCLAW_REQUIRE_MITM_EFFECTIVE=true` enabled so `mitm` fails loudly instead of silently running without interception.
- Set `KEYCLAW_LOG_LEVEL=debug` when you need to see per-request intercept and rewrite activity.

### Custom Ruleset, Config, Or Vault Key Problems

- If `doctor` fails the `config-file` check, fix `~/.keyclaw/config.toml` or remove it to fall back to env vars and built-in defaults.
- If `doctor` shows active allowlist entries, remember those matches are intentionally left unredacted.
- If `doctor` fails the `ruleset` check, fix `KEYCLAW_GITLEAKS_CONFIG` or unset it to go back to the bundled rules.
- If `doctor` fails the `vault-key` check, restore `~/.keyclaw/vault.key` or set `KEYCLAW_VAULT_PASSPHRASE` explicitly to the correct value.

## Configuration

KeyClaw reads `~/.keyclaw/config.toml` if it exists, then applies environment variable overrides on top. Precedence is:

```text
env vars > ~/.keyclaw/config.toml > built-in defaults
```

Missing `~/.keyclaw/config.toml` is fine; KeyClaw silently falls back to env vars and defaults. Invalid TOML is treated as a blocking configuration error, and `keyclaw doctor` reports it explicitly.

### Config File

Example `~/.keyclaw/config.toml`:

```toml
[proxy]
addr = "127.0.0.1:8877"

[logging]
level = "info"

[notice]
mode = "minimal"

[detection]
entropy_enabled = true
entropy_threshold = 3.5

[audit]
path = "~/.keyclaw/audit.log"

[hosts]
codex = ["api.openai.com", "chat.openai.com", "chatgpt.com"]
claude = ["api.anthropic.com", "claude.ai"]

[allowlist]
rule_ids = ["generic-api-key"]
patterns = ["^sk-test-"]
secret_sha256 = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
```

Supported file sections today are `proxy`, `vault`, `logging`, `notice`, `detection`, `audit`, `hosts`, and `allowlist`. Use the file for steady-state local settings, then reach for env vars when you want a one-off override.

Allowlist entries let you intentionally skip redaction for known-safe matches:

- `rule_ids`: skip every match produced by specific gitleaks rule IDs
- `patterns`: skip secrets whose matched value satisfies a regex
- `secret_sha256`: skip one exact secret value by SHA-256 digest, without storing the plaintext in config

To compute a `secret_sha256` entry locally:

```bash
printf '%s' 'your-known-safe-secret' | sha256sum
```

### Environment Variables

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
| `KEYCLAW_AUDIT_LOG` | `~/.keyclaw/audit.log` | Append-only JSONL audit log path, or `off` to disable persistent audit logging |
| `KEYCLAW_LOG_LEVEL` | `info` | Operator log verbosity for stderr runtime messages (`error`, `warn`, `info`, `debug`) |
| `KEYCLAW_NOTICE_MODE` | `verbose` | Prompt notice injection mode after redaction (`verbose`, `minimal`, `off`) |
| `KEYCLAW_UNSAFE_LOG` | `false` | Disable normal log scrubbing and log raw secret material for debugging only; unsafe and opt-in |
| `KEYCLAW_FAIL_CLOSED` | `true` | Fail closed on errors |
| `KEYCLAW_REQUIRE_MITM_EFFECTIVE` | `true` | Fail if proxy bypass is detected |

### Setting Variables

Environment variables override the config file when both are set.

Inline for one command:

```bash
KEYCLAW_LOG_LEVEL=debug KEYCLAW_NOTICE_MODE=minimal keyclaw claude --resume latest
KEYCLAW_GITLEAKS_CONFIG="$PWD/gitleaks.toml" keyclaw doctor
```

Persistent for the current shell session:

```bash
export KEYCLAW_LOG_LEVEL=debug
export KEYCLAW_NOTICE_MODE=minimal
keyclaw codex exec --model gpt-5
```

Persistent across new shells:

```bash
# ~/.bashrc or ~/.zshrc
export KEYCLAW_LOG_LEVEL=debug
export KEYCLAW_NOTICE_MODE=minimal
export KEYCLAW_GITLEAKS_CONFIG="$HOME/.config/keyclaw/gitleaks.toml"
```

If you use `keyclaw proxy` as a detached daemon, or enable `keyclaw proxy autostart`, daemon-side settings are read when that proxy process starts. After changing `~/.keyclaw/config.toml` or variables such as `KEYCLAW_PROXY_ADDR`, `KEYCLAW_LOG_LEVEL`, `KEYCLAW_GITLEAKS_CONFIG`, `KEYCLAW_NOTICE_MODE`, or `KEYCLAW_REQUIRE_MITM_EFFECTIVE`, restart the proxy so the running daemon picks them up.

KeyClaw does not use or require `KEYCLAW_GITLEAKS_BIN`. Secret detection uses the bundled gitleaks rules compiled natively into the binary; set `KEYCLAW_GITLEAKS_CONFIG` only when you want to override those rules with your own TOML file.

By default, KeyClaw creates a machine-local vault key next to the encrypted vault and reuses it on later runs. Set `KEYCLAW_VAULT_PASSPHRASE` only when you need to override that key material explicitly. Existing vaults written with the removed built-in default are migrated to a generated local key on the next successful write. If an existing vault cannot be decrypted or its key material is missing, KeyClaw fails closed and tells you how to recover.

`KEYCLAW_NOTICE_MODE=verbose` keeps the current full acknowledgment guidance, `minimal` injects a shorter notice, and `off` suppresses notice injection entirely while still redacting and reinjecting secrets normally.

The only intentional exception to scrubbed runtime logging is `KEYCLAW_UNSAFE_LOG=true`. When enabled, KeyClaw may write raw request fragments to stderr or `~/.keyclaw/mitm.log` to help debug interception problems. Leave it unset for normal use.

## Audit Log

By default, KeyClaw appends one JSON line per redacted secret to `~/.keyclaw/audit.log`. Each entry includes the UTC timestamp, `rule_id`, placeholder, request host, and action, but never the raw secret value itself.

Set `KEYCLAW_AUDIT_LOG=off` or `[audit] path = "off"` to disable the persistent audit log. Set `KEYCLAW_AUDIT_LOG=/path/to/audit.log` or `[audit] path = "/path/to/audit.log"` to move it somewhere else.

KeyClaw does not rotate the audit log by itself; it always appends. For size management, point it at a path managed by `logrotate`, `newsyslog`, or your platform’s equivalent rotation tool.

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
├── config.rs          # Env + TOML configuration
├── gitleaks_rules.rs  # Bundled gitleaks rule loading + native regex compilation
├── pipeline.rs        # Request rewrite pipeline
├── placeholder.rs     # Placeholder parsing, generation, and resolution
├── redaction.rs       # JSON walker + notice injection
├── vault.rs           # AES-GCM encrypted secret storage
├── proxy.rs           # Proxy server entrypoint + handler wiring
├── proxy/
│   ├── common.rs      # Shared host checks, response helpers, and logging
│   ├── http.rs        # HTTP request/response interception
│   ├── streaming.rs   # SSE frame resolution and buffering
│   └── websocket.rs   # WebSocket message redaction and resolution
├── launcher.rs        # CLI surface and subcommand dispatch
├── launcher/
│   ├── bootstrap.rs   # Processor/bootstrap setup and launched-tool wiring
│   └── doctor.rs      # Operator health checks
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
