<div align="center">

```
 ╦╔═╔═╗╦ ╦╔═╗╦  ╔═╗╦ ╦
 ╠╩╗║╣ ╚╦╝║  ║  ╠═╣║║║
 ╩ ╩╚═╝ ╩ ╚═╝╩═╝╩ ╩╚╩╝
```

**Your secrets never leave your machine.**

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

The `env.sh` script auto-disables when the proxy isn't running — safe to add to your `.bashrc`.

### Quick Start — MITM Wrapper

Wraps a single CLI session with automatic proxy setup and teardown:

```bash
# Wrap a Codex session
./target/release/keyclaw mitm codex -- codex

# Wrap a Claude session
./target/release/keyclaw mitm claude -- claude
```

### Verify It Works

```bash
./target/release/keyclaw doctor
```

`keyclaw doctor` is the first thing to run after changing local config or before debugging a failed `mitm` session. It checks the proxy bind address, proxy URL, CA readiness, vault path, custom gitleaks config, proxy-bypass risk, and other operator-facing safety knobs.

Interpret the output like this:

- `PASS` — the check is ready for normal use
- `WARN` — KeyClaw can still run, but the config is risky or non-standard
- `FAIL` — fix this before relying on the proxy; `doctor` exits non-zero
- `hint:` — the next operator action to take for that specific check

## Configuration

KeyClaw is configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYCLAW_PROXY_ADDR` | `127.0.0.1:8877` | Proxy listen address |
| `KEYCLAW_PROXY_URL` | `http://127.0.0.1:8877` | Proxy URL exported to child processes |
| `KEYCLAW_CA_CERT` | (auto-generated `~/.keyclaw/ca.crt`) | Override CA cert path passed to clients |
| `KEYCLAW_VAULT_PATH` | `~/.keyclaw/vault.enc` | Encrypted vault location |
| `KEYCLAW_VAULT_PASSPHRASE` | (built-in default) | Vault encryption passphrase |
| `KEYCLAW_CODEX_HOSTS` | `api.openai.com,chat.openai.com,chatgpt.com` | Codex/OpenAI hosts to intercept |
| `KEYCLAW_CLAUDE_HOSTS` | `api.anthropic.com,claude.ai` | Claude/Anthropic hosts to intercept |
| `KEYCLAW_MAX_BODY_BYTES` | `2097152` (2MB) | Maximum request body size |
| `KEYCLAW_DETECTOR_TIMEOUT` | `4s` | Timeout for request-body secret detection and streamed body reads (`250ms`, `4s`, `1m` formats supported) |
| `KEYCLAW_GITLEAKS_CONFIG` | (bundled rules) | Path to custom gitleaks.toml rule file |
| `KEYCLAW_UNSAFE_LOG` | `false` | Log actual secrets for debugging only; unsafe and opt-in |
| `KEYCLAW_FAIL_CLOSED` | `true` | Fail closed on errors |
| `KEYCLAW_REQUIRE_MITM_EFFECTIVE` | `true` | Fail if proxy bypass is detected |

KeyClaw does not use or require `KEYCLAW_GITLEAKS_BIN`. Secret detection uses the bundled gitleaks rules compiled natively into the binary; set `KEYCLAW_GITLEAKS_CONFIG` only when you want to override those rules with your own TOML file.

## Error Codes

KeyClaw uses deterministic error codes for programmatic handling:

| Code | Meaning |
|------|---------|
| `mitm_not_effective` | Proxy bypass detected (e.g., `NO_PROXY=*`) |
| `body_too_large` | Request body exceeds `KEYCLAW_MAX_BODY_BYTES` |
| `invalid_json` | Failed to parse/rewrite request JSON |
| `strict_resolve_failed` | Placeholder resolution failed in strict mode |

## Security Model

### What KeyClaw Protects Against

- Secrets in your codebase being sent to AI APIs
- API keys, tokens, and credentials leaking through CLI tool traffic
- Accidental exposure of `.env` files, config files, and hardcoded credentials

### What KeyClaw Does NOT Protect Against

- A compromised local machine (KeyClaw runs locally — if your machine is compromised, all bets are off)
- Secrets transmitted outside of intercepted hosts
- Side-channel leakage (e.g., secret length is preserved in placeholders)

### Trust Boundary

The trust boundary is your machine. KeyClaw's CA certificate is generated locally and never leaves your machine. The encrypted vault is local. All secret operations happen in-process.

## Project Structure

```
src/
├── main.rs            # Entry point
├── lib.rs             # Module declarations
├── certgen.rs         # Runtime CA certificate generation
├── config.rs          # Environment-based configuration
├── gitleaks_rules.rs  # Gitleaks TOML parser + native regex compilation
├── proxy.rs           # MITM proxy (HTTP, SSE, WebSocket)
├── pipeline.rs        # Request rewrite pipeline
├── placeholder.rs     # Secret detection and placeholder replacement
├── redaction.rs       # JSON walker + notice injection
├── vault.rs           # AES-GCM encrypted secret storage
├── launcher.rs        # CLI launcher (mitm/proxy/doctor)
├── logscrub.rs        # Log sanitization
└── errors.rs          # Error types and codes
gitleaks.toml          # Bundled detection rules (220+)
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
