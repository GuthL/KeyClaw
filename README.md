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
│             │◄────┤  2. Detect secrets (regex/entropy) │◄────┤ API         │
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

### Detection Pipeline

KeyClaw uses a multi-layered detection chain:

| Layer | Method | What It Catches |
|-------|--------|-----------------|
| **Gitleaks** | Subprocess | 800+ secret patterns from the Gitleaks ruleset |
| **Regex** | Aho-Corasick | OpenAI keys (`sk-proj-*`), AWS keys (`AKIA*`), GitHub tokens (`ghp_*`, `ghs_*`) |
| **Generic** | Pattern match | `api_key=...`, `secret_key=...`, `access_token=...` |
| **Entropy** | Shannon entropy | High-entropy strings that look like credentials |

### What Makes It Different

- **Transparent** — Works as a drop-in proxy. No code changes, no wrapper SDKs.
- **Bidirectional** — Redacts secrets in requests, reinjects them in responses (including SSE streams and WebSocket).
- **Machine-agnostic** — Generates its own CA certificate on first run. Clone, build, run.
- **Fail-closed** — If detection fails, requests are blocked by default. No silent failures.
- **Vault-backed** — Secrets are stored in an AES-GCM encrypted vault with atomic writes. Placeholders are deterministic per-secret.

## Getting Started

### Prerequisites

- Rust 1.75+ and Cargo
- (Optional) [Gitleaks](https://github.com/gitleaks/gitleaks) for extended detection

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

## Configuration

KeyClaw is configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYCLAW_LISTEN` | `127.0.0.1:8877` | Proxy listen address |
| `KEYCLAW_VAULT_PATH` | `~/.keyclaw/vault.enc` | Encrypted vault location |
| `KEYCLAW_VAULT_PASSPHRASE` | (built-in default) | Vault encryption passphrase |
| `KEYCLAW_POLICY_MODE` | `block` | `block` or `warn` — whether to block or warn on detected secrets |
| `KEYCLAW_ALLOWED_HOSTS` | `api.anthropic.com,api.openai.com,...` | Hosts to intercept |
| `KEYCLAW_MAX_BODY_BYTES` | `2097152` (2MB) | Maximum request body size |
| `KEYCLAW_UNSAFE_LOG` | `false` | Log actual secrets (for debugging only!) |
| `KEYCLAW_REQUIRE_MITM` | `true` | Fail if proxy bypass is detected |

## Error Codes

KeyClaw uses deterministic error codes for programmatic handling:

| Code | Meaning |
|------|---------|
| `blocked_by_leak_policy` | Secret detected in request, blocked by policy |
| `gitleaks_unavailable` | Gitleaks binary not found (falls back to embedded detector) |
| `mitm_not_effective` | Proxy bypass detected (e.g., `NO_PROXY=*`) |

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
├── main.rs          # Entry point
├── lib.rs           # Module declarations
├── certgen.rs       # Runtime CA certificate generation
├── config.rs        # Environment-based configuration
├── proxy.rs         # MITM proxy (HTTP, SSE, WebSocket)
├── pipeline.rs      # Request rewrite + policy evaluation pipeline
├── placeholder.rs   # Secret detection and placeholder replacement
├── redaction.rs      # JSON walker + notice injection
├── vault.rs         # AES-GCM encrypted secret storage
├── policy.rs        # Policy executor (block/warn/allow)
├── launcher.rs      # CLI launcher (mitm/proxy/doctor)
├── logscrub.rs      # Log sanitization
├── errors.rs        # Error types and codes
└── detector/
    ├── mod.rs        # Detector trait
    ├── gitleaks.rs   # Gitleaks subprocess detector
    └── embedded.rs   # Built-in regex/entropy detector
```

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
