<p align="center">
  <img src="docs/assets/keyclaw-wordmark.svg" alt="KeyClaw wordmark" width="720">
</p>

<h3 align="center">A local MITM proxy that strips secrets out of LLM traffic before they leave your machine.</h3>

<p align="center">
  Keep API keys, cloud credentials, and private tokens on-device while Claude Code, Codex, and compatible proxy-aware API clients keep working.
</p>

<p align="center">
  <a href="https://github.com/GuthL/KeyClaw/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/GuthL/KeyClaw/actions/workflows/ci.yml/badge.svg?branch=master"></a>
  <a href="https://crates.io/crates/keyclaw"><img alt="Crate version" src="https://img.shields.io/crates/v/keyclaw?logo=rust"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-0f172a"></a>
  <a href="https://www.rust-lang.org/"><img alt="Rust version" src="https://img.shields.io/badge/rust-1.85%2B-93450a?logo=rust"></a>
</p>

<p align="center">
  <a href="#quickstart-under-60-seconds">Quickstart</a>
  ·
  <a href="#how-it-works">How It Works</a>
  ·
  <a href="#why-keyclaw">Why KeyClaw?</a>
  ·
  <a href="docs/README.md">Docs</a>
  ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

KeyClaw sits between your AI tool and the upstream API, detects sensitive values in outbound payloads, swaps them for format-preserving placeholders like `{{KEYCLAW_AAAA_0000~o<id>}}`, stores the mapping in a session-scoped local resolver, and reinjects the real values into responses on the way back. The core runtime classes are `opaque_token` plus typed structured detectors, so the model never sees the raw value but your workflow still behaves as if it did.

## Why It Matters

- AI coding tools are excellent at reading exactly the files you wish they would ignore.
- Secret scanners catch leaks after the fact; KeyClaw protects the live request before it crosses the network.
- You do not need wrapper SDKs, prompt discipline, or a separate hosted service to keep credentials out of model prompts.

## Architecture

```
+-------------+   request   +-----------------+  sanitized   +----------------------+
|  Claude Code | ---------->|    KeyClaw      |  request     | Supported provider   |
|  Codex       |            |   local proxy   |------------>| APIs / custom hosts  |
|  Client      |<---------- |                 |<----------- | via --include        |
+-------------+   response  +---------+-------+  response   +----------------------+
                  (resolved)          |
                             +--------v---------+
                             | Session-scoped   |
                             | local store      |
                             +------------------+

    1. Detect opaque tokens and typed structured data in outbound request body
    2. Replace with typed placeholders, store mapping in the session-scoped store
    3. Forward sanitized request upstream
    4. Resolve placeholders in response (HTTP, SSE, WebSocket)
```

## Used With

<p>
  <img alt="Claude Code" src="https://img.shields.io/badge/Claude%20Code-first--class-111827">
  <img alt="ChatGPT" src="https://img.shields.io/badge/ChatGPT-proxy%20mode-111827">
  <img alt="OpenAI API" src="https://img.shields.io/badge/OpenAI%20API-supported-111827">
  <img alt="Anthropic API" src="https://img.shields.io/badge/Anthropic%20API-supported-111827">
  <img alt="Google API" src="https://img.shields.io/badge/Google%20API-supported-111827">
  <img alt="Provider APIs" src="https://img.shields.io/badge/Together%20%7C%20Groq%20%7C%20Mistral%20%7C%20Cohere%20%7C%20DeepSeek-supported-111827">
</p>

KeyClaw ships first-class wrappers for Claude Code and Codex. In generic proxy mode, the default interception list also covers Google, Together, Groq, Mistral, Cohere, and DeepSeek API domains.

| Tool | Path | Notes |
|------|------|-------|
| Claude Code | `keyclaw claude ...` wrapper or `source ~/.keyclaw/env.sh` | First-class CLI path |
| Codex | `keyclaw codex ...` wrapper or `source ~/.keyclaw/env.sh` | First-class CLI path |
| macOS desktop apps | System proxy + trusted KeyClaw CA | Finder-launched apps do not inherit shell proxy env by default; see [docs/macos-gui-apps.md](docs/macos-gui-apps.md) |
| ChatGPT / OpenAI web traffic | Local proxy + trusted CA | In scope at the host layer for `chatgpt.com` / `chat.openai.com` when traffic truly traverses the proxy |
| Direct API clients | `HTTP_PROXY` / `HTTPS_PROXY` + KeyClaw CA | Default hosts include OpenAI, Anthropic, Google, Together, Groq, Mistral, Cohere, and DeepSeek |

Cursor, aider, Continue, and similar proxy-aware tools are in scope when they actually route traffic through KeyClaw and trust the local CA, but they remain generic proxy integrations rather than first-class wrappers.

## Quickstart Under 60 Seconds

KeyClaw is published on crates.io and packaged for Homebrew via `GuthL/tap`.

### Install With Cargo

The default runtime uses the built-in sensitive-data engine only: typed structured detectors plus opaque-token entropy detection.

```bash
cargo install keyclaw
keyclaw init
keyclaw proxy
source ~/.keyclaw/env.sh
```

### Install With Homebrew

```bash
brew tap GuthL/tap
brew install keyclaw
keyclaw init
keyclaw proxy
source ~/.keyclaw/env.sh
```

If you want the latest unreleased KeyClaw commit instead of the published crate, use `cargo install --git https://github.com/GuthL/KeyClaw keyclaw`.

That installs the CLI, generates the local CA, initializes the session-scoped runtime, starts the detached proxy, and wires the current shell to trust and use it.

### Claude Code

```bash
keyclaw claude --resume latest
```

Or use the proxy globally:

```bash
claude
```

### Generic proxy-aware clients

```bash
source ~/.keyclaw/env.sh
your-client-here
```

For tools outside the built-in `claude` / `codex` wrappers:

1. Run `keyclaw init` once so `~/.keyclaw/ca.crt` exists.
2. Trust `~/.keyclaw/ca.crt` in your OS keychain or certificate store.
3. Route the client through `http://127.0.0.1:8877`, either via shell env vars or app/OS proxy settings.
4. Verify with `keyclaw doctor` and a real request that traffic is actually being intercepted.

GUI desktop apps launched outside your shell do not necessarily inherit `source ~/.keyclaw/env.sh`. On macOS, the reliable path for `Claude.app`, `Codex.app`, `ChatGPT.app`, and similar desktop apps is to trust `~/.keyclaw/ca.crt` in the login keychain and use the macOS system proxy instead of assuming shell env injection will reach them. See [docs/macos-gui-apps.md](docs/macos-gui-apps.md) for the current supported flow and rollback steps.

Built-in generic-proxy hosts are:

- `api.openai.com`, `chat.openai.com`, `chatgpt.com`
- `api.anthropic.com`, `claude.ai`
- `generativelanguage.googleapis.com`
- `api.together.xyz`, `api.groq.com`, `api.mistral.ai`, `api.cohere.ai`, `api.deepseek.com`

To intercept an extra host or custom gateway, add repeated `--include` globs:

```bash
keyclaw proxy --include "*my-custom-api.com*"
source ~/.keyclaw/env.sh
```

Or persist the same idea with an environment variable:

```bash
export KEYCLAW_INCLUDE_HOSTS="*my-custom-api.com*"
keyclaw proxy
```

### One terminal:

```bash
keyclaw proxy
source ~/.keyclaw/env.sh
claude "scan this repo for AWS credentials"
```

### Two terminals:

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

Starting `keyclaw proxy` again on the same listen address replaces the previously tracked detached daemon. If you start another proxy on a different address, the existing proxy stays up and the newest detached daemon becomes the instance that `keyclaw proxy status` and `keyclaw proxy stop` track.

On Linux with `systemd --user`, you can also keep the daemon coming back after login or reboot:

```bash
keyclaw proxy autostart enable
keyclaw proxy autostart status
keyclaw proxy autostart disable
```

Autostart only keeps the daemon alive. Shells still need `source ~/.keyclaw/env.sh` to route CLI traffic through it.

If you want the proxy attached to the current terminal instead, use `keyclaw proxy start --foreground`.

> **Tip:** Add `[ -f ~/.keyclaw/env.sh ] && source ~/.keyclaw/env.sh` to your `~/.bashrc` or `~/.zshrc` to auto-route through KeyClaw in new shells while the proxy is already running. The detached proxy does not auto-start after reboot unless you enable `keyclaw proxy autostart enable`, so after a reboot you may need to start it again.

### macOS desktop apps

The CLI wrappers (`keyclaw claude ...`, `keyclaw codex ...`) are the preferred path on macOS because they inject proxy settings and CA trust into the child process directly.

Finder-launched apps are different: they are started by macOS, not by your shell, so they usually bypass `~/.keyclaw/env.sh` unless you configure the OS proxy itself. The current supported desktop-app flow is:

1. `keyclaw init`
2. start a healthy proxy and confirm `keyclaw proxy status`
3. trust `~/.keyclaw/ca.crt` in the macOS login keychain for SSL
4. enable the macOS HTTP and HTTPS system proxy on the active network service
5. fully quit and relaunch the desktop app

If the system proxy is enabled while no healthy KeyClaw listener is actually serving the advertised address, desktop apps and browsers can fail with proxy-connection errors. `keyclaw doctor` now warns on macOS when Finder-launched apps are likely bypassing the proxy or when the KeyClaw CA is not trusted for SSL in the login keychain. Use [docs/macos-gui-apps.md](docs/macos-gui-apps.md) for the exact commands, verification steps, and rollback path.

## How It Works

### Before: a real-looking request with a leaked AWS key

```json
{
  "model": "claude-sonnet-4",
  "messages": [
    {
      "role": "user",
      "content": "Deploy the staging stack with AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  ]
}
```

### After: the same request after KeyClaw

```json
{
  "model": "claude-sonnet-4",
  "messages": [
    {
      "role": "developer",
      "content": "KeyClaw notice: 2 sensitive values were redacted before this request left the machine."
    },
    {
      "role": "user",
      "content": "Deploy the staging stack with AWS_ACCESS_KEY_ID={{KEYCLAW_AAA_AAAA_AA~o77dc0005c514277d}} and AWS_SECRET_ACCESS_KEY={{KEYCLAW_AAA_AAAAAA_AA~o8b4f0f2d14a8b2c1}}"
    }
  ],
  "x-keyclaw-contract": "placeholder:v2"
}
```

When the model echoes or manipulates those placeholders in a response, KeyClaw resolves them back to the real values before the local client sees the final payload.

## Why KeyClaw?

| Approach | Great at | Where KeyClaw is different |
|----------|----------|----------------------------|
| `llm-interceptor` | Inspecting, analyzing, and logging AI traffic | KeyClaw is designed to actively rewrite live requests, preserve workflows with placeholder reinjection, and fail closed when protection breaks |
| `gitleaks` / `trufflehog` | Scanning repos, history, images, or leaked material for secrets | KeyClaw operates inline on live traffic instead of only auditing files or previously leaked data |
| Manual prompt hygiene | Reducing obvious copy/paste mistakes | KeyClaw is automatic and still catches secrets hidden in payloads, configs, or generated request bodies |

If you want to inspect LLM traffic, `llm-interceptor` is a useful neighbor. If you want to stop raw credentials from reaching the upstream API in the first place, KeyClaw is the tighter fit.

## Detection Stack

KeyClaw now uses one in-process sensitive-data engine:

1. Structured typed detectors in `src/sensitive.rs` for `password`, `email`, `phone`, `national_id`, `passport`, `payment_card`, and `cvv`
2. Opaque-token detection for high-entropy credential-like spans
3. Allowlist filtering
4. An optional local classifier only for ambiguous low-confidence candidates

The runtime does not require any external detector binary. Placeholder mappings are kept in a session-scoped store, so the same value is stable within one daemon session but not across restarts.

## Verify It Works

```bash
keyclaw doctor
```

`keyclaw doctor` is the fastest way to catch broken CA files, proxy bypass, invalid `~/.keyclaw/config.toml`, broken allowlist entries, and misconfigured detector knobs before you debug the client itself.

Interpret the output like this:

- `PASS` means the check is ready for normal use
- `WARN` means KeyClaw can still run, but the config is risky or non-standard
- `FAIL` means fix this before relying on the proxy; `doctor` exits non-zero
- `hint:` points at the next operator action for that specific check

## Configuration

KeyClaw reads `~/.keyclaw/config.toml` if it exists, then applies environment variable overrides on top. Precedence is:

```text
env vars > ~/.keyclaw/config.toml > built-in defaults
```

Missing `~/.keyclaw/config.toml` is fine; KeyClaw silently falls back to env vars and defaults. Invalid TOML is treated as a blocking configuration error, and `keyclaw doctor` reports it explicitly.

For the full configuration reference, see [docs/configuration.md](docs/configuration.md).

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
dry_run = false
entropy_enabled = true
entropy_threshold = 3.5

[audit]
path = "~/.keyclaw/audit.log"

[hosts]
codex = ["api.openai.com", "chat.openai.com", "chatgpt.com"]
claude = ["api.anthropic.com", "claude.ai"]
providers = [
  "generativelanguage.googleapis.com",
  "api.together.xyz",
  "api.groq.com",
  "api.mistral.ai",
  "api.cohere.ai",
  "api.deepseek.com",
]
include = ["*my-custom-api.com*"]

[allowlist]
rule_ids = ["opaque.high_entropy"]
patterns = ["^sk-test-"]
secret_sha256 = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]

[[hooks]]
event = "secret_detected"
rule_ids = ["opaque.high_entropy", "typed.email"]
action = "exec"
command = "notify-slack --channel security"

[[hooks]]
event = "request_redacted"
rule_ids = ["*"]
action = "log"
path = "~/.keyclaw/hooks.log"

[[hooks]]
event = "secret_detected"
rule_ids = ["opaque.high_entropy"]
action = "block"
message = "production key detected"
```

Supported file sections today are `proxy`, `logging`, `notice`, `detection`, `audit`, `sensitive`, `classifier`, `hosts`, `allowlist`, and `hooks`. Use the file for steady-state local settings, then reach for env vars when you want a one-off override.

Allowlist entries let you intentionally skip redaction for known-safe matches:

- `rule_ids`: skip every match produced by a specific detector ID such as `opaque.high_entropy`
- `patterns`: skip secrets whose matched value satisfies a regex
- `secret_sha256`: skip one exact secret value by SHA-256 digest, without storing the plaintext in config

To compute a `secret_sha256` entry locally:

```bash
printf '%s' 'your-known-safe-secret' | sha256sum
```

Disable persistent audit logging with:

```toml
[audit]
path = "off"
```

Hook entries let you trigger local side effects from request-side events without exposing the raw sensitive value:

- `event = "secret_detected"` fires when a sensitive value is found during request rewriting
- `event = "request_redacted"` fires after a request has been rewritten, just before it is forwarded upstream
- `action = "exec"` runs a local command with sanitized metadata in env vars and a JSON payload on `stdin`
- `action = "log"` appends a JSON line to the configured file
- `action = "block"` rejects matching `secret_detected` requests with `hook_blocked`

Hook payloads include only `event`, `rule_id`, `kind`, `policy`, `placeholder`, and `request_host`. Raw values are never passed to hook commands or hook log files.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYCLAW_PROXY_ADDR` | `127.0.0.1:8877` | Proxy listen address |
| `KEYCLAW_PROXY_URL` | `http://127.0.0.1:8877` | Proxy URL exported to child processes |
| `KEYCLAW_CA_CERT` | `~/.keyclaw/ca.crt` | Override CA cert path passed to clients |
| `KEYCLAW_CODEX_HOSTS` | `api.openai.com,chat.openai.com,chatgpt.com` | Codex/OpenAI hosts to intercept |
| `KEYCLAW_CLAUDE_HOSTS` | `api.anthropic.com,claude.ai` | Claude/Anthropic hosts to intercept |
| `KEYCLAW_PROVIDER_HOSTS` | `generativelanguage.googleapis.com,api.together.xyz,api.groq.com,api.mistral.ai,api.cohere.ai,api.deepseek.com` | Additional provider API hosts intercepted by default |
| `KEYCLAW_INCLUDE_HOSTS` | unset | Extra exact hosts or glob patterns to intercept |
| `KEYCLAW_MAX_BODY_BYTES` | `2097152` | Maximum request body size |
| `KEYCLAW_DETECTOR_TIMEOUT` | `20s` | Timeout for request-body collection and rewrite processing; raise it for very large CLI payloads if `request_timeout` warnings persist |
| `KEYCLAW_AUDIT_LOG` | `~/.keyclaw/audit.log` | Append-only JSONL audit log path, or `off` to disable |
| `KEYCLAW_LOG_LEVEL` | `info` | Runtime stderr verbosity: `error`, `warn`, `info`, `debug` |
| `KEYCLAW_NOTICE_MODE` | `verbose` | Redaction notice mode: `verbose`, `minimal`, `off` |
| `KEYCLAW_DRY_RUN` | `false` | Scan and log what would be redacted without modifying traffic |
| `KEYCLAW_UNSAFE_LOG` | `false` | Disable normal log scrubbing for debugging only |
| `KEYCLAW_FAIL_CLOSED` | `true` | Block requests on rewrite or detection failures |
| `KEYCLAW_REQUIRE_MITM_EFFECTIVE` | `true` | Fail if proxy bypass is detected |
| `KEYCLAW_ENTROPY_ENABLED` | `true` | Enable opaque-token detection |
| `KEYCLAW_ENTROPY_THRESHOLD` | `3.5` | Minimum entropy score for opaque-token matches |
| `KEYCLAW_ENTROPY_MIN_LEN` | `20` | Minimum token length for opaque-token matches |
| `KEYCLAW_SENSITIVE_SESSION_TTL` | `1h` | Session-store TTL for placeholder mappings |
| `KEYCLAW_SENSITIVE_EMAILS_ENABLED` | `false` | Enable email detection |
| `KEYCLAW_SENSITIVE_PASSWORDS_ENABLED` | `false` | Enable password detection |
| `KEYCLAW_SENSITIVE_PHONES_ENABLED` | `false` | Enable phone detection |
| `KEYCLAW_SENSITIVE_NATIONAL_IDS_ENABLED` | `false` | Enable national-ID detection |
| `KEYCLAW_SENSITIVE_PASSPORTS_ENABLED` | `false` | Enable passport detection |
| `KEYCLAW_SENSITIVE_PAYMENT_CARDS_ENABLED` | `false` | Enable payment-card detection |
| `KEYCLAW_SENSITIVE_CVV_ENABLED` | `false` | Enable CVV detection |
| `KEYCLAW_LOCAL_CLASSIFIER_ENABLED` | `false` | Enable the optional local classifier |
| `KEYCLAW_LOCAL_CLASSIFIER_ENDPOINT` | unset | OpenAI-compatible local classifier endpoint |
| `KEYCLAW_LOCAL_CLASSIFIER_MODEL` | unset | Local classifier model name |
| `KEYCLAW_LOCAL_CLASSIFIER_TIMEOUT` | `3s` | Local classifier HTTP timeout |

Large top-level `prompt` or `instructions` strings that look like machine-generated hidden context are downgraded to input-only rewriting once they get big enough and do not contain obvious credential hints. Normal `messages` / `input` content is still inspected, and large prompt bodies that clearly contain secrets are still rewritten.

### Setting Variables

Environment variables override the config file when both are set.

Inline for one command:

```bash
KEYCLAW_LOG_LEVEL=debug KEYCLAW_NOTICE_MODE=minimal keyclaw claude --resume latest
KEYCLAW_SENSITIVE_EMAILS_ENABLED=true KEYCLAW_SENSITIVE_PASSWORDS_ENABLED=true keyclaw doctor
```

Persistent for the current shell session:

```bash
export KEYCLAW_LOG_LEVEL=debug
export KEYCLAW_NOTICE_MODE=minimal
export KEYCLAW_INCLUDE_HOSTS="*my-custom-api.com*"
keyclaw codex exec --model gpt-5
```

Persistent across new shells:

```bash
# ~/.bashrc or ~/.zshrc
export KEYCLAW_LOG_LEVEL=debug
export KEYCLAW_NOTICE_MODE=minimal
export KEYCLAW_SENSITIVE_PAYMENT_CARDS_ENABLED=true
export KEYCLAW_INCLUDE_HOSTS="*my-custom-api.com*"
```

If you use `keyclaw proxy` as a detached daemon, or enable `keyclaw proxy autostart`, daemon-side settings are read when that proxy process starts. After changing `~/.keyclaw/config.toml` or variables such as `KEYCLAW_PROXY_ADDR`, `KEYCLAW_LOG_LEVEL`, `KEYCLAW_NOTICE_MODE`, `KEYCLAW_REQUIRE_MITM_EFFECTIVE`, `KEYCLAW_PROVIDER_HOSTS`, `KEYCLAW_INCLUDE_HOSTS`, or any `KEYCLAW_SENSITIVE_*` detector toggle, restart the proxy so the running daemon picks them up.

`KEYCLAW_NOTICE_MODE=verbose` keeps the current full acknowledgment guidance, `minimal` injects a shorter notice, and `off` suppresses notice injection entirely while still redacting and reinjecting secrets normally.

Use dry-run when you want to tune detection without changing live traffic: set `[detection] dry_run = true`, export `KEYCLAW_DRY_RUN=true`, or pass `--dry-run` to `keyclaw rewrite-json`, `keyclaw mitm ...`, `keyclaw codex ...`, `keyclaw claude ...`, or `keyclaw proxy start`.

Use repeated `--include` flags on `keyclaw proxy`, `keyclaw proxy start`, `keyclaw mitm`, `keyclaw codex`, or `keyclaw claude` when you need to intercept a custom API hostname or gateway without replacing the built-in provider list.

The only intentional exception to scrubbed runtime logging is `KEYCLAW_UNSAFE_LOG=true`. When enabled, KeyClaw may write raw request fragments to stderr or `~/.keyclaw/mitm.log` to help debug interception problems. Leave it unset for normal use.

## Audit Log

By default, KeyClaw appends one JSON line per redacted secret to `~/.keyclaw/audit.log`. Each entry includes the UTC timestamp, `rule_id`, placeholder, request host, and action, but never the raw secret value itself.

Set `KEYCLAW_AUDIT_LOG=off` or `[audit] path = "off"` to disable the persistent audit log. Set `KEYCLAW_AUDIT_LOG=/path/to/audit.log` or `[audit] path = "/path/to/audit.log"` to move it somewhere else.

KeyClaw does not rotate the audit log by itself; it always appends. For size management, point it at a path managed by `logrotate`, `newsyslog`, or your platform's equivalent rotation tool.

## Logging

Operator-facing runtime messages use leveled stderr prefixes:

- `keyclaw info:` startup, shutdown, CA/ruleset initialization, and lifecycle summaries
- `keyclaw debug:` per-request proxy activity such as interception, rewrite, and placeholder resolution
- `keyclaw warn:` risky but non-fatal conditions such as unsafe logging or bypass risk
- `keyclaw error:` fatal CLI errors before exit

Set `KEYCLAW_LOG_LEVEL=error`, `warn`, `info`, or `debug` to reduce or expand stderr verbosity. The default is `info`, which stays lifecycle-focused and avoids emitting a line for every proxied request. Use `debug` when troubleshooting live traffic. The `doctor` subcommand is intentionally separate: it writes its `doctor: PASS|WARN|FAIL ...` report to stdout so it can be piped or parsed cleanly.

## Error Codes

KeyClaw uses deterministic error codes for programmatic handling:

| Code | Meaning |
|------|---------|
| `mitm_not_effective` | Proxy bypass detected |
| `body_too_large` | Request body exceeds `KEYCLAW_MAX_BODY_BYTES` |
| `invalid_json` | Failed to parse or rewrite request JSON |
| `request_timeout` | Request body read or rewrite timed out before inspection completed |
| `strict_resolve_failed` | Placeholder resolution failed in strict mode |
| `hook_blocked` | A configured hook rejected the request |

## Security Model

For the full threat model, see [docs/threat-model.md](docs/threat-model.md).

### What KeyClaw Protects Against

- Secrets in your codebase being sent to AI APIs
- API keys, tokens, and credentials leaking through CLI or IDE traffic
- Accidental exposure of `.env` files, config files, and hardcoded credentials

### Non-Goals And Limits

- A compromised local machine
- Traffic that never uses the KeyClaw proxy or targets hosts outside the configured intercept lists
- Perfect secret detection across every provider, credential format, or prompt phrasing
- Side-channel leakage such as exact secret-length preservation

### Trust Boundary

The trust boundary is your machine. KeyClaw only protects traffic that a supported client actually routes through the local proxy. The CA certificate is generated locally and never leaves your machine. Sensitive detection, placeholder generation, session-scoped storage, and reinjection all happen in-process.

## Project Structure

```text
src/
├── main.rs            # Entry point
├── lib.rs             # Module declarations
├── allowlist.rs       # Operator-controlled allowlist logic
├── audit.rs           # Persistent JSONL audit log writes
├── certgen.rs         # Runtime CA certificate generation
├── config.rs          # Env + TOML configuration
├── entropy.rs         # High-entropy token detection
├── hooks.rs           # Configured request-side hook execution
├── sensitive.rs       # Typed detection engine + session-scoped store
├── pipeline.rs        # Request rewrite pipeline
├── placeholder.rs     # Placeholder parsing, generation, and resolution
├── redaction.rs       # JSON walker + notice injection
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
```

## Additional Docs

| Doc | Purpose |
|-----|---------|
| [docs/README.md](docs/README.md) | Entry point for deeper documentation |
| [docs/architecture.md](docs/architecture.md) | Request/response flow, module map, and design decisions |
| [docs/configuration.md](docs/configuration.md) | Full config file and environment variable reference |
| [docs/secret-patterns.md](docs/secret-patterns.md) | Supported secret categories and custom-rule guidance |
| [docs/threat-model.md](docs/threat-model.md) | Threat model, trust boundary, and non-goals |
| [CLAUDE.md](CLAUDE.md) | Agent guide for Claude Code |
| [AGENTS.md](AGENTS.md) | Agent guide for Codex |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local development, validation, release, and documentation expectations.

## License

[MIT](LICENSE)
