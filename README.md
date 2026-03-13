# KeyClaw

KeyClaw is a local proxy and CLI wrapper for secret-safe AI traffic. It sits between your tool and the upstream API, rewrites outbound payloads to remove sensitive values, injects a short notice so the model understands what happened, and reinjects the real values locally on the way back.

The runtime is built around two detector families:

- `opaque_token`: high-entropy tokens that look like credentials, API keys, access tokens, or random identifiers
- typed structured detectors: passwords, emails, phone numbers, national IDs, passports, payment-card numbers, and CVV

The current placeholder contract is format-preserving and session-scoped. A redacted value becomes a placeholder like `{{KEYCLAW_aaaaa@aaaaaaa.aaa~e771b46928f160da7}}`, where the visible shape is preserved but the original value is not.

## What KeyClaw Does

- intercepts supported AI CLI traffic before it leaves your machine
- replaces sensitive values with reversible placeholders
- stores placeholder mappings in a session-scoped local store instead of a persistent vault
- injects an operator-controlled notice so the model understands that placeholders are safe to use
- resolves placeholders in responses, SSE streams, and supported WebSocket flows
- records sanitized audit metadata without writing raw secrets to disk
- supports request-side hooks for logging, external automation, or blocking

## What It Does Not Do

- it does not make a remote model trustworthy
- it does not inspect multipart uploads or arbitrary binary files
- it does not persist a long-lived encrypted secret vault in the current architecture
- it does not guarantee perfect detection; entropy and regex-based systems always involve precision and recall tradeoffs

## Quick Start

### 1. Build Or Install

From a checkout:

```bash
cargo build --release
```

Or install it into your Cargo bin directory:

```bash
cargo install --path .
```

### 2. Run First-Time Setup

```bash
keyclaw init
keyclaw doctor
```

`init` prepares `~/.keyclaw/`, generates the local CA if needed, writes `~/.keyclaw/env.sh`, and offers to source that env script from your shell rc file.

### 3. Choose How To Use It

For one-off CLI sessions, use the wrappers:

```bash
keyclaw codex --resume latest
keyclaw claude --continue
```

For a long-lived daemon:

```bash
keyclaw proxy start
source ~/.keyclaw/env.sh
```

Once `env.sh` is sourced, tools launched from that shell inherit the proxy settings automatically.

## Core Commands

### `keyclaw init`

Guided first-run setup.

- ensures `~/.keyclaw/ca.crt` and `~/.keyclaw/ca.key` exist
- writes `~/.keyclaw/env.sh`
- offers to patch your shell rc file
- runs `doctor` at the end

### `keyclaw doctor`

Runs health checks for:

- config-file validity
- proxy bind address sanity
- proxy URL sanity
- CA presence and macOS trust checks
- detection and allowlist settings
- bypass risk such as `NO_PROXY`
- unsafe logging mode

It returns exit code `1` only for blocking failures.

### `keyclaw codex ...` and `keyclaw claude ...`

Preferred path for CLI use. These wrappers:

- start an in-process proxy
- inject proxy environment into the child process
- point TLS consumers at the KeyClaw CA where possible
- fail loudly if traffic appears to bypass the proxy when `KEYCLAW_REQUIRE_MITM_EFFECTIVE=true`

Flags supported by the wrappers:

- `--dry-run`
- `--include <HOST_GLOB>` repeatable, supports `*` and `?`

### `keyclaw mitm <tool> ...`

Generic wrapper entry point for supported tools.

Today `tool` is intentionally limited to:

- `codex`
- `claude`

### `keyclaw proxy`

Manages the detached proxy daemon.

```bash
keyclaw proxy start
keyclaw proxy start --foreground
keyclaw proxy stop
keyclaw proxy status
keyclaw proxy stats
keyclaw proxy autostart enable
keyclaw proxy autostart disable
keyclaw proxy autostart status
```

`proxy start` detaches by default. On macOS and Linux, autostart support targets:

- macOS `launchd`
- Linux `systemd --user`

Autostart keeps the daemon alive after login, but shells still need `source ~/.keyclaw/env.sh`.

### `keyclaw rewrite-json`

Reads JSON from stdin and writes rewritten JSON to stdout. This is the fastest way to test detection without going through a live proxy.

```bash
printf '%s\n' '{"prompt":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"}' | keyclaw rewrite-json
```

Useful for:

- detector tuning
- hook development
- config smoke tests
- CI fixtures

## Placeholder Contract

KeyClaw now uses a single format-preserving placeholder family:

```text
{{KEYCLAW_<shape>~<kind><id>}}
```

Meaning:

- `<shape>` mirrors the visible character pattern of the original value
- `<kind>` is a one-letter tag for the sensitive-data class
- `<id>` is a 16-hex session-scoped opaque identifier

Example:

```text
alice@company.dev
{{KEYCLAW_aaaaa@aaaaaaa.aaa~e771b46928f160da7}}
```

Current kind tags:

- `o`: opaque token
- `p`: password
- `e`: email
- `h`: phone
- `i`: national ID
- `s`: passport
- `c`: payment card
- `v`: CVV

The placeholder preserves shape, not value. It should never be treated as a reversible encoding by anything except the local KeyClaw runtime.

## Detection Model

### Opaque-Token Detection

Enabled by default.

This path looks for high-entropy tokens that resemble credentials or opaque identifiers. It is intentionally pragmatic: if a token is random-looking enough and not allowlisted, KeyClaw may replace it even if it is not semantically a "real secret."

### Typed Detection

Optional per class:

- passwords
- emails
- phones
- national IDs
- passports
- payment cards
- CVV

Typed detection is rules-first. An optional local classifier can be enabled for ambiguous low-confidence candidates through an OpenAI-compatible `/v1/chat/completions` endpoint.

## Runtime Files

KeyClaw stores runtime state under `~/.keyclaw/`:

- `ca.crt`: local certificate authority certificate
- `ca.key`: local CA private key
- `env.sh`: shell helper for proxy environment export
- `audit.log`: sanitized JSONL audit log unless disabled
- `proxy.log`: detached proxy log
- `mitm.log`: wrapper log for interactive CLI sessions
- `proxy.pid`: daemon PID tracking

The sensitive-value store is session-scoped in memory. It is not persisted as a long-lived vault in the current runtime.

## Configuration

Configuration comes from three layers, in this order:

1. built-in defaults
2. `~/.keyclaw/config.toml`
3. environment variable overrides

Important controls:

- proxy bind and exported URL
- host allowlist and extra include globs
- fail-closed vs pass-through behavior
- dry-run mode
- audit logging path
- entropy detector thresholds
- typed detector toggles
- session-store TTL
- hook definitions
- local classifier endpoint/model/timeout

See [docs/configuration.md](./docs/configuration.md) for the complete file schema and env-var table.

## Dry Run, Audit Logs, And Hooks

### Dry Run

`--dry-run` or `KEYCLAW_DRY_RUN=true` keeps the detection and reporting path active without mutating live traffic.

### Audit Log

Audit entries are sanitized and do not include raw sensitive values. They include metadata like:

- request host
- rule id
- kind
- subtype
- policy
- placeholder

Disable it with:

```bash
export KEYCLAW_AUDIT_LOG=off
```

### Hooks

Hooks are request-side actions configured in `config.toml`. They can:

- `log`
- `exec`
- `block`

Hook payloads are sanitized and carry metadata such as event, rule id, kind, placeholder, and request host.

## macOS Desktop Apps

For Finder-launched apps on macOS, shell env injection is not enough. The supported path is:

1. run `keyclaw init`
2. trust `~/.keyclaw/ca.crt` in the login keychain for SSL
3. run a healthy KeyClaw proxy
4. point the macOS HTTP and HTTPS system proxy at the KeyClaw listener
5. fully relaunch the desktop app

See [docs/macos-gui-apps.md](./docs/macos-gui-apps.md) for the exact steps.

## Security Model

KeyClaw assumes:

- user input, retrieved content, model output, and remote providers are untrusted
- the local rewrite engine and session-scoped resolver are trusted
- raw secrets should never leave the machine when detection succeeds

Read [docs/threat-model.md](./docs/threat-model.md) for the concrete trust boundaries and failure modes.

## Docs Map

- [docs/README.md](./docs/README.md): docs index
- [docs/architecture.md](./docs/architecture.md): runtime design
- [docs/configuration.md](./docs/configuration.md): file and env configuration
- [docs/secret-patterns.md](./docs/secret-patterns.md): detector coverage and placeholder contract
- [docs/threat-model.md](./docs/threat-model.md): assets, adversaries, controls
- [docs/macos-gui-apps.md](./docs/macos-gui-apps.md): macOS desktop-app path
- [docs/release/maintainer-checklist.md](./docs/release/maintainer-checklist.md): release checklist

## Development

Fast local verification:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --all-features -- -D warnings
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contributor workflow and release notes.
