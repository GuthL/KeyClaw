# Configuration Reference

KeyClaw supports both a persistent config file and one-off environment variable overrides.

## Precedence

```text
env vars > ~/.keyclaw/config.toml > built-in defaults
```

Missing `~/.keyclaw/config.toml` is fine. Invalid TOML is a hard configuration error and is surfaced by `keyclaw doctor`.

## Config File

Default path:

```text
~/.keyclaw/config.toml
```

Example:

```toml
[proxy]
addr = "127.0.0.1:8877"
url = "http://127.0.0.1:8877"
ca_cert = "~/.keyclaw/ca.crt"
require_mitm_effective = true

[vault]
path = "~/.keyclaw/vault.enc"

[logging]
level = "info"
unsafe_log = false

[notice]
mode = "minimal"

[detection]
fail_closed = true
dry_run = false
max_body_bytes = 2097152
detector_timeout = "20s"
gitleaks_config = "~/.config/keyclaw/gitleaks.toml"
entropy_enabled = true
entropy_threshold = 3.5
entropy_min_len = 20

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
rule_ids = ["generic-api-key"]
patterns = ["^sk-test-"]
secret_sha256 = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]

[[hooks]]
event = "secret_detected"
rule_ids = ["generic-api-key"]
action = "exec"
command = "notify-slack --channel security"

[[hooks]]
event = "request_redacted"
rule_ids = ["*"]
action = "log"
path = "~/.keyclaw/hooks.log"
```

Supported top-level sections today:

- `proxy`
- `vault`
- `logging`
- `notice`
- `detection`
- `audit`
- `hosts`
- `allowlist`
- `hooks`

## Environment Variables

| Variable | Default | Notes |
|----------|---------|-------|
| `KEYCLAW_PROXY_ADDR` | `127.0.0.1:8877` | Proxy bind address |
| `KEYCLAW_PROXY_URL` | `http://127.0.0.1:8877` | URL exported to child processes |
| `KEYCLAW_CA_CERT` | `~/.keyclaw/ca.crt` | CA path passed to clients |
| `KEYCLAW_VAULT_PATH` | `~/.keyclaw/vault.enc` | Vault file location |
| `KEYCLAW_VAULT_PASSPHRASE` | unset | Explicit passphrase override |
| `KEYCLAW_CODEX_HOSTS` | `api.openai.com,chat.openai.com,chatgpt.com` | OpenAI-family hosts to intercept |
| `KEYCLAW_CLAUDE_HOSTS` | `api.anthropic.com,claude.ai` | Anthropic-family hosts to intercept |
| `KEYCLAW_PROVIDER_HOSTS` | `generativelanguage.googleapis.com,api.together.xyz,api.groq.com,api.mistral.ai,api.cohere.ai,api.deepseek.com` | Additional provider API hosts intercepted by default |
| `KEYCLAW_INCLUDE_HOSTS` | unset | Extra exact hosts or glob patterns to intercept |
| `KEYCLAW_MAX_BODY_BYTES` | `2097152` | Request-body size limit |
| `KEYCLAW_DETECTOR_TIMEOUT` | `20s` | Request-body collection and rewrite timeout; raise it for very large CLI payloads if `request_timeout` warnings persist |
| `KEYCLAW_GITLEAKS_CONFIG` | bundled rules | Path to override `gitleaks.toml` |
| `KEYCLAW_AUDIT_LOG` | `~/.keyclaw/audit.log` | Audit log path or `off` |
| `KEYCLAW_LOG_LEVEL` | `info` | `error`, `warn`, `info`, or `debug` |
| `KEYCLAW_NOTICE_MODE` | `verbose` | `verbose`, `minimal`, or `off` |
| `KEYCLAW_DRY_RUN` | `false` | Detect but do not rewrite |
| `KEYCLAW_UNSAFE_LOG` | `false` | Disable log scrubbing for debugging |
| `KEYCLAW_FAIL_CLOSED` | `true` | Reject traffic on rewrite failures |
| `KEYCLAW_REQUIRE_MITM_EFFECTIVE` | `true` | Fail loudly if traffic bypasses the proxy |
| `KEYCLAW_ENTROPY_ENABLED` | `true` | Enable entropy-based secret detection |
| `KEYCLAW_ENTROPY_THRESHOLD` | `3.5` | Entropy threshold for entropy matches |
| `KEYCLAW_ENTROPY_MIN_LEN` | `20` | Minimum token length for entropy matches |

Large top-level `prompt` or `instructions` strings that look like hidden client context are downgraded to input-only rewriting once they get large enough and do not contain obvious credential hints. Message-array content is still inspected, and large prompt bodies that clearly contain secrets are still rewritten.

## Allowlist

The allowlist exists for known-safe cases where redaction would be too aggressive.

- `rule_ids`: suppress matches from specific bundled rule IDs
- `patterns`: suppress matches whose values match a regex
- `secret_sha256`: suppress one exact secret by SHA-256 digest, without storing the plaintext

Example hash generation:

```bash
printf '%s' 'your-known-safe-secret' | sha256sum
```

## Audit Log

By default, KeyClaw writes one JSON line per redacted secret to `~/.keyclaw/audit.log`.

- Set `KEYCLAW_AUDIT_LOG=off` or `[audit] path = "off"` to disable it.
- Set `KEYCLAW_AUDIT_LOG=/path/to/file` or `[audit] path = "/path/to/file"` to relocate it.
- Rotation is the operator's job; KeyClaw appends and does not rotate automatically.

## Hooks

Hooks let you trigger local actions from request-side rewrite events without exposing the raw secret value.

- `event = "secret_detected"` fires when KeyClaw finds a secret during request rewriting
- `event = "request_redacted"` fires after the request has been rewritten, just before forwarding upstream
- `action = "exec"` runs a local command with sanitized metadata in env vars and a JSON payload on `stdin`
- `action = "log"` appends a JSON line to the configured file
- `action = "block"` rejects matching `secret_detected` requests with `hook_blocked`

Hook payloads include only `event`, `rule_id`, `placeholder`, and `request_host`. Raw secrets are not passed to hook commands or hook log files.

## Daemon Restart Rules

If you run KeyClaw as a detached daemon with `keyclaw proxy`, daemon-side settings are read when that process starts. After changing `~/.keyclaw/config.toml` or variables such as `KEYCLAW_PROXY_ADDR`, `KEYCLAW_LOG_LEVEL`, `KEYCLAW_GITLEAKS_CONFIG`, `KEYCLAW_NOTICE_MODE`, or `KEYCLAW_REQUIRE_MITM_EFFECTIVE`, restart the proxy so the running daemon picks them up.

## Notes

- Repeated `--include` flags are available on `keyclaw proxy`, `keyclaw proxy start`, `keyclaw mitm`, `keyclaw codex`, and `keyclaw claude`. They are merged into the effective interception list for that process and accept `*` / `?` glob patterns.
- GUI desktop apps launched by the OS usually do not inherit the shell proxy environment from `~/.keyclaw/env.sh`; on macOS, use the system proxy path documented in [macOS desktop-app guide](macos-gui-apps.md).
- KeyClaw does not use or require `KEYCLAW_GITLEAKS_BIN`.
- By default, KeyClaw creates a machine-local `vault.key` next to the vault instead of relying on a built-in shared passphrase.
- `KEYCLAW_UNSAFE_LOG=true` is strictly for debugging and may expose raw secret material in logs.
- `keyclaw doctor` is the quickest way to validate a new configuration.
