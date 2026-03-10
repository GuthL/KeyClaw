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
detector_timeout = "4s"
gitleaks_config = "~/.config/keyclaw/gitleaks.toml"
entropy_enabled = true
entropy_threshold = 3.5
entropy_min_len = 20

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

Supported top-level sections today:

- `proxy`
- `vault`
- `logging`
- `notice`
- `detection`
- `audit`
- `hosts`
- `allowlist`

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
| `KEYCLAW_MAX_BODY_BYTES` | `2097152` | Request-body size limit |
| `KEYCLAW_DETECTOR_TIMEOUT` | `4s` | Request inspection timeout |
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

## Daemon Restart Rules

If you run KeyClaw as a detached daemon with `keyclaw proxy`, daemon-side settings are read when that process starts. After changing `~/.keyclaw/config.toml` or variables such as `KEYCLAW_PROXY_ADDR`, `KEYCLAW_LOG_LEVEL`, `KEYCLAW_GITLEAKS_CONFIG`, `KEYCLAW_NOTICE_MODE`, or `KEYCLAW_REQUIRE_MITM_EFFECTIVE`, restart the proxy so the running daemon picks them up.

## Notes

- KeyClaw does not use or require `KEYCLAW_GITLEAKS_BIN`.
- By default, KeyClaw creates a machine-local `vault.key` next to the vault instead of relying on a built-in shared passphrase.
- `KEYCLAW_UNSAFE_LOG=true` is strictly for debugging and may expose raw secret material in logs.
- `keyclaw doctor` is the quickest way to validate a new configuration.
