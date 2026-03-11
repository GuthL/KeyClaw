# Configuration Reference

KeyClaw reads `~/.keyclaw/config.toml` when it exists and then applies environment-variable overrides on top.

## Precedence

```text
env vars > ~/.keyclaw/config.toml > built-in defaults
```

Invalid config is surfaced by `keyclaw doctor` and the runtime fails closed by default.

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
entropy_enabled = true
entropy_threshold = 3.5
entropy_min_len = 20

[audit]
path = "~/.keyclaw/audit.log"

[sensitive]
passwords_enabled = true
emails_enabled = true
phones_enabled = true
national_ids_enabled = false
passports_enabled = false
payment_cards_enabled = true
cvv_enabled = true
session_ttl = "1h"

[classifier]
enabled = false
endpoint = "http://127.0.0.1:8000/v1/chat/completions"
model = "Qwen3.5-0.8B"
timeout = "3s"

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
rule_ids = ["opaque.high_entropy"]
action = "exec"
command = "notify-slack --channel security"

[[hooks]]
event = "request_redacted"
rule_ids = ["*"]
action = "log"
path = "~/.keyclaw/hooks.log"
```

Supported top-level sections:

- `proxy`
- `logging`
- `notice`
- `detection`
- `audit`
- `sensitive`
- `classifier`
- `hosts`
- `allowlist`
- `hooks`

## Environment Variables

| Variable | Default | Notes |
|----------|---------|-------|
| `KEYCLAW_PROXY_ADDR` | `127.0.0.1:8877` | Proxy bind address |
| `KEYCLAW_PROXY_URL` | `http://127.0.0.1:8877` | URL exported to child processes |
| `KEYCLAW_CA_CERT` | `~/.keyclaw/ca.crt` | CA path passed to clients |
| `KEYCLAW_CODEX_HOSTS` | `api.openai.com,chat.openai.com,chatgpt.com` | OpenAI-family hosts to intercept |
| `KEYCLAW_CLAUDE_HOSTS` | `api.anthropic.com,claude.ai` | Anthropic-family hosts to intercept |
| `KEYCLAW_PROVIDER_HOSTS` | `generativelanguage.googleapis.com,api.together.xyz,api.groq.com,api.mistral.ai,api.cohere.ai,api.deepseek.com` | Additional provider API hosts intercepted by default |
| `KEYCLAW_INCLUDE_HOSTS` | unset | Extra exact hosts or glob patterns to intercept |
| `KEYCLAW_MAX_BODY_BYTES` | `2097152` | Request-body size limit |
| `KEYCLAW_DETECTOR_TIMEOUT` | `20s` | Request-body collection and rewrite timeout |
| `KEYCLAW_AUDIT_LOG` | `~/.keyclaw/audit.log` | Audit log path or `off` |
| `KEYCLAW_LOG_LEVEL` | `info` | `error`, `warn`, `info`, or `debug` |
| `KEYCLAW_NOTICE_MODE` | `verbose` | `verbose`, `minimal`, or `off` |
| `KEYCLAW_DRY_RUN` | `false` | Detect but do not rewrite |
| `KEYCLAW_UNSAFE_LOG` | `false` | Disable log scrubbing for debugging |
| `KEYCLAW_FAIL_CLOSED` | `true` | Reject traffic on rewrite failures |
| `KEYCLAW_REQUIRE_MITM_EFFECTIVE` | `true` | Fail loudly if traffic bypasses the proxy |
| `KEYCLAW_ENTROPY_ENABLED` | `true` | Enable opaque-token detection |
| `KEYCLAW_ENTROPY_THRESHOLD` | `3.5` | Entropy threshold for opaque-token matches |
| `KEYCLAW_ENTROPY_MIN_LEN` | `20` | Minimum token length for opaque-token matches |
| `KEYCLAW_SENSITIVE_PASSWORDS_ENABLED` | `false` | Enable password detection |
| `KEYCLAW_SENSITIVE_EMAILS_ENABLED` | `false` | Enable email detection |
| `KEYCLAW_SENSITIVE_PHONES_ENABLED` | `false` | Enable phone detection |
| `KEYCLAW_SENSITIVE_NATIONAL_IDS_ENABLED` | `false` | Enable national-ID detection |
| `KEYCLAW_SENSITIVE_PASSPORTS_ENABLED` | `false` | Enable passport detection |
| `KEYCLAW_SENSITIVE_PAYMENT_CARDS_ENABLED` | `false` | Enable payment-card detection |
| `KEYCLAW_SENSITIVE_CVV_ENABLED` | `false` | Enable CVV detection |
| `KEYCLAW_SENSITIVE_SESSION_TTL` | `1h` | Session-store TTL for reversible mappings |
| `KEYCLAW_LOCAL_CLASSIFIER_ENABLED` | `false` | Enable the optional local classifier |
| `KEYCLAW_LOCAL_CLASSIFIER_ENDPOINT` | unset | OpenAI-compatible `/v1/chat/completions` endpoint |
| `KEYCLAW_LOCAL_CLASSIFIER_MODEL` | unset | Model name sent to the classifier backend |
| `KEYCLAW_LOCAL_CLASSIFIER_TIMEOUT` | `3s` | HTTP timeout for classifier requests |

## Detection Model

KeyClaw now uses a single in-process engine:

1. Structured typed detectors in `src/sensitive.rs`
2. High-entropy opaque-token detection
3. Allowlist filtering
4. Optional local classifier only for ambiguous candidates

The default runtime stores placeholder mappings in a session-scoped in-memory store. No persistent vault is required.

## Allowlist

Allowlists suppress known-safe matches:

- `rule_ids`: suppress all matches for a detector ID such as `opaque.high_entropy`
- `patterns`: suppress matches whose values match a regex
- `secret_sha256`: suppress one exact value by SHA-256 digest without storing plaintext

To compute a `secret_sha256` entry locally:

```bash
printf '%s' 'your-known-safe-secret' | sha256sum
```

## Audit Log

By default, KeyClaw writes one JSON line per redaction to `~/.keyclaw/audit.log`.

- Set `KEYCLAW_AUDIT_LOG=off` or `[audit] path = "off"` to disable it.
- Rotation is operator-managed.
- Audit records include kind, subtype, policy, detector source, and confidence metadata, but never raw values.

## Hooks

Hooks trigger sanitized local actions from request-side rewrite events:

- `event = "secret_detected"` fires when a sensitive value is found
- `event = "request_redacted"` fires after rewrite and before upstream forwarding
- `action = "exec"` runs a local command with sanitized metadata
- `action = "log"` appends a JSON line to the configured file
- `action = "block"` rejects matching `secret_detected` requests with `hook_blocked`

Hook payloads contain metadata such as `event`, `rule_id`, `kind`, `policy`, `placeholder`, and `request_host`, but never the raw secret.

## Daemon Restart Rules

If you run KeyClaw as a detached daemon with `keyclaw proxy`, daemon-side settings are read when that process starts. After changing `~/.keyclaw/config.toml` or variables such as `KEYCLAW_PROXY_ADDR`, `KEYCLAW_LOG_LEVEL`, `KEYCLAW_NOTICE_MODE`, `KEYCLAW_REQUIRE_MITM_EFFECTIVE`, `KEYCLAW_PROVIDER_HOSTS`, or `KEYCLAW_INCLUDE_HOSTS`, restart the proxy so the running daemon picks them up.

## Notes

- Repeated `--include` flags are available on `keyclaw proxy`, `keyclaw proxy start`, `keyclaw mitm`, `keyclaw codex`, and `keyclaw claude`.
- GUI desktop apps launched by the OS usually do not inherit the shell proxy environment from `~/.keyclaw/env.sh`; on macOS use the system-proxy path documented in [macOS desktop-app guide](macos-gui-apps.md).
- `KEYCLAW_UNSAFE_LOG=true` is strictly for debugging and may expose raw sensitive material in logs.
- `keyclaw doctor` is the quickest way to validate a new configuration.
