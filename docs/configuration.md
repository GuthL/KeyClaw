# Configuration

KeyClaw loads configuration from three layers:

1. built-in defaults
2. `~/.keyclaw/config.toml`
3. environment variable overrides

If a config file exists and is invalid, normal commands fail fast. `keyclaw
doctor` reports the error instead of crashing silently.

## Quick Example

```toml
[proxy]
addr = "127.0.0.1:8877"
url = "http://127.0.0.1:8877"
require_mitm_effective = true

[logging]
level = "info"
unsafe_log = false

[notice]
mode = "verbose"

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
phones_enabled = false
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
include = ["api.my-company.example"]

[allowlist]
rule_ids = ["opaque.high_entropy"]
patterns = ["^example-token-"]
secret_sha256 = []

[[hooks]]
event = "request_redacted"
action = "log"
path = "~/.keyclaw/hooks.log"
```

## Config File Sections

### `[proxy]`

- `addr`: bind address for the local proxy listener
- `url`: URL exported to child processes and `~/.keyclaw/env.sh`
- `ca_cert`: optional CA certificate path override
- `require_mitm_effective`: fail wrapped tool sessions if traffic appears to
  bypass the proxy

### `[logging]`

- `level`: `error`, `warn`, `info`, `debug`, or `trace`
- `unsafe_log`: allow unsanitized logging for local debugging only

### `[notice]`

- `mode`: `verbose`, `minimal`, or `off`

This controls the text KeyClaw injects after it rewrites a payload.

### `[detection]`

- `fail_closed`: block the request when rewriting fails
- `dry_run`: report detections without mutating the request
- `max_body_bytes`: inspection size cap
- `detector_timeout`: maximum time spent reading and inspecting a body
- `entropy_enabled`: enable the `opaque_token` detector
- `entropy_threshold`: Shannon entropy threshold for opaque-token candidates
- `entropy_min_len`: minimum token length for entropy-driven matching

### `[audit]`

- `path`: JSONL audit log location

Set the environment variable `KEYCLAW_AUDIT_LOG=off` to disable persistent audit
logging entirely.

### `[sensitive]`

- `passwords_enabled`
- `emails_enabled`
- `phones_enabled`
- `national_ids_enabled`
- `passports_enabled`
- `payment_cards_enabled`
- `cvv_enabled`
- `session_ttl`

This section controls typed structured detectors and the lifetime of the
session-scoped store. `KEYCLAW_SENSITIVE_SESSION_TTL` is the environment
override for `session_ttl`.

### `[classifier]`

- `enabled`
- `endpoint`
- `model`
- `timeout`

The classifier must expose an OpenAI-compatible
`/v1/chat/completions` endpoint. It is optional and off by default.

### `[hosts]`

- `codex`: exact hosts or globs treated as Codex/OpenAI traffic
- `claude`: exact hosts or globs treated as Claude/Anthropic traffic
- `providers`: shared provider hosts
- `include`: extra hosts or globs added to the intercept set

KeyClaw only rewrites traffic routed to in-scope hosts.

### `[allowlist]`

- `rule_ids`: skip detection by rule id
- `patterns`: regex patterns matched against the raw candidate value
- `secret_sha256`: exact SHA-256 digests of values that should be ignored

The allowlist is config-file-driven only.

### `[[hooks]]`

Each hook entry has:

- `event`: `secret_detected` or `request_redacted`
- `action`: `log`, `exec`, or `block`
- `rule_ids`: optional list to scope the hook to specific detector ids

Action-specific fields:

- `log`: `path`
- `exec`: `command`, optional `timeout_ms`
- `block`: optional `message`

Hook records are sanitized and include metadata such as `rule_id`, `kind`,
`subtype`, `policy`, `placeholder`, and `request_host`.

## Environment Variables

### Proxy And Routing

- `KEYCLAW_PROXY_ADDR`
- `KEYCLAW_PROXY_URL`
- `KEYCLAW_CA_CERT`
- `KEYCLAW_CODEX_HOSTS`
- `KEYCLAW_CLAUDE_HOSTS`
- `KEYCLAW_PROVIDER_HOSTS`
- `KEYCLAW_INCLUDE_HOSTS`

### Runtime Behavior

- `KEYCLAW_FAIL_CLOSED`
- `KEYCLAW_DRY_RUN`
- `KEYCLAW_MAX_BODY_BYTES`
- `KEYCLAW_DETECTOR_TIMEOUT`
- `KEYCLAW_REQUIRE_MITM_EFFECTIVE`
- `KEYCLAW_NOTICE_MODE`
- `KEYCLAW_LOG_LEVEL`
- `KEYCLAW_UNSAFE_LOG`
- `KEYCLAW_AUDIT_LOG`

### Opaque-Token Detection

- `KEYCLAW_ENTROPY_ENABLED`
- `KEYCLAW_ENTROPY_THRESHOLD`
- `KEYCLAW_ENTROPY_MIN_LEN`

### Typed Sensitive-Data Detection

- `KEYCLAW_SENSITIVE_PASSWORDS_ENABLED`
- `KEYCLAW_SENSITIVE_EMAILS_ENABLED`
- `KEYCLAW_SENSITIVE_PHONES_ENABLED`
- `KEYCLAW_SENSITIVE_NATIONAL_IDS_ENABLED`
- `KEYCLAW_SENSITIVE_PASSPORTS_ENABLED`
- `KEYCLAW_SENSITIVE_PAYMENT_CARDS_ENABLED`
- `KEYCLAW_SENSITIVE_CVV_ENABLED`
- `KEYCLAW_SENSITIVE_SESSION_TTL`

### Optional Local Classifier

- `KEYCLAW_LOCAL_CLASSIFIER_ENABLED`
- `KEYCLAW_LOCAL_CLASSIFIER_ENDPOINT`
- `KEYCLAW_LOCAL_CLASSIFIER_MODEL`
- `KEYCLAW_LOCAL_CLASSIFIER_TIMEOUT`

## Runtime Files

KeyClaw keeps local state in `~/.keyclaw/`:

- `ca.crt`
- `ca.key`
- `env.sh`
- `audit.log`
- `proxy.log`
- `mitm.log`
- `proxy.pid`

The placeholder mapping itself is not stored in a long-lived vault. It is kept
in a session-scoped store managed by `src/sensitive.rs`.

## Practical Patterns

### Ephemeral CLI Usage

```bash
keyclaw codex --include api.my-company.example --resume latest
```

### Detached Daemon

```bash
keyclaw proxy start
source ~/.keyclaw/env.sh
```

### Rewrite Testing

```bash
printf '%s\n' '{"messages":[{"role":"user","content":"email=alice@example.com"}]}' \
  | KEYCLAW_SENSITIVE_EMAILS_ENABLED=true keyclaw rewrite-json
```

### Disable Audit Logging

```bash
export KEYCLAW_AUDIT_LOG=off
```
