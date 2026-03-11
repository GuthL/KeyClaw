# KeyClaw Local Proxy Trace On Louis's Machine

Date: 2026-03-10

This file records the local debugging session for the report:

- "the proxy does not seem to catch much secret on this machine after running"

It is written as prompt-ready context for a future debugging pass.

## Summary

There were three distinct failure modes on this machine:

1. Desktop GUI apps (`Codex.app`, `Claude.app`, `ChatGPT.app`) initially bypassed KeyClaw entirely because they were launched by macOS and did not inherit proxy environment variables from a shell that sourced `~/.keyclaw/env.sh`.
2. The `keyclaw codex ...` CLI wrapper was routing traffic through KeyClaw correctly, but the native Codex binary was rejecting the KeyClaw MITM certificate on macOS with `The certificate was not trusted.` The fix was to add `~/.keyclaw/ca.crt` to the macOS login keychain as a trusted root.
3. After enabling the macOS system proxy for `Wi-Fi`, `Claude.app` reached KeyClaw but failed with `ERR_CERT_AUTHORITY_INVALID` because the KeyClaw CA trust entry had been added incorrectly for Electron's trust path. The fix was to add an explicit user-domain `SSL` trust setting for `~/.keyclaw/ca.crt`, flush `trustd`, and relaunch Claude.

After fixing the trust issue, a real `keyclaw codex exec ...` run with a fake secret in the prompt succeeded and produced a `chatgpt.com` audit-log redaction entry for the fake secret.

## Important Outcomes

- `keyclaw claude ...` was already correctly routed through KeyClaw.
- `keyclaw codex ...` now also works after trusting the KeyClaw CA in the macOS login keychain.
- Desktop apps can be forced through KeyClaw on this machine by enabling the macOS system proxy for `Wi-Fi`.
- `Claude.app` now successfully uses KeyClaw after the corrected user-domain SSL trust fix.
- `Codex.app` reaches KeyClaw under the system proxy, but some startup traffic still triggers `invalid_json` rewrite warnings inside KeyClaw.

## Local State Observed Before Fixes

### Audit log baseline

`keyclaw proxy stats` showed almost no real provider traffic:

- Total redactions: `34`
- Top hosts:
  - `127.0.0.1: 32`
  - `api.anthropic.com: 1`
  - `stdin: 1`

That strongly suggested KeyClaw detection itself was functioning, but real client traffic was mostly not flowing through it.

### Broken proxy process state

At one point the machine had stale/orphaned KeyClaw proxy processes:

- foreground listener on `127.0.0.1:8877`
- another listener on `127.0.0.1:64999`
- stale `~/.keyclaw/env.sh` pointing at a dead PID and old port
- no valid `~/.keyclaw/proxy.pid`

This caused split-brain behavior:

- `keyclaw proxy status` said `proxy not running`
- but `lsof` still showed listeners on KeyClaw ports

That was cleaned up during debugging.

## Initial Desktop App Bypass Trace

### Codex desktop app

Observed running GUI process:

- `/Applications/Codex.app/Contents/MacOS/Codex`

Observed network helper:

- `Codex Helper --type=utility --utility-sub-type=network.mojom.NetworkService`

Observed live outbound network:

- direct outbound TLS/UDP to public remote `:443`
- not to `127.0.0.1:<keyclaw-port>`

Conclusion before system proxy configuration:

- `Codex.app` was bypassing KeyClaw before any request rewrite could happen.
- Root cause: GUI app launched by macOS, not from a shell with KeyClaw proxy env.

### Claude desktop app

Observed running GUI process:

- `/Applications/Claude.app/Contents/MacOS/Claude`

Observed network helper:

- `Claude Helper --type=utility --utility-sub-type=network.mojom.NetworkService`

Observed live outbound network:

- direct sockets like `10.0.0.6:* -> public-ip:443`
- not to `127.0.0.1:<keyclaw-port>`

Conclusion before system proxy configuration:

- `Claude.app` was also bypassing KeyClaw before any request rewrite.

## CLI Wrapper Trace

## `keyclaw claude`

Command used:

```bash
keyclaw claude -p "Reply with OK only."
```

Observed process tree:

- parent: `keyclaw`
- child: `claude`

Observed child environment:

- `HTTP_PROXY=http://127.0.0.1:8877`
- `HTTPS_PROXY=http://127.0.0.1:8877`
- `ALL_PROXY=http://127.0.0.1:8877`
- `SSL_CERT_FILE=~/.keyclaw/ca.crt`
- `REQUESTS_CA_BUNDLE=~/.keyclaw/ca.crt`
- `NODE_EXTRA_CA_CERTS=~/.keyclaw/ca.crt`

Observed sockets:

- `claude` had `127.0.0.1:* -> 127.0.0.1:8877`
- `keyclaw` had corresponding outbound TLS sockets to Anthropic

Conclusion:

- `keyclaw claude` is routed through KeyClaw correctly on this machine.

### Note

During the Claude trace, KeyClaw logged repeated:

- `keyclaw warn: rewrite timeout`

This did not prove bypass, but it may explain why the machine can feel like it is "catching little" or behaving unreliably under some Claude CLI traffic patterns.

## `keyclaw codex` Before Trust Fix

Initial command used:

```bash
keyclaw codex exec -C /tmp --skip-git-repo-check "Reply with OK only."
```

Observed process tree:

- `keyclaw`
- `node .../bin/codex`
- native Codex binary

Observed native Codex binary environment:

- `HTTP_PROXY=http://127.0.0.1:8877`
- `HTTPS_PROXY=http://127.0.0.1:8877`
- `ALL_PROXY=http://127.0.0.1:8877`
- `SSL_CERT_FILE=~/.keyclaw/ca.crt`
- `REQUESTS_CA_BUNDLE=~/.keyclaw/ca.crt`
- `NODE_EXTRA_CA_CERTS=~/.keyclaw/ca.crt`

Conclusion:

- `keyclaw codex` was not bypassing KeyClaw at launch time.
- It was definitely trying to use the KeyClaw proxy.

### Failure observed

Codex failed with errors like:

- `The certificate was not trusted.`
- failures on `https://chatgpt.com/backend-api/...`

That showed the problem was not routing. It was TLS trust.

## Codex TLS Trust Investigation

Observed properties of the native Codex binary:

- linked against macOS `Security.framework`
- contained many `rustls` strings internally

Interpretation:

- the Codex native binary on macOS was not relying solely on the shell CA variables in a way that accepted the KeyClaw CA
- the machine-local KeyClaw CA needed to be trusted by macOS keychain for this client path

### KeyClaw CA details

From `~/.keyclaw/ca.crt`:

- Subject: `CN=KeyClaw CA, O=KeyClaw`
- Issuer: `CN=KeyClaw CA, O=KeyClaw`
- SHA-256 fingerprint:
  - `25:CA:B0:8A:25:1D:10:04:A3:B4:49:B3:B5:4D:9C:CD:07:FF:BE:0D:70:8A:D7:12:AA:92:5A:37:49:F0:FC:BE`

### Initial trust fix applied

The KeyClaw CA was initially added to the login keychain with:

```bash
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db ~/.keyclaw/ca.crt
```

That was sufficient for the native Codex CLI path, but it later turned out to be the wrong trust-domain shape for Electron GUI use because `-d` writes to the admin trust domain. The cert was present in the login keychain, but the trust settings were not ideal for Chromium/Electron.

## `keyclaw codex` After Trust Fix

Retest command:

```bash
keyclaw codex exec -C /tmp --skip-git-repo-check "Reply with OK only."
```

Result:

- the previous `certificate was not trusted` failure disappeared
- Codex successfully started its normal MCP startup flow:
  - `mcp: pencil ready`
  - `mcp: codex_apps ready`

This confirmed the keychain trust fix addressed the native TLS trust problem.

## Positive Control: Real Redaction On Codex Path

Final proof command:

```bash
keyclaw codex exec -C /tmp --skip-git-repo-check "Reply with the word SAFE only. Here is a test credential: api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"
```

Observed model output:

- Codex acknowledged the KeyClaw placeholder notice
- returned `SAFE`

Observed audit log delta:

- audit log line count increased
- new entries were recorded with `request_host: "chatgpt.com"`
- one new entry matched the fake secret under:
  - `rule_id: "generic-api-key"`
  - `match_source: "regex"`
- additional `entropy` entries were also recorded for other high-entropy strings in the request context

Important proof line:

- `request_host: "chatgpt.com"` appeared in the new audit entries

That proves the real Codex CLI path was:

- `codex CLI -> KeyClaw localhost proxy -> chatgpt.com backend`

and that KeyClaw actually redacted the fake secret in that live Codex request.

## Final Conclusions

### Working

- `keyclaw claude ...` works on this machine
- `keyclaw codex ...` works on this machine after the CA trust fix
- KeyClaw can actively redact secrets in real Codex traffic on this machine
- `Claude.app` now works through KeyClaw when the macOS system proxy is enabled on `Wi-Fi`

### Not protected by default

- `Codex.app`
- `Claude.app`
- `ChatGPT.app`

These desktop apps still bypass KeyClaw when launched normally by macOS if the system proxy is off, because they do not inherit shell proxy env by default.

### Protected when the macOS system proxy is enabled

- `Claude.app` now reaches `127.0.0.1:8877` successfully
- `ChatGPT.app` also showed live `127.0.0.1:8877` connections while the system proxy was enabled
- `Codex.app` also reached `127.0.0.1:8877`, but some startup traffic still produced KeyClaw rewrite warnings

## Recommended Next Steps

1. Use the CLI wrappers for protected traffic:

```bash
keyclaw codex ...
keyclaw claude ...
```

2. If desktop apps must be protected, investigate one of:

- launching them from a proxy-configured environment
- system proxy configuration
- app-specific proxy configuration if supported

3. Investigate `rewrite timeout` warnings seen on the Claude CLI path. They may indicate request-body collection or rewrite latency that can reduce practical coverage even when routing is correct.

4. If coverage still "feels low", use:

```bash
keyclaw proxy stats
tail -n 50 ~/.keyclaw/audit.log
```

and check whether real provider hosts like `chatgpt.com`, `api.openai.com`, or `api.anthropic.com` are appearing.

## GUI Setup On macOS

This was fully executed during the session on the active `Wi-Fi` service.

### Why this is needed

- The GUI apps were launched by macOS, not by a shell with KeyClaw env vars.
- On this machine, `scutil --proxy` showed `HTTPSEnable : 0`, meaning the system HTTPS proxy was effectively off.
- For these GUI apps, system proxy configuration is more reliable than shell env injection.

### Preconditions

- `~/.keyclaw/ca.crt` must be trusted in the macOS keychain.
- A KeyClaw proxy must be running.

### Steps executed on this machine

1. Start the proxy:

```bash
keyclaw proxy --foreground
```

2. Identify the active network service. On this machine:

- `route get default` showed `interface: en0`
- `networksetup -listnetworkserviceorder` mapped `en0` to `Wi-Fi`

3. Configure the system proxy for `Wi-Fi`:

```bash
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8877 off
networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8877 off
networksetup -setwebproxystate "Wi-Fi" on
networksetup -setsecurewebproxystate "Wi-Fi" on
networksetup -setproxybypassdomains "Wi-Fi" localhost 127.0.0.1 "*.local" "169.254/16"
```

4. Confirm the proxy is live:

```bash
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"
scutil --proxy
```

Observed values:

- `Enabled: Yes`
- `Server: 127.0.0.1`
- `Port: 8877`
- `HTTPEnable : 1`
- `HTTPSEnable : 1`
- `HTTPProxy : 127.0.0.1`
- `HTTPSProxy : 127.0.0.1`

5. Fully quit and relaunch the GUI apps:

```bash
osascript -e 'tell application "Codex" to quit' -e 'tell application "Claude" to quit'
open -a Codex
open -a Claude
```

The relaunch matters because already-running GUI apps may keep old network state.

### Verification

After relaunch, desktop traffic started reaching KeyClaw. Evidence included:

```bash
lsof -nP -iTCP:8877
```

Observed results:

- `Claude.app` main process and network helper had live `127.0.0.1:* -> 127.0.0.1:8877` sockets
- `ChatGPT.app` also had a live `127.0.0.1:* -> 127.0.0.1:8877` socket
- `Codex.app` network helper also had a live `127.0.0.1:* -> 127.0.0.1:8877` socket

This proved the GUI apps were no longer bypassing KeyClaw when the macOS system proxy was enabled.

## Claude GUI `ERR_CERT_AUTHORITY_INVALID` Fix

After the system proxy was enabled, `Claude.app` started reaching KeyClaw but failed with:

- `net::ERR_CERT_AUTHORITY_INVALID`
- `Failed to load URL: https://claude.ai/`

The active runtime log was:

- `~/Library/Logs/Claude/main.log`

Observed failures there included:

- `[growthbook] fetch failed: Error: net::ERR_CERT_AUTHORITY_INVALID`
- `[getBootstrapData] Bootstrap fetch failed net::ERR_CERT_AUTHORITY_INVALID`
- repeated health-check failures with `net::ERR_CERT_AUTHORITY_INVALID`

### Root cause

The earlier trust command used `-d`, which means:

- `security add-trusted-cert -d ...`
- `-d` adds trust to the admin domain, not the user domain

Chromium's macOS trust evaluation checks user trust settings first. The login keychain cert was present, but the Electron path still rejected it.

### Correct trust fix applied

First, the KeyClaw CA was added to the user domain without `-d`:

```bash
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ~/.keyclaw/ca.crt
```

Then an explicit SSL trust setting was added:

```bash
security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.keyclaw/ca.crt
```

Verification:

```bash
security dump-trust-settings
security verify-cert -c ~/.keyclaw/ca.crt -k ~/Library/Keychains/login.keychain-db -p ssl
```

Observed result:

- `Number of trusted certs = 1`
- `Cert 0: KeyClaw CA`
- `Number of trust settings : 1`
- `Policy OID : SSL`
- `certificate verification successful`

Then trust consumers were flushed and Claude was relaunched:

```bash
killall trustd || true
osascript -e 'tell application "Claude" to quit'
open -a Claude
```

### Result

After that correction:

- `~/Library/Logs/Claude/main.log` no longer showed fresh `ERR_CERT_AUTHORITY_INVALID` failures
- the same log showed successful bootstrap behavior, including:
  - `[growthbook] loaded 39 features (39 changed)` at `2026-03-10 22:58:55`
  - `[growthbook] loaded 39 features (0 changed)` at `2026-03-10 22:59:03`
- `lsof -nP -iTCP:8877` showed many live `Claude -> 127.0.0.1:8877` connections

Conclusion:

- `Claude.app` now works through KeyClaw on this machine when the system proxy is enabled.

## Codex GUI Follow-up

After the macOS system proxy was enabled, `Codex.app` also began routing to `127.0.0.1:8877`.

Evidence:

- the Codex network helper had a live `127.0.0.1:* -> 127.0.0.1:8877` connection
- KeyClaw foreground logs emitted fresh rewrite warnings during Codex desktop startup
- the Codex desktop log for `2026-03-10` showed repeated failures like:
  - `Statsig: network override failed`
  - `Failed to fetch (ab.chatgpt.com)`

At the same time, KeyClaw logged:

- `keyclaw warn: rewrite error (invalid_json): invalid_json: rewrite failed: decode json: expected value at line 1 column 1`

Interpretation:

- `Codex.app` is no longer bypassing KeyClaw when the system proxy is enabled
- there is still an application-level incompatibility on some startup traffic through KeyClaw, likely involving non-chat `chatgpt.com` side traffic rather than the basic proxy route itself

## Subsequent Code Fixes

After the live machine trace, the KeyClaw codebase was updated to address two distinct product issues that were uncovered during the session.

### 1. `invalid_json` startup warnings on Codex GUI traffic

Root cause in code:

- KeyClaw treated a missing or empty `Content-Type` as JSON by default in `src/proxy/common.rs`
- some Codex desktop startup requests sent non-JSON bodies without a JSON content type
- KeyClaw attempted to decode those bodies as JSON anyway and logged:
  - `invalid_json: rewrite failed: decode json: expected value at line 1 column 1`

Fix applied:

- `is_json("")` no longer returns `true`
- bodies without a JSON content type are now only rewritten when JSON sniffing in the HTTP path positively identifies them as JSON

Added regression coverage:

- `src/proxy/common.rs`
  - `is_json_requires_an_explicit_json_content_type`
- `tests/integration_proxy.rs`
  - `non_json_body_without_content_type_is_passed_through_in_fail_closed_mode`
  - `json_body_without_content_type_is_still_rewritten`

Result:

- non-JSON traffic without `Content-Type: application/json` is no longer forced through the JSON rewrite path
- real JSON traffic without an explicit JSON content type is still rewritten

### 2. Flaky background proxy / dead system proxy failure mode

Root cause in code:

- `keyclaw proxy` detached mode was only spawning a background child process and returning after `proxy.pid` and `env.sh` appeared
- it did not verify that the configured address was actually listening
- `Server::start()` silently fell back from the configured address to `127.0.0.1:0` when the requested port was busy
- on macOS, there was no real `launchd` autostart support

Observed operator impact:

- the system proxy could still point at `127.0.0.1:8877`
- the detached KeyClaw child could die or bind a different random port
- Chrome and other GUI apps would then lose internet with:
  - `ERR_PROXY_CONNECTION_FAILED`

Fixes applied:

- foreground proxy startup now disables the silent `AddrInUse -> 127.0.0.1:0` fallback
- detached readiness now requires:
  - matching `proxy.pid`
  - `env.sh` present
  - the configured address is actually accepting TCP connections
- `keyclaw proxy status` now fails if the process exists but is not listening on the advertised address
- detached startup now calls `setsid()` on Unix so the child is less sensitive to parent-terminal teardown
- macOS `launchd` autostart support was added with:
  - `~/Library/LaunchAgents/com.keyclaw.proxy.plist`
  - `RunAtLoad`
  - `KeepAlive`
  - `launchctl bootstrap`
  - `launchctl kickstart -k`

Added regression coverage:

- `tests/e2e_cli/proxy.rs`
  - `proxy_detached_fails_fast_when_configured_port_is_busy`
  - `proxy_autostart_enable_writes_launch_agent_and_invokes_launchctl`
- `src/launcher/bootstrap/tests.rs`
  - `proxy_addr_is_listening_detects_live_listener`

Operational mitigation used on this machine:

- the macOS `Wi-Fi` system proxy was turned back off after the internet outage:

```bash
networksetup -setwebproxystate "Wi-Fi" off
networksetup -setsecurewebproxystate "Wi-Fi" off
```

Verification:

- `networksetup -getwebproxy "Wi-Fi"` showed `Enabled: No`
- `networksetup -getsecurewebproxy "Wi-Fi"` showed `Enabled: No`
- `scutil --proxy` showed `HTTPEnable : 0` and `HTTPSEnable : 0`

This restored normal internet access immediately, and the code changes above are intended to prevent KeyClaw from leaving the machine in that broken state again.

### Rollback

To stop forcing GUI traffic through KeyClaw on `Wi-Fi`:

```bash
networksetup -setwebproxystate "Wi-Fi" off
networksetup -setsecurewebproxystate "Wi-Fi" off
```

Then quit and relaunch the GUI apps again.

### Lower-confidence alternative

It may also be possible to use `launchctl setenv` to inject proxy env vars into newly launched GUI apps, but for Electron/Chromium-based desktop apps on macOS, system proxy configuration is the higher-confidence path.

## Sanitization Notes

- This file intentionally avoids including any real secrets observed in the shell environment during process inspection.
- The only explicit secret shown here is the fake test credential used to verify redaction.
