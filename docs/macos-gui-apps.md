# macOS Desktop-App Guide

KeyClaw's CLI wrappers are the preferred macOS path because they inject proxy settings and CA trust into the child process directly.

Finder-launched apps are different. `Claude.app`, `Codex.app`, `ChatGPT.app`, and similar GUI clients are launched by macOS, not by your shell, so they do not reliably inherit the proxy environment you get from `source ~/.keyclaw/env.sh`.

The current supported path for macOS desktop apps is:

1. initialize KeyClaw normally
2. trust `~/.keyclaw/ca.crt` in the login keychain for SSL
3. run a healthy KeyClaw proxy
4. enable the macOS HTTP and HTTPS system proxy on the active network service
5. fully relaunch the desktop app

## Prerequisites

Run the normal first-run setup first:

```bash
keyclaw init
keyclaw proxy
keyclaw proxy status
keyclaw doctor
```

If `keyclaw proxy status` is not healthy, do not enable the macOS system proxy yet. A system proxy that points at a dead KeyClaw listener can break browser and desktop-app connectivity. On macOS, `keyclaw doctor` also warns when Finder-launched apps are likely bypassing the proxy or when `~/.keyclaw/ca.crt` is not trusted for SSL in the login keychain.

## Trust The KeyClaw CA

Trust `~/.keyclaw/ca.crt` in the login keychain for SSL:

```bash
security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.keyclaw/ca.crt
killall trustd || true
```

Verify it:

```bash
security verify-cert -c ~/.keyclaw/ca.crt -k ~/Library/Keychains/login.keychain-db -p ssl
```

Use the user login keychain path above. The desktop-app trace showed that an incorrect trust-domain shape can still leave Electron/Chromium apps rejecting the KeyClaw CA with certificate-authority errors.

## Enable The System Proxy

Find the active network service if needed:

```bash
route get default
networksetup -listnetworkserviceorder
```

Then enable the proxy on that service. Example for `Wi-Fi`:

```bash
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8877 off
networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8877 off
networksetup -setwebproxystate "Wi-Fi" on
networksetup -setsecurewebproxystate "Wi-Fi" on
networksetup -setproxybypassdomains "Wi-Fi" localhost 127.0.0.1 "*.local" "169.254/16"
```

Check the live state:

```bash
networksetup -getwebproxy "Wi-Fi"
networksetup -getsecurewebproxy "Wi-Fi"
scutil --proxy
```

You want both HTTP and HTTPS proxies enabled and pointing at `127.0.0.1:8877`.

## Relaunch And Verify

Fully quit and relaunch the desktop app after changing the proxy:

```bash
osascript -e 'tell application "Claude" to quit' || true
open -a Claude
```

Use the same pattern for `Codex` or `ChatGPT`.

Useful verification checks:

```bash
keyclaw doctor
keyclaw proxy status
lsof -nP -iTCP:8877
tail -n 50 ~/.keyclaw/audit.log
```

Healthy signs:

- the app or its network helper has a live `127.0.0.1:* -> 127.0.0.1:8877` connection
- `keyclaw proxy status` reports the proxy as healthy
- audit-log entries or runtime logs show real provider hosts instead of only `stdin` or localhost test traffic

## Roll Back

To stop forcing macOS desktop traffic through KeyClaw:

```bash
networksetup -setwebproxystate "Wi-Fi" off
networksetup -setsecurewebproxystate "Wi-Fi" off
```

Then relaunch the desktop app again.

## Notes

- The CLI wrappers remain the simpler and higher-confidence path when they are available.
- Desktop-app support depends on both correct CA trust and a healthy system-proxy listener.
- If traffic still \"feels low,\" inspect `keyclaw proxy stats`, `~/.keyclaw/audit.log`, and runtime logs before assuming detection is broken.
