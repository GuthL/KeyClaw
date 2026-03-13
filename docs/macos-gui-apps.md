# macOS GUI Apps

The recommended KeyClaw path on macOS is still the CLI wrapper flow:

- `keyclaw codex ...`
- `keyclaw claude ...`

Finder-launched desktop apps need more setup because shell environment injection
is not enough.

## Supported Setup

Use this sequence when you want a GUI app to route traffic through KeyClaw:

1. Run `keyclaw init`.
2. Trust `~/.keyclaw/ca.crt` in the login keychain for SSL inspection.
3. Start a healthy KeyClaw proxy.
4. Point the macOS HTTP and HTTPS system proxy at the KeyClaw listener.
5. Fully relaunch the desktop app.

If one of those steps is missing, the app may bypass KeyClaw entirely or fail
TLS validation.

## Step By Step

### 1. Initialize KeyClaw

```bash
keyclaw init
keyclaw doctor
```

This creates:

- `~/.keyclaw/ca.crt`
- `~/.keyclaw/ca.key`
- `~/.keyclaw/env.sh`

### 2. Trust The CA

Open `~/.keyclaw/ca.crt` in Keychain Access and trust it for SSL in the login
keychain.

`keyclaw doctor` checks this with `security verify-cert`.

### 3. Start The Proxy

Foreground:

```bash
keyclaw proxy start --foreground
```

Detached:

```bash
keyclaw proxy start
```

`keyclaw proxy status` should report the listener as healthy before you proceed.

### 4. Enable The System Proxy

On the active network service, set both:

- HTTP proxy
- HTTPS proxy

to the KeyClaw listener, usually `127.0.0.1:8877`.

`keyclaw doctor` checks the current macOS system proxy settings through
`scutil --proxy`.

### 5. Relaunch The App

Close the GUI app completely and relaunch it after the system proxy is set.

Apps that keep long-lived connections open may not pick up the new proxy until a
full restart.

## Autostart

`keyclaw proxy autostart enable` installs a per-user LaunchAgent:

```text
~/Library/LaunchAgents/com.keyclaw.proxy.plist
```

This keeps the daemon running after login. It does not set the macOS system
proxy for you, and it does not modify existing shell sessions.

## Common Failure Modes

- The app is launched from Finder but the system proxy is still off.
- The CA exists but is not trusted in the login keychain.
- The daemon is not healthy or is bound to a different address than the one
  configured in the macOS system proxy.
- The app was not fully restarted after proxy settings changed.

## Practical Advice

If you control how the app is launched and the app has a CLI entrypoint, prefer
the wrapper path instead of system-wide GUI proxying. The wrapper path is easier
to reason about, easier to disable, and easier to verify with `keyclaw doctor`.
