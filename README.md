# KeyClaw

KeyClaw provides a local MITM launcher and payload redaction pipeline for `codex` and `claude` CLI traffic.

## Features

- AES-GCM encrypted secret vault with atomic writes.
- Recursive JSON walker that replaces in-body secrets with placeholders.
- Contract marker injection (`_keyclaw_contract=placeholder:v1`).
- Detector chain: Gitleaks subprocess detector and embedded regex/Aho-Corasick/entropy detector.
- Policy executor with fail-closed defaults and deterministic error codes.
- MITM launchers with proxy+CA env setup, TTY/stdin passthrough, signal forwarding, and exit-code passthrough.
- Hardening with log scrubbing and body size/timeout guards.
- Deterministic error codes: `blocked_by_leak_policy`, `gitleaks_unavailable`, `mitm_not_effective`.

## Quick Start

```bash
cargo build --release
./target/release/keyclaw mitm codex -- codex ...
./target/release/keyclaw mitm claude -- claude ...
```

## Tests

```bash
cargo test
```

## Notes

- `doctor` validates proxy effectiveness and bypass risk (`NO_PROXY=*` or protected hosts in `NO_PROXY`).
- HTTPS `CONNECT` MITM interception is enabled. To inspect live CLI traffic, clients must trust the KeyClaw CA exposed via `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS`.
