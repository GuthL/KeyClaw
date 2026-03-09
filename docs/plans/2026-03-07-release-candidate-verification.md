# KeyClaw Release Candidate Verification

This dry run records the final verification shape for a v0.x release candidate.

## Local Gates

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- `cargo build --release`

## Operator Smoke

- `scripts/smoke-release.sh target/release/keyclaw`
- Confirm `keyclaw proxy` starts the daemon and prints `source ~/.keyclaw/env.sh`
- Confirm `keyclaw proxy stop` shuts the daemon down cleanly
- Confirm `keyclaw codex ...` and `keyclaw claude ...` still route traffic through KeyClaw

## Release Artifacts

- Supported targets remain `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`
- Tagged archives remain `keyclaw-v{version}-{target}.tar.gz`
- `SHA256SUMS` must be generated and verified before publication

## Publication Rehearsal

- `cargo publish --dry-run`
- Review the draft GitHub Release assets before publishing anything publicly
