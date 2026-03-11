# Contributing to KeyClaw

KeyClaw is a local security tool for AI developer workflows. Contributions
should preserve the local trust boundary, fail-closed defaults, and operator
clarity that make the tool safe to run in real environments.

## Before You Start

1. Check existing [issues](https://github.com/GuthL/KeyClaw/issues).
2. Open an issue before large behavioral or architectural changes.
3. Read [`README.md`](./README.md), [`docs/README.md`](./docs/README.md), and
   [`SECURITY.md`](./SECURITY.md) before changing public behavior.

## Development Setup

```bash
git clone https://github.com/GuthL/KeyClaw.git
cd KeyClaw
cargo build
cargo test
cargo run -- --help
```

Prerequisites:

- Rust 1.75+ through [rustup](https://rustup.rs)
- no external detector binaries for the default runtime

The current sensitive-data engine lives in `src/sensitive.rs`. That file owns:

- detector configuration
- opaque-token detection
- typed structured detectors
- optional classifier wiring
- the session-scoped store used for placeholder resolution

## Project Layout

- `src/`: runtime and CLI implementation
- `tests/`: unit, integration, and end-to-end coverage
- `docs/`: operator and maintainer documentation
- `scripts/`: packaging and release verification helpers
- `.github/`: CI, release automation, and templates

`AGENTS.md` and `CLAUDE.md` contain the synchronized module map for coding
agents.

## Local Validation

### Routine local iteration

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --locked
cargo test --locked
cargo doc --no-deps
```

### Full verification before a pull request

Run the slower daemon and proxy lifecycle tier explicitly before opening a pull
request:

```bash
cargo test --locked --test e2e_cli -- --ignored --test-threads=1
```

The regular `cargo test --locked` loop intentionally skips that ignored tier so
day-to-day iteration stays faster.

If you are changing release packaging or release docs, also run:

```bash
scripts/package-release.sh 0.1.0 x86_64-unknown-linux-gnu target/release/keyclaw dist
scripts/verify-release-contract.sh 0.1.0 dist
```

The maintainer release source of truth is
[`docs/release/maintainer-checklist.md`](./docs/release/maintainer-checklist.md).

## Documentation Expectations

When you change public behavior, update the public docs in the same change:

- `README.md` for first-run guidance and quickstart
- `docs/configuration.md` for config and env surface
- `docs/architecture.md` for runtime flow and trust boundaries
- `docs/secret-patterns.md` for detector behavior
- `docs/threat-model.md` for security framing
- `SECURITY.md` for reporting instructions and high-level scope

## Testing Guidance

### General changes

- add or update tests near the behavior you changed
- prefer focused tests over incidental coverage
- preserve fail-closed behavior unless the change is explicitly about relaxing
  it

### Detection changes

When you change `src/sensitive.rs`, update the detector-facing tests first:

- `tests/placeholder.rs`
- `tests/pipeline.rs`
- `tests/integration_proxy.rs` when end-to-end rewrite or reinjection behavior
  changes

Useful commands:

```bash
cargo test placeholder
cargo test --test pipeline
cargo test --test integration_proxy
```

The normal rule is simple: new detector work should route through
`src/sensitive.rs`, not a parallel detector subsystem.

## Pull Requests

- keep PRs focused
- explain operator impact clearly
- list the validation commands you ran
- update docs when CLI behavior, setup flow, or placeholder behavior changes
- never commit real secrets, private certificates, or local runtime state

## CI And Releases

GitHub Actions is the release gate for this repository.

- `CI` covers the fast loop and the explicit slow e2e tier
- `Release` packages the supported Linux and macOS targets

Maintain crates.io, GitHub release artifacts, and downstream packaging in lock
step. Use
[`docs/release/maintainer-checklist.md`](./docs/release/maintainer-checklist.md)
for versioning, verification, publication, and rollback.

## Security

If you discover a vulnerability, follow [`SECURITY.md`](./SECURITY.md). Do not
open a public issue for security reports.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](./LICENSE).
