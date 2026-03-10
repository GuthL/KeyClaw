# Contributing to KeyClaw

KeyClaw is a local security tool for AI developer workflows. Contributions should preserve the trust boundary, fail-closed behavior, and operator clarity that make the project usable in real environments.

## Before You Start

1. Check existing [issues](https://github.com/GuthL/KeyClaw/issues) to avoid duplicate work.
2. Open an issue before starting large behavioral or architectural changes.
3. Read the [README](README.md), [docs/](docs/README.md), and [SECURITY.md](SECURITY.md) so your changes stay aligned with the published operating model.

## Development Setup

```bash
git clone https://github.com/GuthL/KeyClaw.git
cd KeyClaw
cargo build
cargo test
cargo run -- --help
```

### Prerequisites

- Rust 1.75+ via [rustup](https://rustup.rs)
- No external `gitleaks` binary is required

KeyClaw compiles the bundled [`gitleaks.toml`](gitleaks.toml) rules into native Rust regexes. If you want to test a custom ruleset, point `KEYCLAW_GITLEAKS_CONFIG` at your own TOML file and verify it with `keyclaw doctor`.

## Project Layout

- `src/`: runtime implementation
- `tests/`: unit and integration coverage
- `docs/`: user-facing documentation beyond the README
- `.github/`: CI, release automation, and community templates
- `scripts/`: release packaging and verification helpers

For the codebase module map, see [AGENTS.md](AGENTS.md) or [CLAUDE.md](CLAUDE.md).

## Local Validation

Run these before you open a pull request:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --locked
cargo test --locked -- --test-threads=1
cargo doc --no-deps
```

The test suite includes cases that temporarily override `HOME`, so the documented full-suite command runs the tests serially to avoid cross-test environment races.

If you are changing release packaging, also run:

```bash
scripts/package-release.sh 0.1.0 x86_64-unknown-linux-gnu target/release/keyclaw dist
scripts/verify-release-contract.sh 0.1.0 dist
```

## Documentation Expectations

When you change public behavior, keep the public docs in sync:

- `README.md` for first-run setup, quickstart, positioning, and operator-facing guidance
- `docs/` for deeper reference material such as configuration, architecture, and threat model
- `SECURITY.md` for scope, trust boundary, and reporting guidance
- CLI help text when commands, flags, or workflows change

When you change setup guidance, keep these contracts intact unless the implementation changes intentionally:

- `keyclaw proxy` starts the daemon
- `source ~/.keyclaw/env.sh` wires the shell to the proxy
- Linux autostart keeps the daemon alive across login or reboot, but does not reconfigure existing shells
- `keyclaw doctor` is the primary operator verification path

## Testing Guidance

### General changes

- Add or update tests close to the changed behavior.
- Prefer focused tests over broad incidental coverage.
- Preserve fail-closed behavior unless the change is explicitly about relaxing that policy.

### New secret patterns

When adding new secret detection patterns:

1. Edit [`gitleaks.toml`](gitleaks.toml).
2. Add tests in `tests/placeholder.rs` and, when relevant, `tests/integration_proxy.rs`.
3. If rule loading or compilation behavior must change, update `src/gitleaks_rules.rs`.

Suggested verification:

```bash
cargo test placeholder
cargo test --test integration_proxy
```

In short: **Adding new secret detection patterns to `gitleaks.toml` is the normal path.**

## Pull Requests

- Keep PRs focused and explain the operator or maintainer impact clearly.
- Include the validation commands you ran.
- Update docs and screenshots or SVG assets when the repo-facing experience changes.
- Do not include real secrets, private certificates, or local machine state in commits.

## CI And Releases

GitHub Actions is the release gate for this repository.

- `CI` runs formatting, clippy, build, and test checks on pushes and pull requests
- `Release` builds the supported Linux/macOS archives on version tags and publishes a draft GitHub Release

Maintainers should treat `scripts/package-release.sh`, `scripts/verify-release-contract.sh`, and `.github/workflows/release.yml` as the release source of truth.

## Security

If you discover a security vulnerability, follow [SECURITY.md](SECURITY.md). Do not open a public issue for vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
