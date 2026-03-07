# Contributing to KeyClaw

Thanks for your interest in contributing to KeyClaw! This guide will help you get started.

## Development Setup

```bash
git clone https://github.com/GuthL/KeyClaw.git
cd KeyClaw
cargo build
cargo test
```

### Prerequisites

- **Rust 1.75+** (install via [rustup](https://rustup.rs))

No external `gitleaks` binary is required. KeyClaw ships with the bundled ruleset compiled into native Rust regexes; if you want custom detection behavior, point `KEYCLAW_GITLEAKS_CONFIG` at your own `gitleaks.toml`.

## Project Structure

See [CLAUDE.md](CLAUDE.md) for a detailed module map and architecture overview. That file is designed for both humans and AI agents to quickly understand the codebase.

## Making Changes

### Before You Start

1. Check existing [issues](https://github.com/GuthL/KeyClaw/issues) to avoid duplicate work
2. For large changes, open an issue first to discuss the approach

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes
4. Run tests: `cargo test`
5. Run clippy: `cargo clippy`
6. Commit with a clear message
7. Push and open a Pull Request

### Code Style

- Follow standard Rust conventions (`cargo fmt` to format)
- Keep functions focused — prefer small functions over large ones
- Add tests for new detection patterns and policy logic
- Don't add unnecessary dependencies

### Testing

```bash
cargo test              # Run all tests
cargo test -- --nocapture  # See println output
```

When adding new secret patterns, include test cases in `tests/placeholder.rs` that cover:
- Basic detection and replacement
- Edge cases (partial matches, embedded in URLs, etc.)
- Round-trip: detect → placeholder → resolve → original

## Areas for Contribution

### Good First Issues

- Adding new secret detection patterns to `src/placeholder.rs`
- Improving log messages and error descriptions
- Adding configuration options to `src/config.rs`

### Bigger Projects

- **Protocol support** — extending beyond HTTP/WebSocket (e.g., gRPC)
- **CLI improvements** — interactive mode, status dashboard
- **Platform support** — Windows/macOS-specific certificate trust integration
- **Detection improvements** — machine learning based secret detection
- **Response streaming** — handling split placeholders across SSE chunk boundaries

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines. **Do not open a public issue for security vulnerabilities.**

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
