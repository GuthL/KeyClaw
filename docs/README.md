# KeyClaw Docs

KeyClaw's README is optimized for first contact. This directory holds the deeper operational material that maintainers, reviewers, and security-minded adopters usually ask for next.

## Start Here

- [Architecture overview](architecture.md): request/response flow, major modules, and runtime trust boundaries
- [Configuration reference](configuration.md): config file sections, environment variables, allowlists, audit log behavior, and daemon restart semantics
- [Supported secret patterns](secret-patterns.md): what the bundled rules catch, how entropy detection fits in, and how to add or override rules
- [Threat model](threat-model.md): what KeyClaw protects against, what it does not, and how to deploy it safely

## Source Of Truth

- Bundled detection rules live in [`gitleaks.toml`](../gitleaks.toml)
- Cargo package metadata lives in [`Cargo.toml`](../Cargo.toml)
- Runtime behavior lives under [`src/`](../src)
- Contributor workflows live in [`.github/`](../.github)

## Related Guides

- [README](../README.md): landing page, quickstart, positioning, and top-level operating guide
- [CONTRIBUTING](../CONTRIBUTING.md): contributor workflow and local validation
- [SECURITY](../SECURITY.md): private vulnerability reporting
- [AGENTS](../AGENTS.md) and [CLAUDE](../CLAUDE.md): AI-agent repo guides

## Distribution

- Cargo install path: `cargo install keyclaw`
- Homebrew tap: `brew tap GuthL/tap && brew install keyclaw`
- Homebrew formula source: [`GuthL/homebrew-tap`](https://github.com/GuthL/homebrew-tap)
- GitHub release artifacts: version tags published from [`.github/workflows/release.yml`](../.github/workflows/release.yml)
