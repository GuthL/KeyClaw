# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows semantic versioning once releases are being cut from tags.

## [Unreleased]

## [0.2.0] - 2026-03-10

### Added

- Public docs hub covering architecture, configuration, secret-pattern coverage, and threat model
- GitHub issue templates and pull request template
- SVG wordmark for the repo landing page
- Built-in interception support for Google, Together, Groq, Mistral, Cohere, and DeepSeek API domains
- Custom host interception via repeated `--include` glob patterns and `KEYCLAW_INCLUDE_HOSTS`
- Optional Kingfisher-backed second-pass detection and audit-log stats summaries

### Changed

- README rewritten around public-facing positioning, faster quickstart, and clearer live-redaction examples
- CI/release workflow presentation cleaned up for public visibility and release badges
- Public Rust API surfaces now carry more useful `cargo doc` output
- Cargo manifest updated for Rust 2024 edition and release-friendly package metadata

## [0.1.0] - 2026-03-10

### Added

- Local MITM proxy for secret-safe AI traffic across HTTP, HTTPS, SSE, and WebSocket flows
- Bundled gitleaks-based secret detection with additional entropy detection for high-entropy tokens
- Deterministic placeholder generation and AES-GCM encrypted local vault storage
- Runtime CA generation, `keyclaw init`, `keyclaw doctor`, and detached proxy workflows
- Proxy lifecycle management including status, stop, and Linux autostart support
- Audit log support, allowlists, and machine-local vault-key generation
- Release packaging scripts and GitHub Actions automation for Linux and macOS binaries

### Changed

- Split proxy and launcher modules into more focused components
- Removed legacy docs references and the old `KEYCLAW_GITLEAKS_BIN` runtime contract

### Fixed

- Improved detector coverage and entropy-driven matching
- Tightened documentation and test coverage around placeholder contracts and module layout
