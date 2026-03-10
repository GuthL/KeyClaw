//! Public library surface for KeyClaw.
//!
//! KeyClaw is a local MITM proxy that rewrites secrets out of outbound LLM
//! traffic before it leaves the machine, then resolves placeholders back into
//! inbound responses for the local client.

/// Operator-controlled allowlist primitives for suppressing known-safe matches.
pub mod allowlist;
/// Persistent audit-log helpers for recording redaction events without raw secrets.
pub mod audit;
/// Runtime CA certificate generation and validation.
pub mod certgen;
/// Runtime configuration loaded from defaults, `~/.keyclaw/config.toml`, and env vars.
pub mod config;
/// High-entropy token detection used alongside provider-specific rules.
pub mod entropy;
/// Error types and deterministic error-code helpers.
pub mod errors;
/// Bundled gitleaks rule loading, compilation, and matching.
pub mod gitleaks_rules;
/// CLI entrypoints and launched-tool integration.
pub mod launcher;
/// Operator-facing runtime logging utilities.
pub mod logging;
/// Log scrubbing utilities for redacting secrets from operator-visible output.
pub mod logscrub;
/// Request rewrite and placeholder-resolution pipeline.
pub mod pipeline;
/// Placeholder generation, parsing, and resolution helpers.
pub mod placeholder;
/// Proxy server entrypoint and handler wiring.
pub mod proxy;
/// JSON-walking utilities and redaction-notice injection.
pub mod redaction;
/// AES-GCM encrypted local secret storage.
pub mod vault;

/// Top-level runtime configuration for KeyClaw.
pub use config::Config;
