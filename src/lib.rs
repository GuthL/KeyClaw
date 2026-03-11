//! Public library surface for KeyClaw.
//!
//! KeyClaw is a local MITM proxy that rewrites sensitive data out of outbound LLM
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
/// High-entropy token detection used for opaque-token replacement.
pub mod entropy;
/// Error types and deterministic error-code helpers.
pub mod errors;
/// Configured hook actions for request-side events.
pub mod hooks;
/// CLI entrypoints and launched-tool integration.
pub mod launcher;
/// Operator-facing runtime logging utilities.
pub mod logging;
/// Log scrubbing utilities for redacting sensitive values from operator-visible output.
pub mod logscrub;
/// Request rewrite and placeholder-resolution pipeline.
pub mod pipeline;
/// Placeholder generation, parsing, and resolution helpers.
pub mod placeholder;
/// Proxy server entrypoint and handler wiring.
pub mod proxy;
/// JSON-walking utilities and redaction-notice injection.
pub mod redaction;
/// Typed sensitive-data detection and session-scoped storage.
pub mod sensitive;
/// Audit-log backed CLI stats summaries.
pub mod stats;

#[cfg(test)]
pub(crate) mod test_support;

/// Top-level runtime configuration for KeyClaw.
pub use config::Config;
