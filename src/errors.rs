//! Error types and deterministic error-code helpers used throughout KeyClaw.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

/// Error code returned when launched-tool traffic bypasses the proxy.
pub const CODE_MITM_NOT_EFFECTIVE: &str = "mitm_not_effective";
/// Error code returned when a request body exceeds the configured size limit.
pub const CODE_BODY_TOO_LARGE: &str = "body_too_large";
/// Error code returned when JSON rewrite or resolution fails.
pub const CODE_INVALID_JSON: &str = "invalid_json";
/// Error code returned when request body collection times out.
pub const CODE_REQUEST_TIMEOUT: &str = "request_timeout";
/// Error code returned when strict placeholder resolution cannot complete.
pub const CODE_STRICT_RESOLVE_FAILED: &str = "strict_resolve_failed";

#[derive(Debug, Clone)]
pub struct KeyclawError {
    code: Option<String>,
    msg: String,
    source: Option<Arc<dyn Error + Send + Sync>>,
}

/// Standard result alias for functions that return [`KeyclawError`].
pub type Result<T> = std::result::Result<T, KeyclawError>;

impl KeyclawError {
    /// Create an uncoded error with a user-facing message.
    pub fn uncoded(msg: impl Into<String>) -> Self {
        Self {
            code: None,
            msg: msg.into(),
            source: None,
        }
    }

    /// Create an error with a deterministic machine-readable code.
    pub fn coded(code: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            code: Some(code.into()),
            msg: msg.into(),
            source: None,
        }
    }

    /// Create an uncoded error and preserve the original source error.
    pub fn uncoded_with_source<E>(msg: impl Into<String>, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            code: None,
            msg: msg.into(),
            source: Some(Arc::new(source)),
        }
    }

    /// Create a coded error and preserve the original source error.
    pub fn coded_with_source<E>(code: impl Into<String>, msg: impl Into<String>, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            code: Some(code.into()),
            msg: msg.into(),
            source: Some(Arc::new(source)),
        }
    }

    /// Return the deterministic code, if present.
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    /// Render the error without repeating the deterministic code.
    pub fn display_without_code(&self) -> String {
        match (self.msg.is_empty(), self.source.as_ref()) {
            (false, Some(source)) => format!("{}: {}", self.msg, source),
            (false, None) => self.msg.clone(),
            (true, Some(source)) => source.to_string(),
            (true, None) => "keyclaw error".to_string(),
        }
    }
}

impl Display for KeyclawError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match (
            self.code.as_deref(),
            self.msg.is_empty(),
            self.source.as_ref(),
        ) {
            (Some(code), false, Some(source)) => write!(f, "{code}: {}: {}", self.msg, source),
            (Some(code), false, None) => write!(f, "{code}: {}", self.msg),
            (Some(code), true, Some(source)) => write!(f, "{code}: {}", source),
            (Some(code), true, None) => write!(f, "{code}"),
            (None, false, Some(source)) => write!(f, "{}: {}", self.msg, source),
            (None, false, None) => write!(f, "{}", self.msg),
            (None, true, Some(source)) => write!(f, "{source}"),
            (None, true, None) => write!(f, "keyclaw error"),
        }
    }
}

impl Error for KeyclawError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn Error + 'static))
    }
}

/// Walk an error chain and return the first [`KeyclawError`] code encountered.
pub fn code_of<'a>(err: &'a (dyn Error + 'static)) -> Option<&'a str> {
    let mut current = Some(err);
    while let Some(e) = current {
        if let Some(keyclaw_err) = e.downcast_ref::<KeyclawError>() {
            if let Some(code) = keyclaw_err.code() {
                return Some(code);
            }
        }
        current = e.source();
    }
    None
}
