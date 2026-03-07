use std::sync::atomic::{AtomicU8, Ordering};

use crate::logscrub;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
}

impl LogLevel {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" | "trace" => Some(Self::Debug),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

static LOG_LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

pub fn configure(level: LogLevel) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn enabled(level: LogLevel) -> bool {
    (level as u8) <= LOG_LEVEL.load(Ordering::Relaxed)
}

pub fn render(level: LogLevel, message: &str) -> String {
    let message = logscrub::scrub(message);
    format!("keyclaw {}: {message}", level.as_str())
}

pub fn render_with_code(level: LogLevel, code: &str, message: &str) -> String {
    let message = logscrub::scrub(message);
    format!("keyclaw {}: {code}: {message}", level.as_str())
}

pub fn emit(level: LogLevel, message: &str) {
    if enabled(level) {
        eprintln!("{}", render(level, message));
    }
}

pub fn emit_with_code(level: LogLevel, code: &str, message: &str) {
    if enabled(level) {
        eprintln!("{}", render_with_code(level, code, message));
    }
}

pub fn info(message: &str) {
    emit(LogLevel::Info, message);
}

pub fn debug(message: &str) {
    emit(LogLevel::Debug, message);
}

pub fn warn(message: &str) {
    emit(LogLevel::Warn, message);
}

pub fn warn_with_code(code: &str, message: &str) {
    emit_with_code(LogLevel::Warn, code, message);
}

pub fn error(message: &str) {
    emit(LogLevel::Error, message);
}

pub fn error_with_code(code: &str, message: &str) {
    emit_with_code(LogLevel::Error, code, message);
}

#[cfg(test)]
mod tests {
    use super::{configure, enabled, render, render_with_code, LogLevel};
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    static LOG_LEVEL_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn parse_accepts_documented_levels() {
        assert_eq!(LogLevel::parse("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::parse("warn"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::parse("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("trace"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("verbose"), None);
    }

    #[test]
    fn render_scrubs_and_formats_messages() {
        let out = render(
            LogLevel::Info,
            "request rewritten: api_key = sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        );

        assert_eq!(out, "keyclaw info: request rewritten: api_key = [redacted]");
    }

    #[test]
    fn render_with_code_scrubs_and_formats_messages() {
        let out = render_with_code(
            LogLevel::Warn,
            "mitm_not_effective",
            "api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v",
        );

        assert_eq!(
            out,
            "keyclaw warn: mitm_not_effective: api_key = [redacted]"
        );
    }

    #[test]
    fn enabled_respects_configured_level() {
        let _guard = LOG_LEVEL_LOCK.lock().expect("log level lock");

        configure(LogLevel::Warn);
        assert!(enabled(LogLevel::Error));
        assert!(enabled(LogLevel::Warn));
        assert!(!enabled(LogLevel::Info));
        assert!(!enabled(LogLevel::Debug));

        configure(LogLevel::Debug);
        assert!(enabled(LogLevel::Info));
        assert!(enabled(LogLevel::Debug));

        configure(LogLevel::Info);
    }
}
