use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use http_body_util::Full;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{
        header::{CONTENT_TYPE, HOST},
        Request, Response, StatusCode,
    },
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
    Body,
};

use crate::errors::KeyclawError;

static UNSAFE_LOG: AtomicBool = AtomicBool::new(false);
static LOG_FILE: Mutex<Option<File>> = Mutex::new(None);

pub fn set_unsafe_log(enabled: bool) {
    UNSAFE_LOG.store(enabled, Ordering::SeqCst);
}

pub fn set_log_file(path: &std::path::Path) -> std::io::Result<()> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    if let Ok(mut guard) = LOG_FILE.lock() {
        *guard = Some(file);
    }
    Ok(())
}

pub(super) fn build_ca_authority(
    cert_pem: &str,
    key_pem: &str,
) -> Result<RcgenAuthority, KeyclawError> {
    let key_pair = KeyPair::from_pem(key_pem)
        .map_err(|e| KeyclawError::uncoded(format!("parse CA private key failed: {e}")))?;
    let issuer = Issuer::from_ca_cert_pem(cert_pem, key_pair)
        .map_err(|e| KeyclawError::uncoded(format!("parse CA certificate failed: {e}")))?;

    Ok(RcgenAuthority::new(
        issuer,
        1_000,
        aws_lc_rs::default_provider(),
    ))
}

pub(super) fn body_from_vec(bytes: Vec<u8>) -> Body {
    Full::new(hudsucker::hyper::body::Bytes::from(bytes)).into()
}

pub(super) fn response_is_sse(res: &Response<Body>) -> bool {
    res.headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|ct| ct.split(';').next())
        .map(|ct| ct.trim().eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
}

pub(super) fn request_host(req: &Request<Body>) -> Option<String> {
    if let Some(authority) = req.uri().authority() {
        return Some(normalize_host(authority.as_str()));
    }

    header_value(req, HOST.as_str()).map(|v| normalize_host(&v))
}

pub(super) fn header_value(req: &Request<Body>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

pub(super) fn normalize_hosts(hosts: &[String]) -> Vec<String> {
    hosts
        .iter()
        .map(|host| normalize_host(host))
        .filter(|host| !host.is_empty())
        .collect()
}

pub(super) fn allowed(allowed_hosts: &[String], host: &str) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }
    let host = normalize_host(host);
    allowed_hosts
        .iter()
        .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
}

pub(super) fn is_json(content_type: &str) -> bool {
    let content_type = content_type.trim().to_lowercase();
    content_type.is_empty()
        || content_type.contains("application/json")
        || content_type.contains("+json")
}

pub(super) fn is_json_payload(payload: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(payload).is_ok()
}

pub(super) fn json_error_response(status: StatusCode, code: &str, msg: &str) -> Response<Body> {
    let payload = serde_json::json!({"error": {"code": code, "message": msg}});
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());

    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(body_from_vec(body))
        .expect("failed to build proxy error response")
}

pub(super) fn log_replacements(
    host: &str,
    original: &[u8],
    replacements: &[crate::placeholder::Replacement],
) {
    if !unsafe_log_enabled() || replacements.is_empty() {
        return;
    }
    let use_file = LOG_FILE
        .lock()
        .ok()
        .as_ref()
        .is_some_and(|guard| guard.is_some());
    macro_rules! log_out {
        ($($arg:tt)*) => {
            if use_file {
                if let Ok(mut guard) = LOG_FILE.lock() {
                    if let Some(ref mut file) = *guard {
                        let _ = writeln!(file, $($arg)*);
                    }
                }
            } else {
                eprintln!($($arg)*);
            }
        }
    }

    let text = String::from_utf8_lossy(original);
    log_out!(
        "keyclaw [UNSAFE] INTERCEPTIONS for {host} ({} found):",
        replacements.len()
    );
    for replacement in replacements {
        if let Some(pos) = text.find(&replacement.secret) {
            let ctx_start = pos.saturating_sub(100);
            let secret_end = pos + replacement.secret.len();
            let before = truncate_utf8(&text[ctx_start..pos], 100);
            let after_end = std::cmp::min(secret_end + 100, text.len());
            let after = truncate_utf8(&text[secret_end..after_end], 100);
            log_out!(
                "  ...{}[SECRET:{} -> {}]{}...",
                before,
                &replacement.secret[..std::cmp::min(8, replacement.secret.len())],
                replacement.placeholder,
                after
            );
        } else {
            log_out!(
                "  {} -> {}",
                &replacement.secret[..std::cmp::min(8, replacement.secret.len())],
                replacement.placeholder
            );
        }
    }
    log_out!("---");
}

pub(super) fn log_debug(line: String) {
    log_with_level(crate::logging::LogLevel::Debug, line);
}

pub(super) fn log_warn(line: String) {
    log_with_level(crate::logging::LogLevel::Warn, line);
}

fn unsafe_log_enabled() -> bool {
    UNSAFE_LOG.load(Ordering::Relaxed)
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim().trim_matches('.').to_lowercase();
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return addr.ip().to_string();
    }

    if let Some((base, _)) = trimmed.rsplit_once(':') {
        if base.contains('.')
            || base.contains('[')
            || base == "localhost"
            || base.parse::<std::net::IpAddr>().is_ok()
        {
            return base.trim_matches('[').trim_matches(']').to_string();
        }
    }

    trimmed.trim_matches('[').trim_matches(']').to_string()
}

fn log_with_level(level: crate::logging::LogLevel, line: String) {
    if !crate::logging::enabled(level) {
        return;
    }
    let msg = crate::logging::render(level, &line);
    if let Ok(mut guard) = LOG_FILE.lock() {
        if let Some(ref mut file) = *guard {
            let _ = writeln!(file, "{}", msg);
            return;
        }
    }
    eprintln!("{}", msg);
}
