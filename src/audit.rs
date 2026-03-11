use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::errors::KeyclawError;
use crate::placeholder::Replacement;

pub fn default_audit_log_path() -> PathBuf {
    crate::certgen::keyclaw_dir().join("audit.log")
}

pub fn append_redactions(
    path: Option<&Path>,
    request_host: &str,
    replacements: &[Replacement],
) -> Result<(), KeyclawError> {
    let Some(path) = path else {
        return Ok(());
    };
    if replacements.is_empty() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            KeyclawError::uncoded(format!("create audit log dir {}: {err}", parent.display()))
        })?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| {
            KeyclawError::uncoded(format!("open audit log {}: {err}", path.display()))
        })?;

    let ts = current_timestamp_utc();
    for replacement in replacements {
        let line = json!({
            "ts": ts,
            "rule_id": replacement.rule_id,
            "kind": replacement.kind.as_str(),
            "subtype": replacement.subtype,
            "policy": replacement.policy.as_str(),
            "placeholder": replacement.placeholder,
            "request_host": request_host,
            "action": "redacted",
            "match_source": replacement.source.as_str(),
            "confidence": replacement.confidence.as_str(),
            "confidence_score": replacement.confidence_score,
            "decoded_depth": replacement.decoded_depth,
            "entropy": replacement.entropy,
        });
        writeln!(file, "{line}").map_err(|err| {
            KeyclawError::uncoded(format!("write audit log {}: {err}", path.display()))
        })?;
    }

    Ok(())
}

fn current_timestamp_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as libc::time_t;

    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::gmtime_r(&secs, &mut tm).is_null() {
            return "1970-01-01T00:00:00Z".to_string();
        }

        let mut buf = [0u8; 32];
        let format = b"%Y-%m-%dT%H:%M:%SZ\0";
        let written = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            format.as_ptr() as *const libc::c_char,
            &tm,
        );
        if written == 0 {
            return "1970-01-01T00:00:00Z".to_string();
        }
        String::from_utf8_lossy(&buf[..written]).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::append_redactions;
    use crate::placeholder::Replacement;
    use crate::sensitive::{MatchConfidence, MatchSource, ProtectionPolicy, SensitiveKind};

    #[test]
    fn append_redactions_writes_jsonl_without_secret_values() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("audit.log");
        let replacements = vec![Replacement {
            rule_id: "opaque.high_entropy".to_string(),
            kind: SensitiveKind::OpaqueToken,
            subtype: "opaque.high_entropy".to_string(),
            policy: ProtectionPolicy::ReversibleSession,
            id: "deadbeefcafebabe".to_string(),
            placeholder: "{{KEYCLAW_Aa0aA0aA~odeadbeefcafebabe}}".to_string(),
            secret: "raw-secret-value".to_string(),
            source: MatchSource::Regex,
            confidence: MatchConfidence::Medium,
            confidence_score: 66,
            entropy: Some(4.2),
            decoded_depth: 1,
        }];

        append_redactions(Some(&path), "stdin", &replacements).expect("write audit log");

        let log = std::fs::read_to_string(path).expect("read audit log");
        assert!(
            log.contains("\"rule_id\":\"opaque.high_entropy\""),
            "log={log}"
        );
        assert!(log.contains("\"request_host\":\"stdin\""), "log={log}");
        assert!(log.contains("\"confidence\":\"medium\""), "log={log}");
        assert!(log.contains("\"match_source\":\"regex\""), "log={log}");
        assert!(!log.contains("raw-secret-value"), "log={log}");
    }
}
