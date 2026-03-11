use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

use crate::logging::LogLevel;
use crate::redaction::NoticeMode;

#[derive(Debug, Clone)]
pub struct Config {
    pub proxy_listen_addr: String,
    pub proxy_url: String,
    pub ca_cert_path: String,
    pub vault_path: PathBuf,
    pub vault_passphrase: Option<String>,
    pub fail_closed: bool,
    pub max_body_bytes: i64,
    pub detector_timeout: Duration,
    pub known_codex_hosts: Vec<String>,
    pub known_claude_hosts: Vec<String>,
    pub gitleaks_config_path: Option<PathBuf>,
    pub log_level: LogLevel,
    pub unsafe_log: bool,
    pub require_mitm_effective: bool,
    pub notice_mode: NoticeMode,
    pub entropy_enabled: bool,
    pub entropy_threshold: f64,
    pub entropy_min_len: usize,
}

impl Config {
    pub fn from_env() -> Self {
        let file = load_config_file();

        Self {
            proxy_listen_addr: env_or_file(
                "KEYCLAW_PROXY_ADDR",
                "proxy_addr",
                &file,
                "127.0.0.1:8877",
            ),
            proxy_url: env_or_file(
                "KEYCLAW_PROXY_URL",
                "proxy_url",
                &file,
                "http://127.0.0.1:8877",
            ),
            ca_cert_path: env_or_file("KEYCLAW_CA_CERT", "ca_cert", &file, ""),
            vault_path: path_env_or_file("KEYCLAW_VAULT_PATH", "vault_path", &file)
                .unwrap_or_else(default_vault_path),
            vault_passphrase: optional_env_or_file(
                "KEYCLAW_VAULT_PASSPHRASE",
                "vault_passphrase",
                &file,
            ),
            fail_closed: bool_env_or_file("KEYCLAW_FAIL_CLOSED", "fail_closed", &file, true),
            max_body_bytes: int64_env_or_file(
                "KEYCLAW_MAX_BODY_BYTES",
                "max_body_bytes",
                &file,
                2 * 1024 * 1024,
            ),
            detector_timeout: duration_env_or_file(
                "KEYCLAW_DETECTOR_TIMEOUT",
                "detector_timeout",
                &file,
                Duration::from_secs(4),
            ),
            known_codex_hosts: split_csv(&env_or_file(
                "KEYCLAW_CODEX_HOSTS",
                "codex_hosts",
                &file,
                "api.openai.com,chat.openai.com,chatgpt.com",
            )),
            known_claude_hosts: split_csv(&env_or_file(
                "KEYCLAW_CLAUDE_HOSTS",
                "claude_hosts",
                &file,
                "api.anthropic.com,claude.ai",
            )),
            gitleaks_config_path: path_env_or_file(
                "KEYCLAW_GITLEAKS_CONFIG",
                "gitleaks_config",
                &file,
            ),
            log_level: log_level_env_or_file(
                "KEYCLAW_LOG_LEVEL",
                "log_level",
                &file,
                LogLevel::Info,
            ),
            unsafe_log: bool_env_or_file("KEYCLAW_UNSAFE_LOG", "unsafe_log", &file, false),
            require_mitm_effective: bool_env_or_file(
                "KEYCLAW_REQUIRE_MITM_EFFECTIVE",
                "require_mitm_effective",
                &file,
                true,
            ),
            notice_mode: notice_mode_env_or_file(
                "KEYCLAW_NOTICE_MODE",
                "notice_mode",
                &file,
                NoticeMode::Verbose,
            ),
            entropy_enabled: bool_env_or_file(
                "KEYCLAW_ENTROPY_ENABLED",
                "entropy_enabled",
                &file,
                true,
            ),
            entropy_threshold: f64_env_or_file(
                "KEYCLAW_ENTROPY_THRESHOLD",
                "entropy_threshold",
                &file,
                3.5,
            ),
            entropy_min_len: usize_env_or_file(
                "KEYCLAW_ENTROPY_MIN_LEN",
                "entropy_min_len",
                &file,
                20,
            ),
        }
    }

    pub fn allowed_hosts(tool: &str, cfg: &Config) -> Vec<String> {
        match tool.trim().to_ascii_lowercase().as_str() {
            "codex" => cfg.known_codex_hosts.clone(),
            "claude" => cfg.known_claude_hosts.clone(),
            _ => {
                let mut all = cfg.known_codex_hosts.clone();
                all.extend(cfg.known_claude_hosts.iter().cloned());
                all
            }
        }
    }
}

pub fn allowed_hosts(tool: &str, cfg: &Config) -> Vec<String> {
    Config::allowed_hosts(tool, cfg)
}

// ---------------------------------------------------------------------------
// Config file loading
// ---------------------------------------------------------------------------

type FileMap = HashMap<String, toml::Value>;

fn config_file_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".keyclaw").join("config.toml")
}

fn load_config_file() -> Option<FileMap> {
    let path = config_file_path();
    let content = std::fs::read_to_string(&path).ok()?;
    match content.parse::<toml::Value>() {
        Ok(toml::Value::Table(table)) => {
            let map: FileMap = table.into_iter().collect();
            Some(map)
        }
        Ok(_) => {
            crate::logging::warn(&format!(
                "config file {} is not a TOML table",
                path.display()
            ));
            None
        }
        Err(e) => {
            crate::logging::warn(&format!("failed to parse {}: {e}", path.display()));
            None
        }
    }
}

/// Validate the config file and return the number of keys if it exists.
pub fn validate_config_file() -> Result<Option<usize>, String> {
    let path = config_file_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    match content.parse::<toml::Value>() {
        Ok(toml::Value::Table(table)) => Ok(Some(table.len())),
        Ok(_) => Err(format!(
            "config file {} is not a TOML table",
            path.display()
        )),
        Err(e) => Err(format!("failed to parse {}: {e}", path.display())),
    }
}

// ---------------------------------------------------------------------------
// Helper: read a string value from the file map
// ---------------------------------------------------------------------------

fn file_string(file_key: &str, file: &Option<FileMap>) -> Option<String> {
    let map = file.as_ref()?;
    match map.get(file_key)? {
        toml::Value::String(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        toml::Value::Integer(n) => Some(n.to_string()),
        toml::Value::Float(f) => Some(f.to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// env-or-file helpers (env var > config file > hardcoded default)
// ---------------------------------------------------------------------------

fn env_or_file(key: &str, file_key: &str, file: &Option<FileMap>, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => file_string(file_key, file).unwrap_or_else(|| fallback.to_string()),
    }
}

fn bool_env_or_file(key: &str, file_key: &str, file: &Option<FileMap>, fallback: bool) -> bool {
    if let Ok(v) = env::var(key) {
        return parse_bool_str(v.trim()).unwrap_or(fallback);
    }
    if let Some(map) = file {
        if let Some(toml::Value::Boolean(b)) = map.get(file_key) {
            return *b;
        }
        if let Some(toml::Value::String(s)) = map.get(file_key) {
            if let Some(b) = parse_bool_str(s.trim()) {
                return b;
            }
        }
    }
    fallback
}

fn parse_bool_str(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "y" | "yes" | "on" => Some(true),
        "0" | "f" | "false" | "n" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn int64_env_or_file(key: &str, file_key: &str, file: &Option<FileMap>, fallback: i64) -> i64 {
    if let Ok(v) = env::var(key) {
        return v.trim().parse::<i64>().unwrap_or(fallback);
    }
    if let Some(map) = file {
        if let Some(toml::Value::Integer(n)) = map.get(file_key) {
            return *n;
        }
        if let Some(toml::Value::String(s)) = map.get(file_key) {
            if let Ok(n) = s.trim().parse::<i64>() {
                return n;
            }
        }
    }
    fallback
}

fn f64_env_or_file(key: &str, file_key: &str, file: &Option<FileMap>, fallback: f64) -> f64 {
    if let Ok(v) = env::var(key) {
        return v.trim().parse::<f64>().unwrap_or(fallback);
    }
    if let Some(map) = file {
        if let Some(toml::Value::Float(f)) = map.get(file_key) {
            return *f;
        }
        if let Some(toml::Value::Integer(n)) = map.get(file_key) {
            return *n as f64;
        }
        if let Some(toml::Value::String(s)) = map.get(file_key) {
            if let Ok(f) = s.trim().parse::<f64>() {
                return f;
            }
        }
    }
    fallback
}

fn usize_env_or_file(key: &str, file_key: &str, file: &Option<FileMap>, fallback: usize) -> usize {
    if let Ok(v) = env::var(key) {
        return v.trim().parse::<usize>().unwrap_or(fallback);
    }
    if let Some(map) = file {
        if let Some(toml::Value::Integer(n)) = map.get(file_key) {
            if *n >= 0 {
                return *n as usize;
            }
        }
        if let Some(toml::Value::String(s)) = map.get(file_key) {
            if let Ok(n) = s.trim().parse::<usize>() {
                return n;
            }
        }
    }
    fallback
}

fn path_env_or_file(key: &str, file_key: &str, file: &Option<FileMap>) -> Option<PathBuf> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => return Some(PathBuf::from(v.trim())),
        _ => {}
    }
    file_string(file_key, file).map(PathBuf::from)
}

fn optional_env_or_file(key: &str, file_key: &str, file: &Option<FileMap>) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => return Some(v.trim().to_string()),
        _ => {}
    }
    file_string(file_key, file)
}

fn duration_env_or_file(
    key: &str,
    file_key: &str,
    file: &Option<FileMap>,
    fallback: Duration,
) -> Duration {
    if let Ok(v) = env::var(key) {
        return parse_duration(v.trim()).unwrap_or(fallback);
    }
    if let Some(s) = file_string(file_key, file) {
        return parse_duration(s.trim()).unwrap_or(fallback);
    }
    fallback
}

fn log_level_env_or_file(
    key: &str,
    file_key: &str,
    file: &Option<FileMap>,
    fallback: LogLevel,
) -> LogLevel {
    if let Ok(v) = env::var(key) {
        return LogLevel::parse(v.trim()).unwrap_or(fallback);
    }
    if let Some(s) = file_string(file_key, file) {
        return LogLevel::parse(s.trim()).unwrap_or(fallback);
    }
    fallback
}

fn notice_mode_env_or_file(
    key: &str,
    file_key: &str,
    file: &Option<FileMap>,
    fallback: NoticeMode,
) -> NoticeMode {
    if let Ok(v) = env::var(key) {
        return NoticeMode::parse(v.trim()).unwrap_or(fallback);
    }
    if let Some(s) = file_string(file_key, file) {
        return NoticeMode::parse(s.trim()).unwrap_or(fallback);
    }
    fallback
}

fn split_csv(input: &str) -> Vec<String> {
    if input.trim().is_empty() {
        return Vec::new();
    }

    input
        .split(',')
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty())
        .collect()
}

fn parse_duration(input: &str) -> Option<Duration> {
    if input.is_empty() {
        return None;
    }

    let mut rest = input;
    let mut nanos_total = 0f64;

    while !rest.is_empty() {
        let num_end = rest
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_digit() || *ch == '.')
            .map(|(idx, ch)| idx + ch.len_utf8())
            .last()?;

        let n: f64 = rest[..num_end].parse().ok()?;
        rest = &rest[num_end..];
        if rest.is_empty() {
            return None;
        }

        let (unit, factor_nanos): (&str, f64) = if rest.starts_with("ns") {
            ("ns", 1.0)
        } else if rest.starts_with("us") {
            ("us", 1_000.0)
        } else if rest.starts_with("\u{b5}s") {
            ("\u{b5}s", 1_000.0)
        } else if rest.starts_with("ms") {
            ("ms", 1_000_000.0)
        } else if rest.starts_with('s') {
            ("s", 1_000_000_000.0)
        } else if rest.starts_with('m') {
            ("m", 60.0 * 1_000_000_000.0)
        } else if rest.starts_with('h') {
            ("h", 3600.0 * 1_000_000_000.0)
        } else {
            return None;
        };

        nanos_total += n * factor_nanos;
        rest = &rest[unit.len()..];
    }

    if !nanos_total.is_finite() || nanos_total < 0.0 {
        return None;
    }

    let nanos_total = nanos_total.round() as u128;
    let secs = nanos_total / 1_000_000_000;
    let nanos = (nanos_total % 1_000_000_000) as u32;
    if secs > u64::MAX as u128 {
        return None;
    }
    Some(Duration::new(secs as u64, nanos))
}

fn default_vault_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".keyclaw").join("vault.enc")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::PROCESS_ENV_LOCK;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn from_env_includes_documented_runtime_overrides() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let keys = [
            "KEYCLAW_PROXY_ADDR",
            "KEYCLAW_PROXY_URL",
            "KEYCLAW_CA_CERT",
            "KEYCLAW_VAULT_PATH",
            "KEYCLAW_VAULT_PASSPHRASE",
            "KEYCLAW_GITLEAKS_CONFIG",
            "KEYCLAW_LOG_LEVEL",
            "KEYCLAW_UNSAFE_LOG",
            "KEYCLAW_DETECTOR_TIMEOUT",
            "KEYCLAW_NOTICE_MODE",
        ];
        let saved = capture_env(&keys);

        env::set_var("KEYCLAW_PROXY_ADDR", "127.0.0.1:9999");
        env::set_var("KEYCLAW_PROXY_URL", "http://127.0.0.1:9999");
        env::set_var("KEYCLAW_CA_CERT", "/tmp/keyclaw-ca.crt");
        env::set_var("KEYCLAW_VAULT_PATH", "/tmp/keyclaw-vault.enc");
        env::set_var("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase");
        env::set_var("KEYCLAW_GITLEAKS_CONFIG", "/tmp/keyclaw-gitleaks.toml");
        env::set_var("KEYCLAW_LOG_LEVEL", "debug");
        env::set_var("KEYCLAW_UNSAFE_LOG", "true");
        env::set_var("KEYCLAW_DETECTOR_TIMEOUT", "250ms");
        env::set_var("KEYCLAW_NOTICE_MODE", "minimal");

        let cfg = Config::from_env();

        assert_eq!(cfg.proxy_listen_addr, "127.0.0.1:9999");
        assert_eq!(cfg.proxy_url, "http://127.0.0.1:9999");
        assert_eq!(cfg.ca_cert_path, "/tmp/keyclaw-ca.crt");
        assert_eq!(cfg.vault_path, PathBuf::from("/tmp/keyclaw-vault.enc"));
        assert_eq!(cfg.vault_passphrase.as_deref(), Some("test-passphrase"));
        assert_eq!(
            cfg.gitleaks_config_path.as_deref(),
            Some(Path::new("/tmp/keyclaw-gitleaks.toml"))
        );
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert!(cfg.unsafe_log);
        assert_eq!(cfg.detector_timeout, Duration::from_millis(250));
        assert_eq!(cfg.notice_mode, NoticeMode::Minimal);

        restore_env(saved);
    }

    #[test]
    fn from_env_uses_documented_defaults_for_runtime_overrides() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let keys = [
            "HOME",
            "KEYCLAW_VAULT_PATH",
            "KEYCLAW_VAULT_PASSPHRASE",
            "KEYCLAW_GITLEAKS_CONFIG",
            "KEYCLAW_LOG_LEVEL",
            "KEYCLAW_UNSAFE_LOG",
            "KEYCLAW_DETECTOR_TIMEOUT",
            "KEYCLAW_NOTICE_MODE",
        ];
        let saved = capture_env(&keys);

        env::set_var("HOME", "/tmp/keyclaw-home");
        env::remove_var("KEYCLAW_VAULT_PATH");
        env::remove_var("KEYCLAW_VAULT_PASSPHRASE");
        env::remove_var("KEYCLAW_GITLEAKS_CONFIG");
        env::remove_var("KEYCLAW_LOG_LEVEL");
        env::remove_var("KEYCLAW_UNSAFE_LOG");
        env::remove_var("KEYCLAW_DETECTOR_TIMEOUT");
        env::remove_var("KEYCLAW_NOTICE_MODE");

        let cfg = Config::from_env();

        assert_eq!(
            cfg.vault_path,
            PathBuf::from("/tmp/keyclaw-home")
                .join(".keyclaw")
                .join("vault.enc")
        );
        assert_eq!(cfg.vault_passphrase, None);
        assert_eq!(cfg.gitleaks_config_path, None);
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert!(!cfg.unsafe_log);
        assert_eq!(cfg.detector_timeout, Duration::from_secs(4));
        assert_eq!(cfg.notice_mode, NoticeMode::Verbose);

        restore_env(saved);
    }

    #[test]
    fn from_env_reads_entropy_settings() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let keys = [
            "KEYCLAW_ENTROPY_ENABLED",
            "KEYCLAW_ENTROPY_THRESHOLD",
            "KEYCLAW_ENTROPY_MIN_LEN",
        ];
        let saved = capture_env(&keys);
        env::set_var("KEYCLAW_ENTROPY_ENABLED", "false");
        env::set_var("KEYCLAW_ENTROPY_THRESHOLD", "4.0");
        env::set_var("KEYCLAW_ENTROPY_MIN_LEN", "30");
        let cfg = Config::from_env();
        assert!(!cfg.entropy_enabled);
        assert!((cfg.entropy_threshold - 4.0).abs() < 0.001);
        assert_eq!(cfg.entropy_min_len, 30);
        restore_env(saved);
    }

    #[test]
    fn from_env_uses_entropy_defaults() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let keys = [
            "KEYCLAW_ENTROPY_ENABLED",
            "KEYCLAW_ENTROPY_THRESHOLD",
            "KEYCLAW_ENTROPY_MIN_LEN",
        ];
        let saved = capture_env(&keys);
        env::remove_var("KEYCLAW_ENTROPY_ENABLED");
        env::remove_var("KEYCLAW_ENTROPY_THRESHOLD");
        env::remove_var("KEYCLAW_ENTROPY_MIN_LEN");
        let cfg = Config::from_env();
        assert!(cfg.entropy_enabled);
        assert!((cfg.entropy_threshold - 3.5).abs() < 0.001);
        assert_eq!(cfg.entropy_min_len, 20);
        restore_env(saved);
    }

    fn capture_env(keys: &[&str]) -> Vec<(String, Option<OsString>)> {
        keys.iter()
            .map(|key| ((*key).to_string(), env::var_os(key)))
            .collect()
    }

    fn restore_env(saved: Vec<(String, Option<OsString>)>) {
        for (key, value) in saved {
            match value {
                Some(value) => env::set_var(key, value),
                None => env::remove_var(key),
            }
        }
    }

    fn all_env_keys() -> Vec<&'static str> {
        vec![
            "HOME",
            "KEYCLAW_PROXY_ADDR",
            "KEYCLAW_PROXY_URL",
            "KEYCLAW_CA_CERT",
            "KEYCLAW_VAULT_PATH",
            "KEYCLAW_VAULT_PASSPHRASE",
            "KEYCLAW_FAIL_CLOSED",
            "KEYCLAW_MAX_BODY_BYTES",
            "KEYCLAW_DETECTOR_TIMEOUT",
            "KEYCLAW_CODEX_HOSTS",
            "KEYCLAW_CLAUDE_HOSTS",
            "KEYCLAW_GITLEAKS_CONFIG",
            "KEYCLAW_LOG_LEVEL",
            "KEYCLAW_UNSAFE_LOG",
            "KEYCLAW_REQUIRE_MITM_EFFECTIVE",
            "KEYCLAW_NOTICE_MODE",
            "KEYCLAW_ENTROPY_ENABLED",
            "KEYCLAW_ENTROPY_THRESHOLD",
            "KEYCLAW_ENTROPY_MIN_LEN",
        ]
    }

    #[test]
    fn from_env_reads_config_file_values() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let all_keys = all_env_keys();
        let saved = capture_env(&all_keys);

        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        let keyclaw_dir = home.join(".keyclaw");
        std::fs::create_dir_all(&keyclaw_dir).expect("mkdir");

        let config_content = r#"
proxy_addr = "127.0.0.1:7777"
proxy_url = "http://127.0.0.1:7777"
fail_closed = false
max_body_bytes = 1048576
detector_timeout = "2s"
log_level = "debug"
notice_mode = "minimal"
entropy_threshold = 4.2
entropy_min_len = 25
entropy_enabled = false
unsafe_log = true
"#;
        std::fs::write(keyclaw_dir.join("config.toml"), config_content).expect("write config");

        env::set_var("HOME", home.to_str().unwrap());
        for key in &all_keys[1..] {
            env::remove_var(key);
        }

        let cfg = Config::from_env();

        assert_eq!(cfg.proxy_listen_addr, "127.0.0.1:7777");
        assert_eq!(cfg.proxy_url, "http://127.0.0.1:7777");
        assert!(!cfg.fail_closed);
        assert_eq!(cfg.max_body_bytes, 1_048_576);
        assert_eq!(cfg.detector_timeout, Duration::from_secs(2));
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert_eq!(cfg.notice_mode, NoticeMode::Minimal);
        assert!((cfg.entropy_threshold - 4.2).abs() < 0.001);
        assert_eq!(cfg.entropy_min_len, 25);
        assert!(!cfg.entropy_enabled);
        assert!(cfg.unsafe_log);

        restore_env(saved);
    }

    #[test]
    fn env_vars_override_config_file() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let all_keys = all_env_keys();
        let saved = capture_env(&all_keys);

        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        let keyclaw_dir = home.join(".keyclaw");
        std::fs::create_dir_all(&keyclaw_dir).expect("mkdir");

        let config_content = r#"
proxy_addr = "127.0.0.1:7777"
log_level = "debug"
fail_closed = false
"#;
        std::fs::write(keyclaw_dir.join("config.toml"), config_content).expect("write config");

        env::set_var("HOME", home.to_str().unwrap());
        for key in &all_keys[1..] {
            env::remove_var(key);
        }
        env::set_var("KEYCLAW_PROXY_ADDR", "127.0.0.1:9999");
        env::set_var("KEYCLAW_LOG_LEVEL", "warn");
        env::set_var("KEYCLAW_FAIL_CLOSED", "true");

        let cfg = Config::from_env();

        assert_eq!(cfg.proxy_listen_addr, "127.0.0.1:9999");
        assert_eq!(cfg.log_level, LogLevel::Warn);
        assert!(cfg.fail_closed);

        restore_env(saved);
    }

    #[test]
    fn missing_config_file_uses_defaults() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let all_keys = all_env_keys();
        let saved = capture_env(&all_keys);

        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();

        env::set_var("HOME", home.to_str().unwrap());
        for key in &all_keys[1..] {
            env::remove_var(key);
        }

        let cfg = Config::from_env();

        assert_eq!(cfg.proxy_listen_addr, "127.0.0.1:8877");
        assert_eq!(cfg.proxy_url, "http://127.0.0.1:8877");
        assert!(cfg.fail_closed);
        assert_eq!(cfg.max_body_bytes, 2 * 1024 * 1024);
        assert_eq!(cfg.log_level, LogLevel::Info);

        restore_env(saved);
    }

    #[test]
    fn validate_config_file_returns_key_count() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let saved = capture_env(&["HOME"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        let keyclaw_dir = home.join(".keyclaw");
        std::fs::create_dir_all(&keyclaw_dir).expect("mkdir");
        std::fs::write(
            keyclaw_dir.join("config.toml"),
            "proxy_addr = \"127.0.0.1:7777\"\nlog_level = \"debug\"\n",
        )
        .expect("write");

        env::set_var("HOME", home.to_str().unwrap());
        let result = validate_config_file();
        assert_eq!(result, Ok(Some(2)));

        restore_env(saved);
    }

    #[test]
    fn validate_config_file_returns_none_when_missing() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let saved = capture_env(&["HOME"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        env::set_var("HOME", tmp.path().to_str().unwrap());

        let result = validate_config_file();
        assert_eq!(result, Ok(None));

        restore_env(saved);
    }

    #[test]
    fn validate_config_file_returns_err_on_bad_toml() {
        let _guard = PROCESS_ENV_LOCK.lock().expect("env lock");
        let saved = capture_env(&["HOME"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        let keyclaw_dir = home.join(".keyclaw");
        std::fs::create_dir_all(&keyclaw_dir).expect("mkdir");
        std::fs::write(keyclaw_dir.join("config.toml"), "not valid [ toml @@").expect("write");

        env::set_var("HOME", home.to_str().unwrap());
        let result = validate_config_file();
        assert!(result.is_err());

        restore_env(saved);
    }
}
