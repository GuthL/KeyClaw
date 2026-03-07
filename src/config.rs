use std::env;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_VAULT_PASSPHRASE: &str = "keyclaw-default-passphrase";

#[derive(Debug, Clone)]
pub struct Config {
    pub proxy_listen_addr: String,
    pub proxy_url: String,
    pub ca_cert_path: String,
    pub vault_path: PathBuf,
    pub vault_passphrase: String,
    pub fail_closed: bool,
    pub max_body_bytes: i64,
    pub detector_timeout: Duration,
    pub known_codex_hosts: Vec<String>,
    pub known_claude_hosts: Vec<String>,
    pub gitleaks_config_path: Option<PathBuf>,
    pub unsafe_log: bool,
    pub require_mitm_effective: bool,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            proxy_listen_addr: env_or("KEYCLAW_PROXY_ADDR", "127.0.0.1:8877"),
            proxy_url: env_or("KEYCLAW_PROXY_URL", "http://127.0.0.1:8877"),
            ca_cert_path: env_or("KEYCLAW_CA_CERT", ""),
            vault_path: path_env("KEYCLAW_VAULT_PATH").unwrap_or_else(default_vault_path),
            vault_passphrase: env_or("KEYCLAW_VAULT_PASSPHRASE", DEFAULT_VAULT_PASSPHRASE),
            fail_closed: bool_env("KEYCLAW_FAIL_CLOSED", true),
            max_body_bytes: int64_env("KEYCLAW_MAX_BODY_BYTES", 2 * 1024 * 1024),
            detector_timeout: duration_env("KEYCLAW_DETECTOR_TIMEOUT", Duration::from_secs(4)),
            known_codex_hosts: split_csv(&env_or(
                "KEYCLAW_CODEX_HOSTS",
                "api.openai.com,chat.openai.com,chatgpt.com",
            )),
            known_claude_hosts: split_csv(&env_or(
                "KEYCLAW_CLAUDE_HOSTS",
                "api.anthropic.com,claude.ai",
            )),
            gitleaks_config_path: path_env("KEYCLAW_GITLEAKS_CONFIG"),
            unsafe_log: bool_env("KEYCLAW_UNSAFE_LOG", false),
            require_mitm_effective: bool_env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", true),
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

fn env_or(key: &str, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => fallback.to_string(),
    }
}

fn bool_env(key: &str, fallback: bool) -> bool {
    match env::var(key) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "t" | "true" | "y" | "yes" | "on" => true,
            "0" | "f" | "false" | "n" | "no" | "off" => false,
            _ => fallback,
        },
        Err(_) => fallback,
    }
}

fn int64_env(key: &str, fallback: i64) -> i64 {
    match env::var(key) {
        Ok(v) => v.trim().parse::<i64>().unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn path_env(key: &str) -> Option<PathBuf> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(PathBuf::from(v.trim())),
        _ => None,
    }
}

fn duration_env(key: &str, fallback: Duration) -> Duration {
    match env::var(key) {
        Ok(v) => parse_duration(v.trim()).unwrap_or(fallback),
        Err(_) => fallback,
    }
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
        } else if rest.starts_with("µs") {
            ("µs", 1_000.0)
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

    use once_cell::sync::Lazy;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn from_env_includes_documented_runtime_overrides() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let keys = [
            "KEYCLAW_PROXY_ADDR",
            "KEYCLAW_PROXY_URL",
            "KEYCLAW_CA_CERT",
            "KEYCLAW_VAULT_PATH",
            "KEYCLAW_VAULT_PASSPHRASE",
            "KEYCLAW_GITLEAKS_CONFIG",
            "KEYCLAW_UNSAFE_LOG",
            "KEYCLAW_DETECTOR_TIMEOUT",
            "KEYCLAW_GITLEAKS_BIN",
        ];
        let saved = capture_env(&keys);

        env::set_var("KEYCLAW_PROXY_ADDR", "127.0.0.1:9999");
        env::set_var("KEYCLAW_PROXY_URL", "http://127.0.0.1:9999");
        env::set_var("KEYCLAW_CA_CERT", "/tmp/keyclaw-ca.crt");
        env::set_var("KEYCLAW_VAULT_PATH", "/tmp/keyclaw-vault.enc");
        env::set_var("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase");
        env::set_var("KEYCLAW_GITLEAKS_CONFIG", "/tmp/keyclaw-gitleaks.toml");
        env::set_var("KEYCLAW_UNSAFE_LOG", "true");
        env::set_var("KEYCLAW_DETECTOR_TIMEOUT", "250ms");
        env::set_var("KEYCLAW_GITLEAKS_BIN", "/tmp/ignored-gitleaks");

        let cfg = Config::from_env();

        assert_eq!(cfg.proxy_listen_addr, "127.0.0.1:9999");
        assert_eq!(cfg.proxy_url, "http://127.0.0.1:9999");
        assert_eq!(cfg.ca_cert_path, "/tmp/keyclaw-ca.crt");
        assert_eq!(cfg.vault_path, PathBuf::from("/tmp/keyclaw-vault.enc"));
        assert_eq!(cfg.vault_passphrase, "test-passphrase");
        assert_eq!(
            cfg.gitleaks_config_path.as_deref(),
            Some(Path::new("/tmp/keyclaw-gitleaks.toml"))
        );
        assert!(cfg.unsafe_log);
        assert_eq!(cfg.detector_timeout, Duration::from_millis(250));

        restore_env(saved);
    }

    #[test]
    fn from_env_uses_documented_defaults_for_runtime_overrides() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let keys = [
            "HOME",
            "KEYCLAW_VAULT_PATH",
            "KEYCLAW_VAULT_PASSPHRASE",
            "KEYCLAW_GITLEAKS_CONFIG",
            "KEYCLAW_UNSAFE_LOG",
            "KEYCLAW_DETECTOR_TIMEOUT",
        ];
        let saved = capture_env(&keys);

        env::set_var("HOME", "/tmp/keyclaw-home");
        env::remove_var("KEYCLAW_VAULT_PATH");
        env::remove_var("KEYCLAW_VAULT_PASSPHRASE");
        env::remove_var("KEYCLAW_GITLEAKS_CONFIG");
        env::remove_var("KEYCLAW_UNSAFE_LOG");
        env::remove_var("KEYCLAW_DETECTOR_TIMEOUT");

        let cfg = Config::from_env();

        assert_eq!(
            cfg.vault_path,
            PathBuf::from("/tmp/keyclaw-home")
                .join(".keyclaw")
                .join("vault.enc")
        );
        assert_eq!(cfg.vault_passphrase, "keyclaw-default-passphrase");
        assert_eq!(cfg.gitleaks_config_path, None);
        assert!(!cfg.unsafe_log);
        assert_eq!(cfg.detector_timeout, Duration::from_secs(4));

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
}
