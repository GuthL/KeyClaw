//! Runtime configuration loaded from defaults, an optional TOML file, and
//! environment variable overrides.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::allowlist::Allowlist;
use crate::logging::LogLevel;
use crate::redaction::NoticeMode;

#[derive(Debug, Clone)]
pub struct Config {
    /// Local bind address for the MITM proxy daemon.
    pub proxy_listen_addr: String,
    /// Proxy URL exported to child processes and env scripts.
    pub proxy_url: String,
    /// CA certificate path passed to clients that need explicit trust wiring.
    pub ca_cert_path: String,
    /// Encrypted vault location on disk.
    pub vault_path: PathBuf,
    /// Optional explicit passphrase override for the vault.
    pub vault_passphrase: Option<String>,
    /// Whether request processing should fail closed on rewrite errors.
    pub fail_closed: bool,
    /// Maximum request body size accepted for inspection.
    pub max_body_bytes: i64,
    /// Timeout for reading and inspecting request bodies.
    pub detector_timeout: Duration,
    /// Hostnames considered in-scope for Codex/OpenAI traffic.
    pub known_codex_hosts: Vec<String>,
    /// Hostnames considered in-scope for Claude/Anthropic traffic.
    pub known_claude_hosts: Vec<String>,
    /// Hostnames considered in-scope across supported provider APIs.
    pub known_provider_hosts: Vec<String>,
    /// Additional exact hosts or glob patterns to intercept.
    pub include_hosts: Vec<String>,
    /// Optional custom gitleaks rule file.
    pub gitleaks_config_path: Option<PathBuf>,
    /// Operator-visible runtime log level.
    pub log_level: LogLevel,
    /// Whether raw logs may include unsanitized secret material.
    pub unsafe_log: bool,
    /// Whether launched-tool flows should fail if traffic bypasses the proxy.
    pub require_mitm_effective: bool,
    /// Redaction notice mode injected into rewritten payloads.
    pub notice_mode: NoticeMode,
    /// Whether rewrite flows should report matches without modifying traffic.
    pub dry_run: bool,
    /// Whether entropy detection is enabled.
    pub entropy_enabled: bool,
    /// Minimum entropy threshold for entropy-driven matches.
    pub entropy_threshold: f64,
    /// Minimum token length for entropy-driven matches.
    pub entropy_min_len: usize,
    /// Optional audit log location. `None` disables persistent audit logging.
    pub audit_log_path: Option<PathBuf>,
    /// Operator-defined allowlist entries.
    pub allowlist: Allowlist,
    pub(crate) config_file_status: ConfigFileStatus,
}

#[derive(Debug, Clone)]
pub(crate) enum ConfigFileStatus {
    Missing(PathBuf),
    Loaded(PathBuf),
    Invalid { path: PathBuf, message: String },
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    proxy: FileProxyConfig,
    vault: FileVaultConfig,
    logging: FileLoggingConfig,
    notice: FileNoticeConfig,
    detection: FileDetectionConfig,
    audit: FileAuditConfig,
    hosts: FileHostsConfig,
    allowlist: FileAllowlistConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileProxyConfig {
    addr: Option<String>,
    url: Option<String>,
    ca_cert: Option<String>,
    require_mitm_effective: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileVaultConfig {
    path: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileLoggingConfig {
    level: Option<String>,
    unsafe_log: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileNoticeConfig {
    mode: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileDetectionConfig {
    fail_closed: Option<bool>,
    dry_run: Option<bool>,
    max_body_bytes: Option<i64>,
    detector_timeout: Option<String>,
    gitleaks_config: Option<PathBuf>,
    entropy_enabled: Option<bool>,
    entropy_threshold: Option<f64>,
    entropy_min_len: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileAuditConfig {
    path: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileHostsConfig {
    codex: Option<Vec<String>>,
    claude: Option<Vec<String>>,
    providers: Option<Vec<String>>,
    include: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileAllowlistConfig {
    rule_ids: Vec<String>,
    patterns: Vec<String>,
    secret_sha256: Vec<String>,
}

impl Config {
    /// Load configuration from defaults, `~/.keyclaw/config.toml`, and
    /// environment variable overrides.
    pub fn from_env() -> Self {
        let mut cfg = Self::defaults();
        cfg.apply_config_file();
        cfg.apply_env_overrides();
        cfg
    }

    /// Return the currently allowed hosts for the named tool family.
    ///
    /// Tool-specific lookups include the corresponding first-class tool
    /// hosts, the shared provider host list, and any custom includes. Any
    /// other value returns the union of all shipped hosts plus custom
    /// includes.
    pub fn allowed_hosts(tool: &str, cfg: &Config) -> Vec<String> {
        let mut allowed = match tool.trim().to_ascii_lowercase().as_str() {
            "codex" => {
                let mut hosts = cfg.known_codex_hosts.clone();
                hosts.extend(cfg.known_provider_hosts.iter().cloned());
                hosts
            }
            "claude" => {
                let mut hosts = cfg.known_claude_hosts.clone();
                hosts.extend(cfg.known_provider_hosts.iter().cloned());
                hosts
            }
            _ => {
                let mut all = cfg.known_codex_hosts.clone();
                all.extend(cfg.known_claude_hosts.iter().cloned());
                all.extend(cfg.known_provider_hosts.iter().cloned());
                all
            }
        };
        allowed.extend(cfg.include_hosts.iter().cloned());
        dedup_hosts(allowed)
    }

    pub(crate) fn config_file_status(&self) -> &ConfigFileStatus {
        &self.config_file_status
    }

    /// Return a user-facing error if the optional config file exists but is
    /// invalid.
    pub fn config_file_error(&self) -> Option<crate::errors::KeyclawError> {
        match &self.config_file_status {
            ConfigFileStatus::Invalid { message, .. } => {
                Some(crate::errors::KeyclawError::uncoded(message.clone()))
            }
            _ => None,
        }
    }

    fn defaults() -> Self {
        Self {
            proxy_listen_addr: "127.0.0.1:8877".to_string(),
            proxy_url: "http://127.0.0.1:8877".to_string(),
            ca_cert_path: String::new(),
            vault_path: default_vault_path(),
            vault_passphrase: None,
            fail_closed: true,
            max_body_bytes: 2 * 1024 * 1024,
            detector_timeout: Duration::from_secs(4),
            known_codex_hosts: default_codex_hosts(),
            known_claude_hosts: default_claude_hosts(),
            known_provider_hosts: default_provider_hosts(),
            include_hosts: Vec::new(),
            gitleaks_config_path: None,
            log_level: LogLevel::Info,
            unsafe_log: false,
            require_mitm_effective: true,
            notice_mode: NoticeMode::Verbose,
            dry_run: false,
            entropy_enabled: true,
            entropy_threshold: 3.5,
            entropy_min_len: 20,
            audit_log_path: Some(crate::audit::default_audit_log_path()),
            allowlist: Allowlist::default(),
            config_file_status: ConfigFileStatus::Missing(default_config_path()),
        }
    }

    fn apply_config_file(&mut self) {
        let path = default_config_path();
        self.config_file_status = ConfigFileStatus::Missing(path.clone());

        match load_config_file(&path) {
            Ok(Some(file_cfg)) => {
                let mut candidate = self.clone();
                match candidate.apply_file_config(&file_cfg, &path) {
                    Ok(()) => {
                        *self = candidate;
                        self.config_file_status = ConfigFileStatus::Loaded(path);
                    }
                    Err(err) => {
                        self.config_file_status = ConfigFileStatus::Invalid { path, message: err };
                    }
                }
            }
            Ok(None) => {}
            Err(err) => {
                self.config_file_status = ConfigFileStatus::Invalid { path, message: err };
            }
        }
    }

    fn apply_file_config(
        &mut self,
        file_cfg: &FileConfig,
        path: &Path,
    ) -> std::result::Result<(), String> {
        if let Some(addr) = &file_cfg.proxy.addr {
            self.proxy_listen_addr = addr.trim().to_string();
        }
        if let Some(url) = &file_cfg.proxy.url {
            self.proxy_url = url.trim().to_string();
        }
        if let Some(ca_cert) = &file_cfg.proxy.ca_cert {
            self.ca_cert_path = ca_cert.trim().to_string();
        }
        if let Some(require_mitm_effective) = file_cfg.proxy.require_mitm_effective {
            self.require_mitm_effective = require_mitm_effective;
        }
        if let Some(vault_path) = &file_cfg.vault.path {
            self.vault_path = vault_path.clone();
        }
        if let Some(level) = file_cfg.logging.level.as_deref() {
            self.log_level = LogLevel::parse(level).ok_or_else(|| {
                format!(
                    "config file {} has invalid logging.level `{level}`",
                    path.display()
                )
            })?;
        }
        if let Some(unsafe_log) = file_cfg.logging.unsafe_log {
            self.unsafe_log = unsafe_log;
        }
        if let Some(mode) = file_cfg.notice.mode.as_deref() {
            self.notice_mode = NoticeMode::parse(mode).ok_or_else(|| {
                format!(
                    "config file {} has invalid notice.mode `{mode}`",
                    path.display()
                )
            })?;
        }
        if let Some(fail_closed) = file_cfg.detection.fail_closed {
            self.fail_closed = fail_closed;
        }
        if let Some(dry_run) = file_cfg.detection.dry_run {
            self.dry_run = dry_run;
        }
        if let Some(max_body_bytes) = file_cfg.detection.max_body_bytes {
            self.max_body_bytes = max_body_bytes;
        }
        if let Some(timeout) = file_cfg.detection.detector_timeout.as_deref() {
            self.detector_timeout = parse_duration(timeout).ok_or_else(|| {
                format!(
                    "config file {} has invalid detection.detector_timeout `{timeout}`",
                    path.display()
                )
            })?;
        }
        if let Some(gitleaks_config) = &file_cfg.detection.gitleaks_config {
            self.gitleaks_config_path = Some(gitleaks_config.clone());
        }
        if let Some(entropy_enabled) = file_cfg.detection.entropy_enabled {
            self.entropy_enabled = entropy_enabled;
        }
        if let Some(entropy_threshold) = file_cfg.detection.entropy_threshold {
            self.entropy_threshold = entropy_threshold;
        }
        if let Some(entropy_min_len) = file_cfg.detection.entropy_min_len {
            self.entropy_min_len = entropy_min_len;
        }
        if let Some(audit_path) = file_cfg.audit.path.as_deref() {
            self.audit_log_path = parse_audit_log_setting(audit_path).map_err(|err| {
                format!(
                    "config file {} has invalid audit.path: {err}",
                    path.display()
                )
            })?;
        }
        if let Some(codex_hosts) = &file_cfg.hosts.codex {
            self.known_codex_hosts = normalize_host_list(codex_hosts);
        }
        if let Some(claude_hosts) = &file_cfg.hosts.claude {
            self.known_claude_hosts = normalize_host_list(claude_hosts);
        }
        if let Some(provider_hosts) = &file_cfg.hosts.providers {
            self.known_provider_hosts = normalize_host_list(provider_hosts);
        }
        if let Some(include_hosts) = &file_cfg.hosts.include {
            self.include_hosts = normalize_host_list(include_hosts);
        }
        self.allowlist = Allowlist::from_parts(
            &file_cfg.allowlist.rule_ids,
            &file_cfg.allowlist.patterns,
            &file_cfg.allowlist.secret_sha256,
        )
        .map_err(|err| format!("config file {} has invalid {err}", path.display()))?;

        Ok(())
    }

    fn apply_env_overrides(&mut self) {
        self.proxy_listen_addr = env_or("KEYCLAW_PROXY_ADDR", &self.proxy_listen_addr);
        self.proxy_url = env_or("KEYCLAW_PROXY_URL", &self.proxy_url);
        self.ca_cert_path = env_or("KEYCLAW_CA_CERT", &self.ca_cert_path);
        self.vault_path = path_env("KEYCLAW_VAULT_PATH").unwrap_or_else(|| self.vault_path.clone());
        self.vault_passphrase = optional_env("KEYCLAW_VAULT_PASSPHRASE");
        self.fail_closed = bool_env("KEYCLAW_FAIL_CLOSED", self.fail_closed);
        self.max_body_bytes = int64_env("KEYCLAW_MAX_BODY_BYTES", self.max_body_bytes);
        self.detector_timeout = duration_env("KEYCLAW_DETECTOR_TIMEOUT", self.detector_timeout);
        self.known_codex_hosts = env_csv_or("KEYCLAW_CODEX_HOSTS", &self.known_codex_hosts);
        self.known_claude_hosts = env_csv_or("KEYCLAW_CLAUDE_HOSTS", &self.known_claude_hosts);
        self.known_provider_hosts =
            env_csv_or("KEYCLAW_PROVIDER_HOSTS", &self.known_provider_hosts);
        self.include_hosts = env_csv_or("KEYCLAW_INCLUDE_HOSTS", &self.include_hosts);
        self.gitleaks_config_path =
            path_env("KEYCLAW_GITLEAKS_CONFIG").or_else(|| self.gitleaks_config_path.clone());
        self.log_level = log_level_env("KEYCLAW_LOG_LEVEL", self.log_level);
        self.unsafe_log = bool_env("KEYCLAW_UNSAFE_LOG", self.unsafe_log);
        self.require_mitm_effective = bool_env(
            "KEYCLAW_REQUIRE_MITM_EFFECTIVE",
            self.require_mitm_effective,
        );
        self.notice_mode = notice_mode_env("KEYCLAW_NOTICE_MODE", self.notice_mode);
        self.dry_run = bool_env("KEYCLAW_DRY_RUN", self.dry_run);
        self.entropy_enabled = bool_env("KEYCLAW_ENTROPY_ENABLED", self.entropy_enabled);
        self.entropy_threshold = f64_env("KEYCLAW_ENTROPY_THRESHOLD", self.entropy_threshold);
        self.entropy_min_len = usize_env("KEYCLAW_ENTROPY_MIN_LEN", self.entropy_min_len);
        self.audit_log_path = audit_log_env("KEYCLAW_AUDIT_LOG", self.audit_log_path.clone());
    }

    pub(crate) fn add_include_hosts(&mut self, include_hosts: Vec<String>) {
        self.include_hosts
            .extend(normalize_host_list(&include_hosts));
        self.include_hosts = dedup_hosts(std::mem::take(&mut self.include_hosts));
    }

    pub(crate) fn include_hosts(&self) -> &[String] {
        &self.include_hosts
    }
}

/// Convenience wrapper for [`Config::allowed_hosts`].
pub fn allowed_hosts(tool: &str, cfg: &Config) -> Vec<String> {
    Config::allowed_hosts(tool, cfg)
}

/// Return the default `~/.keyclaw/config.toml` path for the current user.
pub fn default_config_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".keyclaw").join("config.toml")
}

fn env_or(key: &str, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => fallback.to_string(),
    }
}

fn env_csv_or(key: &str, fallback: &[String]) -> Vec<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => split_csv(&v),
        _ => fallback.to_vec(),
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

fn log_level_env(key: &str, fallback: LogLevel) -> LogLevel {
    match env::var(key) {
        Ok(v) => LogLevel::parse(v.trim()).unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn notice_mode_env(key: &str, fallback: NoticeMode) -> NoticeMode {
    match env::var(key) {
        Ok(v) => NoticeMode::parse(v.trim()).unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn f64_env(key: &str, fallback: f64) -> f64 {
    match env::var(key) {
        Ok(v) => v.trim().parse::<f64>().unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn usize_env(key: &str, fallback: usize) -> usize {
    match env::var(key) {
        Ok(v) => v.trim().parse::<usize>().unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn path_env(key: &str) -> Option<PathBuf> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(PathBuf::from(v.trim())),
        _ => None,
    }
}

fn optional_env(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        _ => None,
    }
}

fn duration_env(key: &str, fallback: Duration) -> Duration {
    match env::var(key) {
        Ok(v) => parse_duration(v.trim()).unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn audit_log_env(key: &str, fallback: Option<PathBuf>) -> Option<PathBuf> {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => parse_audit_log_setting(v.trim()).unwrap_or(fallback),
        _ => fallback,
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

fn normalize_host_list(hosts: &[String]) -> Vec<String> {
    hosts
        .iter()
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

fn dedup_hosts(hosts: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for host in hosts {
        if seen.insert(host.clone()) {
            deduped.push(host);
        }
    }
    deduped
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

fn default_codex_hosts() -> Vec<String> {
    split_csv("api.openai.com,chat.openai.com,chatgpt.com")
}

fn default_claude_hosts() -> Vec<String> {
    split_csv("api.anthropic.com,claude.ai")
}

fn default_provider_hosts() -> Vec<String> {
    split_csv(
        "generativelanguage.googleapis.com,api.together.xyz,api.groq.com,api.mistral.ai,api.cohere.ai,api.deepseek.com",
    )
}

fn parse_audit_log_setting(input: &str) -> Result<Option<PathBuf>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty()
        || matches!(
            trimmed.to_ascii_lowercase().as_str(),
            "off" | "none" | "disabled" | "false"
        )
    {
        return Ok(None);
    }

    Ok(Some(PathBuf::from(trimmed)))
}

fn load_config_file(path: &Path) -> std::result::Result<Option<FileConfig>, String> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("cannot read config file {}: {err}", path.display())),
    };

    toml::from_str::<FileConfig>(&raw)
        .map(Some)
        .map_err(|err| format!("cannot parse config file {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use once_cell::sync::Lazy;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn set_env_var<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>>(key: K, value: V) {
        // These tests serialize process-wide environment mutation with ENV_LOCK.
        unsafe { env::set_var(key, value) }
    }

    fn remove_env_var<K: AsRef<std::ffi::OsStr>>(key: K) {
        // These tests serialize process-wide environment mutation with ENV_LOCK.
        unsafe { env::remove_var(key) }
    }

    #[test]
    fn from_env_includes_documented_runtime_overrides() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = [
            "HOME",
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
            "KEYCLAW_AUDIT_LOG",
        ];
        let saved = capture_env(&keys);

        set_env_var("HOME", temp.path());
        set_env_var("KEYCLAW_PROXY_ADDR", "127.0.0.1:9999");
        set_env_var("KEYCLAW_PROXY_URL", "http://127.0.0.1:9999");
        set_env_var("KEYCLAW_CA_CERT", "/tmp/keyclaw-ca.crt");
        set_env_var("KEYCLAW_VAULT_PATH", "/tmp/keyclaw-vault.enc");
        set_env_var("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase");
        set_env_var("KEYCLAW_GITLEAKS_CONFIG", "/tmp/keyclaw-gitleaks.toml");
        set_env_var("KEYCLAW_LOG_LEVEL", "debug");
        set_env_var("KEYCLAW_UNSAFE_LOG", "true");
        set_env_var("KEYCLAW_DETECTOR_TIMEOUT", "250ms");
        set_env_var("KEYCLAW_NOTICE_MODE", "minimal");
        set_env_var("KEYCLAW_AUDIT_LOG", "/tmp/keyclaw-audit.log");

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
        assert_eq!(
            cfg.audit_log_path.as_deref(),
            Some(Path::new("/tmp/keyclaw-audit.log"))
        );

        restore_env(saved);
    }

    #[test]
    fn from_env_uses_documented_defaults_for_runtime_overrides() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = [
            "HOME",
            "KEYCLAW_VAULT_PATH",
            "KEYCLAW_VAULT_PASSPHRASE",
            "KEYCLAW_GITLEAKS_CONFIG",
            "KEYCLAW_LOG_LEVEL",
            "KEYCLAW_UNSAFE_LOG",
            "KEYCLAW_DETECTOR_TIMEOUT",
            "KEYCLAW_NOTICE_MODE",
            "KEYCLAW_AUDIT_LOG",
        ];
        let saved = capture_env(&keys);

        set_env_var("HOME", temp.path());
        remove_env_var("KEYCLAW_VAULT_PATH");
        remove_env_var("KEYCLAW_VAULT_PASSPHRASE");
        remove_env_var("KEYCLAW_GITLEAKS_CONFIG");
        remove_env_var("KEYCLAW_LOG_LEVEL");
        remove_env_var("KEYCLAW_UNSAFE_LOG");
        remove_env_var("KEYCLAW_DETECTOR_TIMEOUT");
        remove_env_var("KEYCLAW_NOTICE_MODE");
        remove_env_var("KEYCLAW_AUDIT_LOG");

        let cfg = Config::from_env();

        assert_eq!(
            cfg.vault_path,
            temp.path().join(".keyclaw").join("vault.enc")
        );
        assert_eq!(cfg.vault_passphrase, None);
        assert_eq!(cfg.gitleaks_config_path, None);
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert!(!cfg.unsafe_log);
        assert_eq!(cfg.detector_timeout, Duration::from_secs(4));
        assert_eq!(cfg.notice_mode, NoticeMode::Verbose);
        assert_eq!(
            cfg.audit_log_path,
            Some(temp.path().join(".keyclaw").join("audit.log"))
        );

        restore_env(saved);
    }

    #[test]
    fn from_env_reads_entropy_settings() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = [
            "HOME",
            "KEYCLAW_ENTROPY_ENABLED",
            "KEYCLAW_ENTROPY_THRESHOLD",
            "KEYCLAW_ENTROPY_MIN_LEN",
        ];
        let saved = capture_env(&keys);
        set_env_var("HOME", temp.path());
        set_env_var("KEYCLAW_ENTROPY_ENABLED", "false");
        set_env_var("KEYCLAW_ENTROPY_THRESHOLD", "4.0");
        set_env_var("KEYCLAW_ENTROPY_MIN_LEN", "30");
        let cfg = Config::from_env();
        assert!(!cfg.entropy_enabled);
        assert!((cfg.entropy_threshold - 4.0).abs() < 0.001);
        assert_eq!(cfg.entropy_min_len, 30);
        restore_env(saved);
    }

    #[test]
    fn allowed_hosts_all_includes_supported_provider_domains() {
        let mut cfg = Config::defaults();
        cfg.include_hosts = vec!["*my-custom-api.com*".into()];

        let allowed = Config::allowed_hosts("all", &cfg);

        for expected in [
            "api.openai.com",
            "api.anthropic.com",
            "generativelanguage.googleapis.com",
            "api.together.xyz",
            "api.groq.com",
            "api.mistral.ai",
            "api.cohere.ai",
            "api.deepseek.com",
            "*my-custom-api.com*",
        ] {
            assert!(
                allowed.iter().any(|host| host == expected),
                "expected {expected} in allowed hosts: {allowed:?}"
            );
        }
    }

    #[test]
    fn from_env_uses_entropy_defaults() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let keys = [
            "HOME",
            "KEYCLAW_ENTROPY_ENABLED",
            "KEYCLAW_ENTROPY_THRESHOLD",
            "KEYCLAW_ENTROPY_MIN_LEN",
        ];
        let saved = capture_env(&keys);
        set_env_var("HOME", temp.path());
        remove_env_var("KEYCLAW_ENTROPY_ENABLED");
        remove_env_var("KEYCLAW_ENTROPY_THRESHOLD");
        remove_env_var("KEYCLAW_ENTROPY_MIN_LEN");
        let cfg = Config::from_env();
        assert!(cfg.entropy_enabled);
        assert!((cfg.entropy_threshold - 3.5).abs() < 0.001);
        assert_eq!(cfg.entropy_min_len, 20);
        restore_env(saved);
    }

    #[test]
    fn from_env_reads_config_file_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let config_dir = temp.path().join(".keyclaw");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(
            config_dir.join("config.toml"),
            r#"
[proxy]
addr = "127.0.0.1:9998"
url = "http://127.0.0.1:9998"

[logging]
level = "debug"

[notice]
mode = "minimal"

[detection]
entropy_enabled = false
entropy_threshold = 4.25
entropy_min_len = 28

[hosts]
codex = ["api.openai.com", "platform.openai.com"]
claude = ["api.anthropic.com", "console.anthropic.com"]
"#,
        )
        .expect("write config");

        let keys = [
            "HOME",
            "KEYCLAW_PROXY_ADDR",
            "KEYCLAW_PROXY_URL",
            "KEYCLAW_LOG_LEVEL",
            "KEYCLAW_NOTICE_MODE",
            "KEYCLAW_ENTROPY_ENABLED",
            "KEYCLAW_ENTROPY_THRESHOLD",
            "KEYCLAW_ENTROPY_MIN_LEN",
            "KEYCLAW_CODEX_HOSTS",
            "KEYCLAW_CLAUDE_HOSTS",
        ];
        let saved = capture_env(&keys);
        set_env_var("HOME", temp.path());
        for key in &keys[1..] {
            remove_env_var(key);
        }

        let cfg = Config::from_env();

        assert_eq!(cfg.proxy_listen_addr, "127.0.0.1:9998");
        assert_eq!(cfg.proxy_url, "http://127.0.0.1:9998");
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert_eq!(cfg.notice_mode, NoticeMode::Minimal);
        assert!(!cfg.entropy_enabled);
        assert!((cfg.entropy_threshold - 4.25).abs() < 0.001);
        assert_eq!(cfg.entropy_min_len, 28);
        assert_eq!(
            cfg.known_codex_hosts,
            vec!["api.openai.com", "platform.openai.com"]
        );
        assert_eq!(
            cfg.known_claude_hosts,
            vec!["api.anthropic.com", "console.anthropic.com"]
        );

        restore_env(saved);
    }

    #[test]
    fn from_env_env_overrides_config_file_values() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let config_dir = temp.path().join(".keyclaw");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(
            config_dir.join("config.toml"),
            r#"
[proxy]
addr = "127.0.0.1:9998"

[logging]
level = "debug"

[notice]
mode = "minimal"
"#,
        )
        .expect("write config");

        let keys = [
            "HOME",
            "KEYCLAW_PROXY_ADDR",
            "KEYCLAW_LOG_LEVEL",
            "KEYCLAW_NOTICE_MODE",
        ];
        let saved = capture_env(&keys);
        set_env_var("HOME", temp.path());
        set_env_var("KEYCLAW_PROXY_ADDR", "127.0.0.1:7777");
        set_env_var("KEYCLAW_LOG_LEVEL", "warn");
        set_env_var("KEYCLAW_NOTICE_MODE", "off");

        let cfg = Config::from_env();

        assert_eq!(cfg.proxy_listen_addr, "127.0.0.1:7777");
        assert_eq!(cfg.log_level, LogLevel::Warn);
        assert_eq!(cfg.notice_mode, NoticeMode::Off);

        restore_env(saved);
    }

    #[test]
    fn from_env_does_not_apply_partial_values_from_invalid_config_file() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let config_dir = temp.path().join(".keyclaw");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(
            config_dir.join("config.toml"),
            r#"
[proxy]
addr = "127.0.0.1:9998"

[logging]
level = "LOUD"
"#,
        )
        .expect("write config");

        let keys = ["HOME", "KEYCLAW_PROXY_ADDR", "KEYCLAW_LOG_LEVEL"];
        let saved = capture_env(&keys);
        set_env_var("HOME", temp.path());
        remove_env_var("KEYCLAW_PROXY_ADDR");
        remove_env_var("KEYCLAW_LOG_LEVEL");

        let cfg = Config::from_env();

        assert_eq!(cfg.proxy_listen_addr, "127.0.0.1:8877");
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert!(cfg.config_file_error().is_some());

        restore_env(saved);
    }

    #[test]
    fn from_env_reads_allowlist_entries() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let config_dir = temp.path().join(".keyclaw");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(
            config_dir.join("config.toml"),
            r#"
[allowlist]
rule_ids = ["generic-api-key"]
patterns = ["^sk-test-"]
secret_sha256 = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
"#,
        )
        .expect("write config");

        let keys = ["HOME"];
        let saved = capture_env(&keys);
        set_env_var("HOME", temp.path());

        let cfg = Config::from_env();
        let counts = cfg.allowlist.counts();

        assert_eq!(counts.rule_ids, 1);
        assert_eq!(counts.patterns, 1);
        assert_eq!(counts.secret_sha256, 1);

        restore_env(saved);
    }

    #[test]
    fn from_env_reads_audit_log_disable_from_config_file() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let temp = tempfile::tempdir().expect("tempdir");
        let config_dir = temp.path().join(".keyclaw");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(config_dir.join("config.toml"), "[audit]\npath = \"off\"\n")
            .expect("write config");

        let keys = ["HOME"];
        let saved = capture_env(&keys);
        set_env_var("HOME", temp.path());

        let cfg = Config::from_env();

        assert_eq!(cfg.audit_log_path, None);

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
                Some(value) => set_env_var(key, value),
                None => remove_env_var(key),
            }
        }
    }
}
