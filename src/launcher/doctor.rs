use std::fs;
use std::net::TcpListener;
use std::path::Path;

use tempfile::NamedTempFile;
use url::Url;

use crate::config::Config;
use crate::errors::{CODE_MITM_NOT_EFFECTIVE, KeyclawError};
use crate::gitleaks_rules::RuleSet;
use crate::vault::VaultPassphraseStatus;

pub(super) fn run_doctor(cfg: &Config) -> i32 {
    let checks = doctor_checks(cfg);
    let mut passed = 0usize;
    let mut warnings = 0usize;
    let mut failures = 0usize;

    for check in checks {
        match check.status {
            DoctorStatus::Pass => passed += 1,
            DoctorStatus::Warn => warnings += 1,
            DoctorStatus::Fail => failures += 1,
        }

        println!(
            "doctor: {} {} {}",
            check.status.label(),
            check.id,
            crate::logscrub::scrub(&check.message)
        );
        if let Some(hint) = check.hint {
            println!("doctor: hint: {}", crate::logscrub::scrub(&hint));
        }
    }

    println!("doctor: summary: {passed} passed, {warnings} warnings, {failures} blocking");

    if failures == 0 { 0 } else { 1 }
}

#[derive(Clone, Copy)]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

impl DoctorStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

struct DoctorCheck {
    status: DoctorStatus,
    id: &'static str,
    message: String,
    hint: Option<String>,
}

fn doctor_checks(cfg: &Config) -> Vec<DoctorCheck> {
    vec![
        check_config_file(cfg),
        check_proxy_bind(cfg),
        check_proxy_url(cfg),
        check_ca_cert(cfg),
        check_vault_path(cfg),
        check_ruleset(cfg),
        check_kingfisher(),
        check_allowlist(cfg),
        check_proxy_bypass(cfg),
        check_unsafe_log(cfg),
        check_vault_passphrase(cfg),
    ]
}

fn check_config_file(cfg: &Config) -> DoctorCheck {
    match cfg.config_file_status() {
        crate::config::ConfigFileStatus::Missing(path) => pass_check(
            "config-file",
            format!(
                "no config file at {}; using env vars and built-in defaults",
                path.display()
            ),
        ),
        crate::config::ConfigFileStatus::Loaded(path) => pass_check(
            "config-file",
            format!("loaded config file from {}", path.display()),
        ),
        crate::config::ConfigFileStatus::Invalid { path, message } => fail_check(
            "config-file",
            message.clone(),
            format!(
                "fix the TOML in {} or remove the file to fall back to env vars and defaults",
                path.display()
            ),
        ),
    }
}

fn check_proxy_bind(cfg: &Config) -> DoctorCheck {
    match TcpListener::bind(cfg.proxy_listen_addr.trim()) {
        Ok(listener) => {
            let addr = listener
                .local_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| cfg.proxy_listen_addr.clone());
            drop(listener);
            pass_check("proxy-bind", format!("can bind proxy listener on {addr}"))
        }
        Err(err) => fail_check(
            "proxy-bind",
            format!(
                "cannot bind proxy listener on {}: {err}",
                cfg.proxy_listen_addr.trim()
            ),
            "set KEYCLAW_PROXY_ADDR to a free local address, for example 127.0.0.1:8877"
                .to_string(),
        ),
    }
}

fn check_proxy_url(cfg: &Config) -> DoctorCheck {
    let proxy_url = cfg.proxy_url.trim();
    if proxy_url.is_empty() {
        return fail_check(
            "proxy-url",
            "proxy URL is empty".to_string(),
            "set KEYCLAW_PROXY_URL to an http://host:port URL".to_string(),
        );
    }

    match Url::parse(proxy_url) {
        Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => {
            pass_check("proxy-url", format!("proxy URL {proxy_url} is valid"))
        }
        Ok(_) => fail_check(
            "proxy-url",
            format!("proxy URL {proxy_url} is missing a supported scheme or host"),
            "set KEYCLAW_PROXY_URL to an http://host:port URL".to_string(),
        ),
        Err(err) => fail_check(
            "proxy-url",
            format!("proxy URL {proxy_url} is invalid: {err}"),
            "set KEYCLAW_PROXY_URL to an http://host:port URL".to_string(),
        ),
    }
}

fn check_ca_cert(cfg: &Config) -> DoctorCheck {
    let explicit_path = cfg.ca_cert_path.trim();
    if !explicit_path.is_empty() {
        return match validate_ca_cert_file(Path::new(explicit_path)) {
            Ok(()) => pass_check(
                "ca-cert",
                format!("readable CA cert configured at {explicit_path}"),
            ),
            Err(err) => fail_check(
                "ca-cert",
                err.to_string(),
                "set KEYCLAW_CA_CERT to a readable PEM file or unset it to use ~/.keyclaw/ca.crt"
                    .to_string(),
            ),
        };
    }

    let keyclaw_dir = crate::certgen::keyclaw_dir();
    let cert_path = keyclaw_dir.join("ca.crt");
    let key_path = keyclaw_dir.join("ca.key");
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => match validate_generated_ca_pair(&cert_path, &key_path) {
            Ok(()) => pass_check(
                "ca-cert",
                format!("existing CA pair is ready at {}", cert_path.display()),
            ),
            Err(err) => fail_check(
                "ca-cert",
                err.to_string(),
                "remove the broken CA files in ~/.keyclaw or regenerate them with `keyclaw proxy`"
                    .to_string(),
            ),
        },
        (true, false) | (false, true) => fail_check(
            "ca-cert",
            format!(
                "incomplete CA state in {} (need both ca.crt and ca.key)",
                keyclaw_dir.display()
            ),
            "remove the partial CA files in ~/.keyclaw, then rerun `keyclaw proxy`".to_string(),
        ),
        (false, false) => match ensure_dir_writable(&keyclaw_dir) {
            Ok(()) => pass_check(
                "ca-cert",
                format!(
                    "CA files are not generated yet, but {} is writable",
                    keyclaw_dir.display()
                ),
            ),
            Err(err) => fail_check(
                "ca-cert",
                err.to_string(),
                "ensure ~/.keyclaw exists and is writable before starting the proxy".to_string(),
            ),
        },
    }
}

fn check_vault_path(cfg: &Config) -> DoctorCheck {
    match validate_vault_path(&cfg.vault_path) {
        Ok(()) => pass_check(
            "vault-path",
            format!("vault path is writable at {}", cfg.vault_path.display()),
        ),
        Err(err) => fail_check(
            "vault-path",
            err.to_string(),
            "set KEYCLAW_VAULT_PATH to a writable file path".to_string(),
        ),
    }
}

fn check_ruleset(cfg: &Config) -> DoctorCheck {
    match cfg.gitleaks_config_path.as_deref() {
        Some(path) => match RuleSet::from_file(path) {
            Ok(ruleset) if ruleset.skipped_rules > 0 => warn_check(
                "ruleset",
                format!(
                    "loaded {} custom gitleaks rules from {}, skipped {} invalid rule(s)",
                    ruleset.rules.len(),
                    path.display(),
                    ruleset.skipped_rules
                ),
                "fix the invalid rules in KEYCLAW_GITLEAKS_CONFIG or unset it to use the bundled rules".to_string(),
            ),
            Ok(ruleset) => pass_check(
                "ruleset",
                format!(
                    "loaded {} custom gitleaks rules from {}",
                    ruleset.rules.len(),
                    path.display()
                ),
            ),
            Err(err) => fail_check(
                "ruleset",
                format!(
                    "cannot load custom gitleaks rules from {}: {err}",
                    path.display()
                ),
                "fix KEYCLAW_GITLEAKS_CONFIG or unset it to use the bundled rules".to_string(),
            ),
        },
        None => pass_check("ruleset", "using bundled gitleaks rules".to_string()),
    }
}

fn check_kingfisher() -> DoctorCheck {
    if crate::kingfisher::default_binary_available() {
        pass_check(
            "kingfisher",
            "kingfisher binary is available for second-pass detection".to_string(),
        )
    } else {
        warn_check(
            "kingfisher",
            "kingfisher binary not found; second-pass detection is disabled".to_string(),
            "install `kingfisher` and ensure it is on PATH to enable the second pass".to_string(),
        )
    }
}

fn check_allowlist(cfg: &Config) -> DoctorCheck {
    let counts = cfg.allowlist.counts();
    let total = counts.total();

    if total == 0 {
        pass_check(
            "allowlist",
            "allowlist disabled; no bypass rules configured".to_string(),
        )
    } else {
        pass_check(
            "allowlist",
            format!(
                "{total} active allowlist entries ({} rule ids, {} patterns, {} secret hashes)",
                counts.rule_ids, counts.patterns, counts.secret_sha256
            ),
        )
    }
}

fn check_proxy_bypass(cfg: &Config) -> DoctorCheck {
    match super::bootstrap::launcher_bypass_risk(
        &std::env::var("NO_PROXY").unwrap_or_default(),
        &Config::allowed_hosts("all", cfg),
    ) {
        Some(reason) if cfg.require_mitm_effective => fail_check(
            "proxy-bypass",
            format!("{CODE_MITM_NOT_EFFECTIVE}: {reason}"),
            "unset NO_PROXY or remove intercepted hosts from it before running KeyClaw".to_string(),
        ),
        Some(reason) => warn_check(
            "proxy-bypass",
            format!("{CODE_MITM_NOT_EFFECTIVE}: {reason}"),
            "unset NO_PROXY or enable KEYCLAW_REQUIRE_MITM_EFFECTIVE for stricter safety"
                .to_string(),
        ),
        None => pass_check(
            "proxy-bypass",
            "NO_PROXY does not bypass the intercepted hosts".to_string(),
        ),
    }
}

fn check_unsafe_log(cfg: &Config) -> DoctorCheck {
    if cfg.unsafe_log {
        warn_check(
            "unsafe-log",
            "KEYCLAW_UNSAFE_LOG is enabled; logs may contain raw secrets".to_string(),
            "unset KEYCLAW_UNSAFE_LOG for normal use".to_string(),
        )
    } else {
        pass_check(
            "unsafe-log",
            "unsafe logging is disabled; log scrubbing remains active".to_string(),
        )
    }
}

fn check_vault_passphrase(cfg: &Config) -> DoctorCheck {
    match crate::vault::inspect_vault_passphrase_status(
        &cfg.vault_path,
        cfg.vault_passphrase.as_deref(),
    ) {
        Ok(VaultPassphraseStatus::EnvOverride) => pass_check(
            "vault-key",
            "custom vault passphrase configured via KEYCLAW_VAULT_PASSPHRASE".to_string(),
        ),
        Ok(VaultPassphraseStatus::LegacyEnvOverride) => warn_check(
            "vault-key",
            "KEYCLAW_VAULT_PASSPHRASE is set to the legacy built-in default".to_string(),
            "set KEYCLAW_VAULT_PASSPHRASE to a unique value or remove it to use a generated machine-local key".to_string(),
        ),
        Ok(VaultPassphraseStatus::GeneratedKeyReady(path)) => pass_check(
            "vault-key",
            format!("machine-local vault key ready at {}", path.display()),
        ),
        Ok(VaultPassphraseStatus::GeneratedKeyWillBeCreated(path)) => pass_check(
            "vault-key",
            format!(
                "machine-local vault key will be created at {} on first write",
                path.display()
            ),
        ),
        Ok(VaultPassphraseStatus::LegacyVaultWillMigrate(path)) => warn_check(
            "vault-key",
            "existing vault still uses the legacy built-in default and will be migrated on next write"
                .to_string(),
            format!(
                "run a write path once to generate {} and re-encrypt the vault",
                path.display()
            ),
        ),
        Err(err) => fail_check(
            "vault-key",
            err.to_string(),
            "restore the machine-local vault key or set KEYCLAW_VAULT_PASSPHRASE to the correct value".to_string(),
        ),
    }
}

pub(super) fn validate_ca_cert_file(path: &Path) -> Result<(), KeyclawError> {
    let metadata = fs::metadata(path).map_err(|err| {
        KeyclawError::uncoded(format!("cannot access CA cert {}: {err}", path.display()))
    })?;
    if !metadata.is_file() {
        return Err(KeyclawError::uncoded(format!(
            "CA cert path {} is not a file",
            path.display()
        )));
    }
    fs::read_to_string(path).map_err(|err| {
        KeyclawError::uncoded(format!("cannot read CA cert {}: {err}", path.display()))
    })?;
    Ok(())
}

fn validate_generated_ca_pair(cert_path: &Path, key_path: &Path) -> Result<(), KeyclawError> {
    crate::certgen::validate_generated_ca_pair(cert_path, key_path).map(|_| ())
}

fn validate_vault_path(path: &Path) -> Result<(), KeyclawError> {
    if path.is_dir() {
        return Err(KeyclawError::uncoded(format!(
            "vault path {} is a directory, not a file",
            path.display()
        )));
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir_writable(dir)?;

    if path.exists() {
        let metadata = fs::metadata(path).map_err(|err| {
            KeyclawError::uncoded(format!(
                "cannot access vault path {}: {err}",
                path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(KeyclawError::uncoded(format!(
                "vault path {} is not a regular file",
                path.display()
            )));
        }
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|err| {
                KeyclawError::uncoded(format!("cannot open vault path {}: {err}", path.display()))
            })?;
    }

    Ok(())
}

fn ensure_dir_writable(path: &Path) -> Result<(), KeyclawError> {
    fs::create_dir_all(path)
        .map_err(|err| KeyclawError::uncoded(format!("cannot create {}: {err}", path.display())))?;
    NamedTempFile::new_in(path).map_err(|err| {
        KeyclawError::uncoded(format!("cannot write in {}: {err}", path.display()))
    })?;
    Ok(())
}

fn pass_check(id: &'static str, message: String) -> DoctorCheck {
    DoctorCheck {
        status: DoctorStatus::Pass,
        id,
        message,
        hint: None,
    }
}

fn warn_check(id: &'static str, message: String, hint: String) -> DoctorCheck {
    DoctorCheck {
        status: DoctorStatus::Warn,
        id,
        message,
        hint: Some(hint),
    }
}

fn fail_check(id: &'static str, message: String, hint: String) -> DoctorCheck {
    DoctorCheck {
        status: DoctorStatus::Fail,
        id,
        message,
        hint: Some(hint),
    }
}
