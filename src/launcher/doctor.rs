use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Debug)]
struct DoctorCheck {
    status: DoctorStatus,
    id: &'static str,
    message: String,
    hint: Option<String>,
}

fn doctor_checks(cfg: &Config) -> Vec<DoctorCheck> {
    let runtime = SystemDoctorRuntime;
    doctor_checks_with_runtime(cfg, &runtime)
}

fn doctor_checks_with_runtime(cfg: &Config, runtime: &impl DoctorRuntime) -> Vec<DoctorCheck> {
    let mut checks = vec![
        check_config_file(cfg),
        check_proxy_bind(cfg),
        check_proxy_url(cfg),
    ];
    if runtime.os() == "macos" {
        checks.push(check_macos_system_proxy(cfg, runtime));
    }
    checks.extend([check_ca_cert(cfg)]);
    if runtime.os() == "macos" {
        checks.push(check_macos_ca_trust(cfg, runtime));
    }
    checks.extend([
        check_vault_path(cfg),
        check_ruleset(cfg),
        check_kingfisher(),
        check_allowlist(cfg),
        check_proxy_bypass(cfg),
        check_unsafe_log(cfg),
        check_vault_passphrase(cfg),
    ]);
    checks
}

trait DoctorRuntime {
    fn os(&self) -> &str;
    fn run_command(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<DoctorCommandOutput, KeyclawError>;
}

struct SystemDoctorRuntime;

#[derive(Clone, Debug, PartialEq, Eq)]
struct DoctorCommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

impl DoctorRuntime for SystemDoctorRuntime {
    fn os(&self) -> &str {
        std::env::consts::OS
    }

    fn run_command(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<DoctorCommandOutput, KeyclawError> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|err| KeyclawError::uncoded(format!("cannot run `{program}`: {err}")))?;
        Ok(DoctorCommandOutput::from_output(output))
    }
}

impl DoctorCommandOutput {
    #[cfg(test)]
    fn success(stdout: &str, stderr: &str) -> Self {
        Self {
            success: true,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    #[cfg(test)]
    fn failure(stdout: &str, stderr: &str) -> Self {
        Self {
            success: false,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        }
    }

    fn from_output(output: std::process::Output) -> Self {
        Self {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        }
    }

    fn summary(&self) -> String {
        let stdout = self.stdout.trim();
        let stderr = self.stderr.trim();
        match (stdout.is_empty(), stderr.is_empty()) {
            (false, false) => format!("{stdout}; {stderr}"),
            (false, true) => stdout.to_string(),
            (true, false) => stderr.to_string(),
            (true, true) => "command returned no output".to_string(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MacOsSystemProxyState {
    http_enabled: bool,
    http_proxy: Option<String>,
    http_port: Option<u16>,
    https_enabled: bool,
    https_proxy: Option<String>,
    https_port: Option<u16>,
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

fn check_macos_system_proxy(cfg: &Config, runtime: &impl DoctorRuntime) -> DoctorCheck {
    let expected = expected_proxy_endpoint(cfg);
    let expected_label = expected_endpoint_label(expected.as_ref());
    let docs_hint = macos_desktop_docs_hint(expected_label.as_deref());

    match runtime.run_command("scutil", &["--proxy"]) {
        Ok(output) if !output.success => warn_check(
            "macos-system-proxy",
            format!(
                "could not confirm the effective macOS system proxy via `scutil --proxy`: {}",
                output.summary()
            ),
            docs_hint,
        ),
        Ok(output) => {
            let state = parse_scutil_proxy_output(&output.stdout);
            match expected {
                Some((expected_host, expected_port))
                    if state.http_enabled
                        && state.https_enabled
                        && state.http_proxy.as_deref() == Some(expected_host.as_str())
                        && state.http_port == Some(expected_port)
                        && state.https_proxy.as_deref() == Some(expected_host.as_str())
                        && state.https_port == Some(expected_port) =>
                {
                    pass_check(
                        "macos-system-proxy",
                        format!(
                            "effective macOS HTTP and HTTPS system proxy point at {expected_host}:{expected_port}"
                        ),
                    )
                }
                Some((_expected_host, _expected_port))
                    if !state.http_enabled && !state.https_enabled =>
                {
                    warn_check(
                        "macos-system-proxy",
                        "effective macOS system proxy is off; Finder-launched macOS apps will usually bypass KeyClaw".to_string(),
                        docs_hint,
                    )
                }
                Some((expected_host, expected_port)) => warn_check(
                    "macos-system-proxy",
                    format!(
                        "effective macOS system proxy does not fully point at {expected_host}:{expected_port} (HTTP {}, HTTPS {})",
                        render_proxy_target(
                            state.http_enabled,
                            state.http_proxy.as_deref(),
                            state.http_port,
                        ),
                        render_proxy_target(
                            state.https_enabled,
                            state.https_proxy.as_deref(),
                            state.https_port,
                        ),
                    ),
                    docs_hint,
                ),
                None => warn_check(
                    "macos-system-proxy",
                    "proxy URL is not valid enough to compare against the macOS system proxy".to_string(),
                    docs_hint,
                ),
            }
        }
        Err(err) => warn_check(
            "macos-system-proxy",
            format!(
                "could not inspect the effective macOS system proxy with `scutil --proxy`: {err}"
            ),
            docs_hint,
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

fn check_macos_ca_trust(cfg: &Config, runtime: &impl DoctorRuntime) -> DoctorCheck {
    let cert_path = configured_ca_cert_path(cfg);
    if !cert_path.exists() {
        return pass_check(
            "macos-ca-trust",
            format!(
                "macOS desktop-app CA trust will be checkable after {} exists",
                cert_path.display()
            ),
        );
    }

    if let Err(err) = validate_ca_cert_file(&cert_path) {
        return warn_check(
            "macos-ca-trust",
            format!(
                "could not verify macOS login-keychain SSL trust because {} is not readable: {err}",
                cert_path.display()
            ),
            macos_ca_trust_hint(&cert_path),
        );
    }

    let keychain_path = login_keychain_path();
    let cert_arg = cert_path.to_string_lossy().to_string();
    let keychain_arg = keychain_path.to_string_lossy().to_string();
    let args = [
        "verify-cert",
        "-c",
        cert_arg.as_str(),
        "-k",
        keychain_arg.as_str(),
        "-p",
        "ssl",
    ];

    match runtime.run_command("security", &args) {
        Ok(output) if output.success => pass_check(
            "macos-ca-trust",
            format!(
                "macOS login-keychain SSL trust accepts {}",
                cert_path.display()
            ),
        ),
        Ok(output) => warn_check(
            "macos-ca-trust",
            format!(
                "{} is not trusted for SSL in the macOS login keychain: {}",
                cert_path.display(),
                output.summary()
            ),
            macos_ca_trust_hint(&cert_path),
        ),
        Err(err) => warn_check(
            "macos-ca-trust",
            format!(
                "could not verify macOS login-keychain SSL trust for {}: {err}",
                cert_path.display()
            ),
            macos_ca_trust_hint(&cert_path),
        ),
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

fn expected_proxy_endpoint(cfg: &Config) -> Option<(String, u16)> {
    let proxy_url = cfg.proxy_url.trim();
    if let Ok(url) = Url::parse(proxy_url) {
        if let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) {
            return Some((host.to_string(), port));
        }
    }

    cfg.proxy_listen_addr
        .trim()
        .parse::<SocketAddr>()
        .ok()
        .map(|addr| (addr.ip().to_string(), addr.port()))
}

fn expected_endpoint_label(expected: Option<&(String, u16)>) -> Option<String> {
    expected.map(|(host, port)| format!("{host}:{port}"))
}

fn macos_desktop_docs_hint(expected: Option<&str>) -> String {
    match expected {
        Some(expected) => format!(
            "Finder-launched apps only use KeyClaw when the macOS HTTP and HTTPS system proxy both point at {expected}; verify with `scutil --proxy` and use docs/macos-gui-apps.md for the enable and rollback commands"
        ),
        None => "Finder-launched apps only use KeyClaw when the macOS HTTP and HTTPS system proxy are configured correctly; verify with `scutil --proxy` and use docs/macos-gui-apps.md for the enable and rollback commands".to_string(),
    }
}

fn configured_ca_cert_path(cfg: &Config) -> PathBuf {
    let explicit_path = cfg.ca_cert_path.trim();
    if explicit_path.is_empty() {
        crate::certgen::keyclaw_dir().join("ca.crt")
    } else {
        PathBuf::from(explicit_path)
    }
}

fn login_keychain_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"))
        .join("Library/Keychains/login.keychain-db")
}

fn macos_ca_trust_hint(cert_path: &Path) -> String {
    format!(
        "run `security add-trusted-cert -r trustRoot -p ssl -k {} {}` and re-check with `security verify-cert -c {} -k {} -p ssl`; the full rollback steps live in docs/macos-gui-apps.md",
        login_keychain_path().display(),
        cert_path.display(),
        cert_path.display(),
        login_keychain_path().display(),
    )
}

fn parse_scutil_proxy_output(output: &str) -> MacOsSystemProxyState {
    let mut state = MacOsSystemProxyState::default();

    for line in output.lines() {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "HTTPEnable" => state.http_enabled = value == "1",
            "HTTPProxy" => state.http_proxy = Some(value.to_string()),
            "HTTPPort" => state.http_port = value.parse().ok(),
            "HTTPSEnable" => state.https_enabled = value == "1",
            "HTTPSProxy" => state.https_proxy = Some(value.to_string()),
            "HTTPSPort" => state.https_port = value.parse().ok(),
            _ => {}
        }
    }

    state
}

fn render_proxy_target(enabled: bool, host: Option<&str>, port: Option<u16>) -> String {
    if !enabled {
        return "off".to_string();
    }
    match (host, port) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => format!("{host}:<missing-port>"),
        (None, Some(port)) => format!("<missing-host>:{port}"),
        (None, None) => "enabled with no host/port details".to_string(),
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::{Config, DoctorCommandOutput, doctor_checks_with_runtime, login_keychain_path};
    use crate::allowlist::Allowlist;
    use crate::config::ConfigFileStatus;
    use crate::hooks::Hook;
    use crate::logging::LogLevel;
    use crate::redaction::NoticeMode;

    #[derive(Default)]
    struct FakeDoctorRuntime {
        os: &'static str,
        commands: HashMap<(String, Vec<String>), Result<DoctorCommandOutput, String>>,
    }

    impl FakeDoctorRuntime {
        fn with_command(
            mut self,
            program: &str,
            args: &[&str],
            result: Result<DoctorCommandOutput, String>,
        ) -> Self {
            self.commands.insert(
                (
                    program.to_string(),
                    args.iter().map(|arg| (*arg).to_string()).collect(),
                ),
                result,
            );
            self
        }
    }

    impl super::DoctorRuntime for FakeDoctorRuntime {
        fn os(&self) -> &str {
            self.os
        }

        fn run_command(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<DoctorCommandOutput, crate::errors::KeyclawError> {
            self.commands
                .get(&(
                    program.to_string(),
                    args.iter().map(|arg| (*arg).to_string()).collect(),
                ))
                .cloned()
                .unwrap_or_else(|| Err(format!("missing fake command: {program} {args:?}")))
                .map_err(crate::errors::KeyclawError::uncoded)
        }
    }

    #[test]
    fn macos_doctor_warns_when_system_proxy_is_off() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cert_path = write_test_ca(&temp);
        let cfg = test_config(&cert_path);
        let runtime = FakeDoctorRuntime {
            os: "macos",
            ..Default::default()
        }
        .with_command(
            "scutil",
            &["--proxy"],
            Ok(DoctorCommandOutput::success(
                r#"
<dictionary> {
  HTTPEnable : 0
  HTTPSEnable : 0
}
"#,
                "",
            )),
        );

        let checks = doctor_checks_with_runtime(&cfg, &runtime);
        let check = checks
            .iter()
            .find(|check| check.id == "macos-system-proxy")
            .expect("macos-system-proxy check");

        assert_eq!(check.status.label(), "WARN");
        assert!(
            check.message.contains("Finder-launched macOS apps"),
            "{check:?}"
        );
        assert!(
            check
                .hint
                .as_deref()
                .unwrap_or_default()
                .contains("docs/macos-gui-apps.md"),
            "{check:?}"
        );
    }

    #[test]
    fn macos_doctor_passes_when_system_proxy_and_ca_trust_match() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cert_path = write_test_ca(&temp);
        let cfg = test_config(&cert_path);
        let keychain_path = login_keychain_path();
        let runtime = FakeDoctorRuntime {
            os: "macos",
            ..Default::default()
        }
        .with_command(
            "scutil",
            &["--proxy"],
            Ok(DoctorCommandOutput::success(
                r#"
<dictionary> {
  HTTPEnable : 1
  HTTPProxy : 127.0.0.1
  HTTPPort : 8877
  HTTPSEnable : 1
  HTTPSProxy : 127.0.0.1
  HTTPSPort : 8877
}
"#,
                "",
            )),
        )
        .with_command(
            "security",
            &[
                "verify-cert",
                "-c",
                cert_path.to_string_lossy().as_ref(),
                "-k",
                keychain_path.to_string_lossy().as_ref(),
                "-p",
                "ssl",
            ],
            Ok(DoctorCommandOutput::success(
                "certificate verification successful",
                "",
            )),
        );

        let checks = doctor_checks_with_runtime(&cfg, &runtime);
        let proxy = checks
            .iter()
            .find(|check| check.id == "macos-system-proxy")
            .expect("macos-system-proxy check");
        let trust = checks
            .iter()
            .find(|check| check.id == "macos-ca-trust")
            .expect("macos-ca-trust check");

        assert_eq!(proxy.status.label(), "PASS");
        assert_eq!(trust.status.label(), "PASS");
    }

    #[test]
    fn macos_doctor_warns_when_ca_is_not_trusted_for_ssl() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cert_path = write_test_ca(&temp);
        let cfg = test_config(&cert_path);
        let keychain_path = login_keychain_path();
        let runtime = FakeDoctorRuntime {
            os: "macos",
            ..Default::default()
        }
        .with_command(
            "scutil",
            &["--proxy"],
            Ok(DoctorCommandOutput::success(
                r#"
<dictionary> {
  HTTPEnable : 1
  HTTPProxy : 127.0.0.1
  HTTPPort : 8877
  HTTPSEnable : 1
  HTTPSProxy : 127.0.0.1
  HTTPSPort : 8877
}
"#,
                "",
            )),
        )
        .with_command(
            "security",
            &[
                "verify-cert",
                "-c",
                cert_path.to_string_lossy().as_ref(),
                "-k",
                keychain_path.to_string_lossy().as_ref(),
                "-p",
                "ssl",
            ],
            Ok(DoctorCommandOutput::failure("", "CSSMERR_TP_NOT_TRUSTED")),
        );

        let checks = doctor_checks_with_runtime(&cfg, &runtime);
        let trust = checks
            .iter()
            .find(|check| check.id == "macos-ca-trust")
            .expect("macos-ca-trust check");

        assert_eq!(trust.status.label(), "WARN");
        assert!(trust.message.contains("not trusted for SSL"), "{trust:?}");
        assert!(
            trust
                .hint
                .as_deref()
                .unwrap_or_default()
                .contains("security add-trusted-cert -r trustRoot -p ssl"),
            "{trust:?}"
        );
    }

    fn test_config(cert_path: &Path) -> Config {
        Config {
            proxy_listen_addr: "127.0.0.1:8877".to_string(),
            proxy_url: "http://127.0.0.1:8877".to_string(),
            ca_cert_path: cert_path.display().to_string(),
            vault_path: PathBuf::from("/tmp/keyclaw-test-vault.enc"),
            vault_passphrase: Some("test-passphrase".to_string()),
            fail_closed: true,
            max_body_bytes: 1024 * 1024,
            detector_timeout: Duration::from_secs(4),
            known_codex_hosts: Vec::new(),
            known_claude_hosts: Vec::new(),
            known_provider_hosts: Vec::new(),
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
            audit_log_path: None,
            allowlist: Allowlist::default(),
            hooks: Vec::<Hook>::new(),
            config_file_status: ConfigFileStatus::Missing(PathBuf::from(
                "/tmp/.keyclaw/config.toml",
            )),
        }
    }

    fn write_test_ca(temp: &tempfile::TempDir) -> PathBuf {
        let cert_path = temp.path().join("ca.crt");
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
        )
        .expect("write cert");
        cert_path
    }
}
