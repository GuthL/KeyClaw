use std::path::PathBuf;
use std::time::Duration;

use crate::config::Config;
use crate::logging::LogLevel;

fn test_config(vault_path: PathBuf) -> Config {
    Config {
        proxy_listen_addr: "127.0.0.1:8877".into(),
        proxy_url: "http://127.0.0.1:8877".into(),
        ca_cert_path: String::new(),
        vault_path,
        vault_passphrase: None,
        fail_closed: true,
        max_body_bytes: 2 * 1024 * 1024,
        detector_timeout: Duration::from_secs(4),
        known_codex_hosts: Vec::new(),
        known_claude_hosts: Vec::new(),
        gitleaks_config_path: None,
        log_level: LogLevel::Info,
        unsafe_log: false,
        require_mitm_effective: true,
        notice_mode: crate::redaction::NoticeMode::Verbose,
        dry_run: false,
        entropy_enabled: true,
        entropy_threshold: 3.5,
        entropy_min_len: 20,
        audit_log_path: Some(crate::audit::default_audit_log_path()),
        allowlist: crate::allowlist::Allowlist::default(),
        config_file_status: crate::config::ConfigFileStatus::Missing(
            crate::config::default_config_path(),
        ),
    }
}

#[test]
fn load_runtime_ruleset_falls_back_to_bundled_rules_when_custom_file_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut cfg = test_config(temp.path().join("vault.enc"));
    cfg.gitleaks_config_path = Some(temp.path().join("missing-gitleaks.toml"));

    let ruleset = super::detection::load_runtime_ruleset(&cfg).expect("fallback to bundled rules");

    assert!(
        !ruleset.rules.is_empty(),
        "bundled fallback should still load shipped rules"
    );
}

#[test]
fn read_and_validate_proxy_pid_returns_none_for_missing_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let pid_path = temp.path().join("proxy.pid");
    assert!(super::proxy_daemon::read_and_validate_proxy_pid(&pid_path).is_none());
}

#[test]
fn read_and_validate_proxy_pid_returns_none_for_invalid_pid() {
    let temp = tempfile::tempdir().expect("tempdir");
    let pid_path = temp.path().join("proxy.pid");
    std::fs::write(&pid_path, "not-a-number").expect("write");
    assert!(super::proxy_daemon::read_and_validate_proxy_pid(&pid_path).is_none());
    assert!(!pid_path.exists());
}

#[test]
fn read_and_validate_proxy_pid_returns_none_for_dead_process() {
    let temp = tempfile::tempdir().expect("tempdir");
    let pid_path = temp.path().join("proxy.pid");
    std::fs::write(&pid_path, "4294967").expect("write");
    assert!(super::proxy_daemon::read_and_validate_proxy_pid(&pid_path).is_none());
    assert!(!pid_path.exists());
}

#[test]
fn is_keyclaw_proxy_process_rejects_unrelated_process() {
    let pid = std::process::id();
    assert!(!super::proxy_daemon::is_keyclaw_proxy_process(pid));
}

#[test]
fn read_proxy_addr_from_env_extracts_address() {
    let temp = tempfile::tempdir().expect("tempdir");
    let env_path = temp.path().join("env.sh");
    let content = "# comment\nexport HTTP_PROXY='http://127.0.0.1:9988'\nexport HTTPS_PROXY='http://127.0.0.1:9988'\n";
    std::fs::write(&env_path, content).expect("write");
    assert_eq!(
        super::proxy_daemon::read_proxy_addr_from_env(&env_path),
        Some("127.0.0.1:9988".to_string())
    );
}

#[test]
fn read_proxy_addr_from_env_returns_none_for_missing_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let env_path = temp.path().join("env.sh");
    assert_eq!(
        super::proxy_daemon::read_proxy_addr_from_env(&env_path),
        None
    );
}
