use std::time::Duration;

use crate::config::Config;
use crate::logging::LogLevel;
use crate::sensitive::{LocalClassifierConfig, SensitiveDataConfig};

fn test_config() -> Config {
    Config {
        proxy_listen_addr: "127.0.0.1:8877".into(),
        proxy_url: "http://127.0.0.1:8877".into(),
        ca_cert_path: String::new(),
        fail_closed: true,
        max_body_bytes: 2 * 1024 * 1024,
        detector_timeout: Duration::from_secs(4),
        known_codex_hosts: Vec::new(),
        known_claude_hosts: Vec::new(),
        known_provider_hosts: Vec::new(),
        include_hosts: Vec::new(),
        log_level: LogLevel::Info,
        unsafe_log: false,
        require_mitm_effective: true,
        notice_mode: crate::redaction::NoticeMode::Verbose,
        dry_run: false,
        entropy_enabled: true,
        entropy_threshold: 3.5,
        entropy_min_len: 20,
        audit_log_path: Some(crate::audit::default_audit_log_path()),
        sensitive_data: SensitiveDataConfig::default(),
        local_classifier: LocalClassifierConfig::default(),
        allowlist: crate::allowlist::Allowlist::default(),
        hooks: Vec::new(),
        config_file_status: crate::config::ConfigFileStatus::Missing(
            crate::config::default_config_path(),
        ),
    }
}

#[test]
fn test_detection_engine_uses_entropy_settings_from_config() {
    let mut cfg = test_config();
    cfg.entropy_enabled = false;
    cfg.entropy_threshold = 4.25;
    cfg.entropy_min_len = 28;

    let engine = super::detection::test_detection_engine(&cfg);

    assert!(!engine.entropy_config().enabled);
    assert!((engine.entropy_config().threshold - 4.25).abs() < f64::EPSILON);
    assert_eq!(engine.entropy_config().min_len, 28);
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

#[test]
fn proxy_addr_is_listening_detects_live_listener() {
    let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping loopback listener test: {err}");
            return;
        }
        Err(err) => panic!("bind listener: {err}"),
    };
    let addr = listener.local_addr().expect("local addr");

    assert!(super::proxy_daemon::proxy_addr_is_listening(
        &addr.to_string()
    ));

    drop(listener);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while std::time::Instant::now() < deadline {
        if !super::proxy_daemon::proxy_addr_is_listening(&addr.to_string()) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    assert!(
        !super::proxy_daemon::proxy_addr_is_listening(&addr.to_string()),
        "listener should stop accepting connections after drop"
    );
}

#[test]
fn detached_proxy_env_forwards_include_hosts() {
    let mut cfg = test_config();
    cfg.add_include_hosts(vec![
        "*my-custom-api.com*".into(),
        "api.together.xyz".into(),
    ]);

    let env = super::proxy_daemon::detached_proxy_env(&cfg);

    assert_eq!(
        env.iter()
            .find(|(key, _)| key == "KEYCLAW_INCLUDE_HOSTS")
            .map(|(_, value): &(String, String)| value.as_str()),
        Some("*my-custom-api.com*,api.together.xyz")
    );
}
