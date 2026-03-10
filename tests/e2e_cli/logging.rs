use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::support::{
    free_addr, rewrite_json_command, run_mitm, run_mitm_with_log_level, start_upstream,
    TEST_SECRET_CODEX,
};

#[test]
fn logs_contain_no_raw_secrets() {
    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm_with_log_level(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
        Some("debug"),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(!stderr.contains(TEST_SECRET_CODEX));
    assert!(
        stderr.contains("request rewritten for host"),
        "stderr={stderr}"
    );
}

#[test]
fn mitm_info_log_level_hides_per_request_proxy_activity() {
    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm_with_log_level(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
        Some("info"),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(stderr.contains("keyclaw info:"), "stderr={stderr}");
    assert!(!stderr.contains("intercept POST /"), "stderr={stderr}");
    assert!(
        !stderr.contains("request rewritten for host"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("response: resolved placeholders back to secrets"),
        "stderr={stderr}"
    );
}

#[test]
fn mitm_debug_log_level_preserves_per_request_proxy_activity() {
    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm_with_log_level(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
        Some("debug"),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(
        stderr.contains("keyclaw debug: intercept POST /"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("keyclaw debug: request rewritten for host 127.0.0.1: replaced 1 secrets"),
        "stderr={stderr}"
    );
}

#[test]
fn coded_errors_emit_a_single_code_prefix() {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault.enc");

    let output = Command::new(bin)
        .arg("mitm")
        .arg("codex")
        .env_clear()
        .env("HOME", temp.path())
        .env("NO_PROXY", "*")
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "true")
        .env("KEYCLAW_VAULT_PATH", &vault_path)
        .env("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase")
        .output()
        .expect("run mitm");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("keyclaw error: mitm_not_effective: NO_PROXY=*"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("mitm_not_effective: mitm_not_effective:"),
        "stderr={stderr}"
    );
}

#[test]
fn mitm_runtime_logs_use_leveled_prefixes() {
    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    let lines = stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert!(!lines.is_empty(), "stderr={stderr}");
    assert!(
        lines.iter().all(|line| line.starts_with("keyclaw info: ")),
        "stderr={stderr}"
    );
}

#[test]
fn rewrite_json_unsafe_logging_warning_uses_warn_prefix() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = r#"{"prompt":"hello"}"#;

    let mut child = rewrite_json_command(temp.path())
        .env("KEYCLAW_UNSAFE_LOG", "true")
        .env("KEYCLAW_LOG_LEVEL", "warn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rewrite-json");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let output = child.wait_with_output().expect("wait rewrite-json");

    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines = stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        lines,
        vec!["keyclaw warn: unsafe logging enabled; secrets may appear in logs"],
        "stderr={stderr}"
    );
}
