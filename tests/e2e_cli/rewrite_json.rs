use std::io::Write;
use std::process::{Command, Stdio};

use crate::common::{allowlist_test_payload, run_rewrite_json_with_input};
use crate::support::{TEST_SECRET_CLAUDE, TEST_SECRET_CODEX, rewrite_json_command, wait_until};

#[test]
fn rewrite_json_respects_entropy_toggle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);

    let mut child = rewrite_json_command(temp.path())
        .env("KEYCLAW_ENTROPY_ENABLED", "false")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
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
    let out = String::from_utf8_lossy(&output.stdout);
    assert_eq!(out, payload);
}

#[test]
fn rewrite_json_fails_on_invalid_config_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        "[logging]\nlevel = \"LOUD\"\n",
    )
    .expect("write config");

    let output = rewrite_json_command(temp.path())
        .output()
        .expect("run rewrite-json");

    assert_ne!(output.status.code(), Some(0));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("config.toml"), "stderr={err}");
    assert!(err.contains("logging.level"), "stderr={err}");
}

#[test]
fn rewrite_json_skips_rule_id_allowlisted_matches() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        r#"
[allowlist]
rule_ids = ["opaque.high_entropy"]
"#,
    )
    .expect("write config");
    let (_, payload) = allowlist_test_payload();

    let output = run_rewrite_json_with_input(temp.path(), &payload);

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert_eq!(out, payload);
}

#[test]
fn rewrite_json_skips_regex_allowlisted_matches() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        r#"
[allowlist]
patterns = ["^AbC123"]
"#,
    )
    .expect("write config");
    let (_, payload) = allowlist_test_payload();

    let output = run_rewrite_json_with_input(temp.path(), &payload);

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert_eq!(out, payload);
}

#[test]
fn rewrite_json_skips_sha256_allowlisted_matches() {
    use sha2::{Digest, Sha256};

    let temp = tempfile::tempdir().expect("tempdir");
    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    let (secret, payload) = allowlist_test_payload();
    let digest = hex::encode(Sha256::digest(secret.as_bytes()));
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            r#"
[allowlist]
secret_sha256 = ["{}"]
"#,
            digest
        ),
    )
    .expect("write config");

    let output = run_rewrite_json_with_input(temp.path(), &payload);

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert_eq!(out, payload);
}

#[test]
fn rewrite_json_writes_audit_log_without_secret_material() {
    let temp = tempfile::tempdir().expect("tempdir");
    let audit_log = temp.path().join("audit.log");
    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);

    let mut child = rewrite_json_command(temp.path())
        .env("KEYCLAW_AUDIT_LOG", &audit_log)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
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
    let log = std::fs::read_to_string(&audit_log).expect("read audit log");
    assert!(log.contains("\"action\":\"redacted\""), "log={log}");
    assert!(log.contains("\"request_host\":\"stdin\""), "log={log}");
    assert!(log.contains("\"kind\":\"opaque_token\""), "log={log}");
    assert!(
        log.contains("\"rule_id\":\"opaque.high_entropy\""),
        "log={log}"
    );
    assert!(
        log.contains("\"placeholder\":\"{{KEYCLAW_OPAQUE_"),
        "log={log}"
    );
    assert!(!log.contains(TEST_SECRET_CODEX), "log={log}");
}

#[test]
fn rewrite_json_disables_audit_log_with_off() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);

    let mut child = rewrite_json_command(temp.path())
        .env("KEYCLAW_AUDIT_LOG", "off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
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
    assert!(
        !temp.path().join("audit.log").exists(),
        "audit log should stay disabled"
    );
}

#[test]
fn rewrite_json_appends_audit_log_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let audit_log = temp.path().join("audit.log");

    for secret in [TEST_SECRET_CODEX, TEST_SECRET_CLAUDE] {
        let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, secret);
        let mut child = rewrite_json_command(temp.path())
            .env("KEYCLAW_AUDIT_LOG", &audit_log)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
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
    }

    let log = std::fs::read_to_string(&audit_log).expect("read audit log");
    assert_eq!(log.lines().count(), 2, "log={log}");
}

#[test]
fn rewrite_json_uses_session_placeholders_without_machine_local_vault_key() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");

    let mut child = Command::new(bin)
        .arg("rewrite-json")
        .env_clear()
        .env("HOME", temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
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
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("{{KEYCLAW_OPAQUE_"), "output={out}");
    assert!(
        !temp.path().join("vault.key").exists(),
        "session-scoped runtime should not create a vault key"
    );
}

#[test]
fn rewrite_json_preserves_env_style_assignment_boundaries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = r#"{"messages":[{"role":"user","content":"install K_API_KEY: f47ac10b-58cc-4372-a567-0e02b2c3d479 in .env\nthen set K_API_KEY = c9bf9e57-1685-4d46-a09f-3a1c5ee70b82"}]}"#;

    let mut child = rewrite_json_command(temp.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
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
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("K_API_KEY: {{KEYCLAW_OPAQUE_"), "output={out}");
    assert!(
        out.contains("K_API_KEY = {{KEYCLAW_OPAQUE_"),
        "output={out}"
    );
    assert!(out.contains("}} in .env"), "output={out}");
    assert!(!out.contains("install {{KEYCLAW_OPAQUE_"), "output={out}");
}

#[test]
fn rewrite_json_dry_run_leaves_payload_unchanged() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload =
        r#"{"messages":[{"role":"user","content":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"}]}"#;

    let mut child = rewrite_json_command(temp.path())
        .arg("--dry-run")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
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
    let out = String::from_utf8_lossy(&output.stdout);
    assert_eq!(out, payload, "output={out}");
}

#[test]
fn rewrite_json_secret_detected_log_hook_writes_placeholder_only() {
    let temp = tempfile::tempdir().expect("tempdir");
    let hook_log = temp.path().join("hooks.log");
    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            r#"
[[hooks]]
event = "secret_detected"
rule_ids = ["opaque.high_entropy"]
action = "log"
path = "{}"
"#,
            hook_log.display()
        ),
    )
    .expect("write config");

    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);
    let output = run_rewrite_json_with_input(temp.path(), &payload);

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    wait_until(std::time::Duration::from_secs(2), || hook_log.exists());
    let log = std::fs::read_to_string(&hook_log).expect("read hook log");
    assert!(log.contains("\"event\":\"secret_detected\""), "log={log}");
    assert!(
        log.contains("\"rule_id\":\"opaque.high_entropy\""),
        "log={log}"
    );
    assert!(
        log.contains("\"placeholder\":\"{{KEYCLAW_OPAQUE_"),
        "log={log}"
    );
    assert!(!log.contains(TEST_SECRET_CODEX), "log={log}");
}
