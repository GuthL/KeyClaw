use std::io::Write;
use std::process::Stdio;

use crate::support::{
    TEST_SECRET_CODEX, install_fake_tool, prepend_path, rewrite_json_command, wait_until,
};

#[test]
fn rewrite_json_blocks_when_secret_detected_hook_requests_block() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        r#"
[[hooks]]
event = "secret_detected"
rule_ids = ["opaque.high_entropy"]
action = "block"
message = "production key detected"
"#,
    )
    .expect("write config");

    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);
    let mut child = rewrite_json_command(temp.path())
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

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("hook_blocked"), "stderr={stderr}");
    assert!(stderr.contains("key detected"), "stderr={stderr}");
}

#[test]
fn rewrite_json_logs_request_redacted_hook_without_secret_material() {
    let temp = tempfile::tempdir().expect("tempdir");
    let hook_log = temp.path().join("hook.log");
    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            r#"
[[hooks]]
event = "request_redacted"
rule_ids = ["opaque.high_entropy"]
action = "log"
path = "{}"
"#,
            hook_log.display()
        ),
    )
    .expect("write config");

    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);
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
    wait_until(std::time::Duration::from_secs(2), || hook_log.exists());
    let log = std::fs::read_to_string(&hook_log).expect("read hook log");
    assert!(log.contains("\"event\":\"request_redacted\""), "log={log}");
    assert!(log.contains("\"request_host\":\"stdin\""), "log={log}");
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
fn rewrite_json_executes_secret_detected_hook_with_sanitized_metadata() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create fake bin");
    let capture_env = temp.path().join("hook-env.txt");
    let capture_stdin = temp.path().join("hook-stdin.json");
    install_fake_tool(
        &bin_dir,
        "hook-capture",
        r#"#!/usr/bin/env bash
printf '%s\n' "$KEYCLAW_HOOK_EVENT" > "$KEYCLAW_HOOK_CAPTURE_ENV"
printf '%s\n' "$KEYCLAW_HOOK_REQUEST_HOST" >> "$KEYCLAW_HOOK_CAPTURE_ENV"
printf '%s\n' "$KEYCLAW_HOOK_RULE_ID" >> "$KEYCLAW_HOOK_CAPTURE_ENV"
printf '%s\n' "$KEYCLAW_HOOK_PLACEHOLDER" >> "$KEYCLAW_HOOK_CAPTURE_ENV"
cat > "$KEYCLAW_HOOK_CAPTURE_STDIN"
"#,
    );

    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        r#"
[[hooks]]
event = "secret_detected"
rule_ids = ["opaque.high_entropy"]
action = "exec"
command = "hook-capture"
"#,
    )
    .expect("write config");

    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);
    let mut child = rewrite_json_command(temp.path());
    prepend_path(&mut child, &bin_dir);
    let mut child = child
        .env("KEYCLAW_HOOK_CAPTURE_ENV", &capture_env)
        .env("KEYCLAW_HOOK_CAPTURE_STDIN", &capture_stdin)
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
    wait_until(std::time::Duration::from_secs(2), || {
        capture_env.exists() && capture_stdin.exists()
    });
    let env_capture = std::fs::read_to_string(&capture_env).expect("read env capture");
    assert!(env_capture.contains("secret_detected"), "env={env_capture}");
    assert!(env_capture.contains("stdin"), "env={env_capture}");
    assert!(
        env_capture.contains("opaque.high_entropy"),
        "env={env_capture}"
    );
    assert!(
        env_capture.contains("{{KEYCLAW_OPAQUE_"),
        "env={env_capture}"
    );
    assert!(
        !env_capture.contains(TEST_SECRET_CODEX),
        "env={env_capture}"
    );

    let stdin_capture = std::fs::read_to_string(&capture_stdin).expect("read stdin capture");
    assert!(
        stdin_capture.contains("\"event\":\"secret_detected\""),
        "stdin={stdin_capture}"
    );
    assert!(
        stdin_capture.contains("\"placeholder\":\"{{KEYCLAW_OPAQUE_"),
        "stdin={stdin_capture}"
    );
    assert!(
        !stdin_capture.contains(TEST_SECRET_CODEX),
        "stdin={stdin_capture}"
    );
}
