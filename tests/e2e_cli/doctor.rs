use crate::support::doctor_command;

#[test]
fn doctor_detects_proxy_bypass_attempt() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path())
        .env("NO_PROXY", "*")
        .output()
        .expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL proxy-bypass"), "output={out}");
    assert!(out.contains("mitm_not_effective"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
}

#[test]
fn doctor_detects_suffix_no_proxy_bypass_attempt() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path())
        .env("NO_PROXY", ".openai.com")
        .output()
        .expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL proxy-bypass"), "output={out}");
    assert!(out.contains(".openai.com"), "output={out}");
    assert!(out.contains("matches api.openai.com"), "output={out}");
}

#[test]
fn doctor_warns_on_unsafe_log_but_exits_zero() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path())
        .env("KEYCLAW_UNSAFE_LOG", "true")
        .output()
        .expect("run doctor");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("WARN unsafe-log"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
    assert!(!out.contains("FAIL "), "output={out}");
}

#[test]
fn doctor_reports_invalid_config_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        "[proxy]\naddr = [\"not-a-string\"\n",
    )
    .expect("write config");

    let output = doctor_command(temp.path()).output().expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL config-file"), "output={out}");
    assert!(out.contains("config.toml"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
}

#[test]
fn doctor_reports_allowlist_status() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        r#"
[allowlist]
rule_ids = ["example-secret"]
patterns = ["^AbC123"]
secret_sha256 = ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
"#,
    )
    .expect("write config");

    let output = doctor_command(temp.path()).output().expect("run doctor");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("PASS allowlist"), "output={out}");
    assert!(out.contains("3 active"), "output={out}");
}

#[test]
fn doctor_reports_clean_healthcheck() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path()).output().expect("run doctor");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(
        out.contains("PASS proxy-bind") || out.contains("WARN proxy-bind"),
        "output={out}"
    );
    assert!(out.contains("PASS ca-cert"), "output={out}");
    assert!(out.contains("PASS detection"), "output={out}");
    assert!(out.contains("doctor: summary:"), "output={out}");
    assert!(!out.contains("FAIL "), "output={out}");
}

#[test]
fn doctor_reports_detection_knobs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path())
        .env("KEYCLAW_ENTROPY_ENABLED", "false")
        .env("KEYCLAW_ENTROPY_THRESHOLD", "4.25")
        .env("KEYCLAW_ENTROPY_MIN_LEN", "28")
        .env("KEYCLAW_SENSITIVE_EMAILS_ENABLED", "true")
        .output()
        .expect("run doctor");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("PASS detection"), "output={out}");
    assert!(out.contains("threshold 4.25"), "output={out}");
    assert!(out.contains("min_len 28"), "output={out}");
    assert!(out.contains("typed detectors enabled"), "output={out}");
}

#[test]
fn doctor_fails_on_broken_generated_ca_pair() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ca_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&ca_dir).expect("create keyclaw dir");
    std::fs::write(ca_dir.join("ca.crt"), "not-a-cert").expect("write malformed cert");
    std::fs::write(ca_dir.join("ca.key"), "not-a-key").expect("write malformed key");

    let output = doctor_command(temp.path()).output().expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL ca-cert"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
    assert!(out.contains("remove the broken CA files"), "output={out}");
}
