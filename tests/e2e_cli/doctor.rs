use std::process::Command;

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
fn doctor_fails_on_invalid_custom_gitleaks_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing-gitleaks.toml");
    let output = doctor_command(temp.path())
        .env("KEYCLAW_GITLEAKS_CONFIG", &missing)
        .output()
        .expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL ruleset"), "output={out}");
    assert!(out.contains("missing-gitleaks.toml"), "output={out}");
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
fn doctor_warns_when_custom_ruleset_skips_invalid_rules() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("gitleaks.toml");
    std::fs::write(
        &config,
        r#"
[[rules]]
id = "valid"
regex = '''([A-Za-z0-9]{8,})'''
keywords = ["api_key"]
secretGroup = 1

[[rules]]
id = "broken"
regex = "("
keywords = ["broken"]
"#,
    )
    .expect("write gitleaks config");

    let output = doctor_command(temp.path())
        .env("KEYCLAW_GITLEAKS_CONFIG", &config)
        .env("KEYCLAW_LOG_LEVEL", "error")
        .output()
        .expect("run doctor");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(out.contains("WARN ruleset"), "output={out}");
    assert!(out.contains("skipped 1 invalid rule"), "output={out}");
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
}

#[test]
fn doctor_reports_clean_healthcheck() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path()).output().expect("run doctor");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("PASS proxy-bind"), "output={out}");
    assert!(out.contains("PASS ca-cert"), "output={out}");
    assert!(out.contains("PASS ruleset"), "output={out}");
    assert!(out.contains("doctor: summary:"), "output={out}");
    assert!(!out.contains("WARN "), "output={out}");
    assert!(!out.contains("FAIL "), "output={out}");
}

#[test]
fn doctor_fails_when_existing_vault_key_is_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault.enc");
    let store = keyclaw::vault::Store::new(vault_path.clone(), "custom-passphrase".to_string());

    let mut entries = std::collections::HashMap::new();
    entries.insert(
        "api_key".to_string(),
        "sk-ABCDEF0123456789ABCDEF0123456789".to_string(),
    );
    store.save(&entries).expect("seed vault");

    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let output = Command::new(bin)
        .arg("doctor")
        .env_clear()
        .env("HOME", temp.path())
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "true")
        .env("KEYCLAW_VAULT_PATH", &vault_path)
        .output()
        .expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL vault-key"), "output={out}");
    assert!(out.contains("vault key"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
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
