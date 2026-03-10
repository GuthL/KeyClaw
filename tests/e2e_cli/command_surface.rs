use crate::support::keyclaw_command;

#[test]
fn help_flag_returns_success_and_lists_supported_subcommands() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = keyclaw_command(temp.path())
        .arg("--help")
        .output()
        .expect("run --help");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(out.contains("Usage:"), "stdout={out}");
    assert!(out.contains("proxy"), "stdout={out}");
    assert!(out.contains("mitm"), "stdout={out}");
    assert!(out.contains("codex"), "stdout={out}");
    assert!(out.contains("claude"), "stdout={out}");
    assert!(out.contains("init"), "stdout={out}");
    assert!(out.contains("rewrite-json"), "stdout={out}");
    assert!(out.contains("doctor"), "stdout={out}");
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
}

#[test]
fn short_help_flag_returns_success_and_lists_supported_subcommands() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = keyclaw_command(temp.path())
        .arg("-h")
        .output()
        .expect("run -h");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(out.contains("Usage:"), "stdout={out}");
    assert!(out.contains("proxy"), "stdout={out}");
    assert!(out.contains("mitm"), "stdout={out}");
    assert!(out.contains("codex"), "stdout={out}");
    assert!(out.contains("claude"), "stdout={out}");
    assert!(out.contains("init"), "stdout={out}");
    assert!(out.contains("rewrite-json"), "stdout={out}");
    assert!(out.contains("doctor"), "stdout={out}");
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
}

#[test]
fn version_flag_returns_success_and_prints_crate_version() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = keyclaw_command(temp.path())
        .arg("--version")
        .output()
        .expect("run --version");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(out.trim(), format!("keyclaw {}", env!("CARGO_PKG_VERSION")));
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
}

#[test]
fn invalid_top_level_argument_returns_actionable_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = keyclaw_command(temp.path())
        .arg("--wat")
        .output()
        .expect("run invalid arg");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(out.trim().is_empty(), "stdout={out}");
    assert!(err.contains("--wat"), "stderr={err}");
    assert!(err.contains("Usage:"), "stderr={err}");
    assert!(err.contains("--help"), "stderr={err}");
}
