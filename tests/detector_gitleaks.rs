use std::fs;
use std::time::Duration;

use keyclaw::detector::Detector;

#[test]
fn parse_gitleaks_report() {
    let findings = keyclaw::detector::parse_gitleaks_report(
        br#"[{"RuleID":"openai","Description":"token","Secret":"***"}]"#,
    )
    .expect("parse");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "openai");
}

#[cfg(unix)]
#[test]
fn gitleaks_timeout_triggers_unavailable_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = dir.path().join("fake-gitleaks-timeout.sh");
    fs::write(&script, "#!/bin/sh\ncat >/dev/null\nsleep 2\necho '[]'\n").expect("write");

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");

    let d = keyclaw::detector::GitleaksDetector::new(
        script.to_string_lossy().into_owned(),
        Duration::from_millis(100),
    );
    let err = d.detect(b"{}").expect_err("expected timeout");
    assert_eq!(
        keyclaw::errors::code_of(&err),
        Some(keyclaw::errors::CODE_GITLEAKS_UNAVAILABLE)
    );
}

#[cfg(unix)]
#[test]
fn gitleaks_parses_findings_from_non_zero_exit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = dir.path().join("fake-gitleaks-findings.sh");
    fs::write(
        &script,
        "#!/bin/sh\ncat >/dev/null\necho '[{\"RuleID\":\"test-rule\",\"Description\":\"desc\",\"Secret\":\"***\"}]'\nexit 1\n",
    )
    .expect("write");

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");

    let d = keyclaw::detector::GitleaksDetector::new(
        script.to_string_lossy().into_owned(),
        Duration::from_secs(2),
    );
    let findings = d.detect(b"{}").expect("detect should parse findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "test-rule");
}
