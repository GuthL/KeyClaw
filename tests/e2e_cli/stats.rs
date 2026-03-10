use crate::support::keyclaw_command;

#[test]
fn proxy_stats_reads_audit_log_and_prints_summary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let audit_log = temp.path().join("audit.log");
    std::fs::write(
        &audit_log,
        concat!(
            "{\"ts\":\"2026-03-10T00:00:00Z\",\"rule_id\":\"generic-api-key\",\"request_host\":\"stdin\",\"action\":\"redacted\"}\n",
            "{\"ts\":\"2026-03-10T00:00:01Z\",\"rule_id\":\"aws-access-key\",\"request_host\":\"api.openai.com\",\"action\":\"redacted\"}\n",
            "{\"ts\":\"2026-03-10T00:00:02Z\",\"rule_id\":\"generic-api-key\",\"request_host\":\"api.openai.com\",\"action\":\"redacted\"}\n"
        ),
    )
    .expect("write audit log");

    let output = keyclaw_command(temp.path())
        .arg("proxy")
        .arg("stats")
        .env("KEYCLAW_AUDIT_LOG", &audit_log)
        .output()
        .expect("run proxy stats");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(out.contains("Total redactions: 3"), "stdout={out}");
    assert!(out.contains("generic-api-key"), "stdout={out}");
    assert!(out.contains("api.openai.com"), "stdout={out}");
    assert!(err.trim().is_empty(), "stderr={err}");
}
