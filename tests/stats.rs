use keyclaw::stats::summarize_audit_log;

#[test]
fn summarize_audit_log_aggregates_redactions_by_rule_and_host() {
    let temp = tempfile::tempdir().expect("tempdir");
    let audit_log = temp.path().join("audit.log");
    std::fs::write(
        &audit_log,
        concat!(
            "{\"ts\":\"2026-03-10T00:00:00Z\",\"rule_id\":\"opaque.high_entropy\",\"kind\":\"opaque_token\",\"request_host\":\"stdin\",\"action\":\"redacted\"}\n",
            "{\"ts\":\"2026-03-10T00:00:01Z\",\"rule_id\":\"opaque.high_entropy\",\"kind\":\"opaque_token\",\"request_host\":\"api.openai.com\",\"action\":\"redacted\"}\n",
            "{\"ts\":\"2026-03-10T00:00:02Z\",\"rule_id\":\"typed.email\",\"kind\":\"email\",\"request_host\":\"api.openai.com\",\"action\":\"redacted\"}\n"
        ),
    )
    .expect("write audit log");

    let summary = summarize_audit_log(&audit_log).expect("summarize audit log");

    assert_eq!(summary.total_redactions, 3);
    assert_eq!(
        summary.latest_event.as_deref(),
        Some("2026-03-10T00:00:02Z")
    );
    assert_eq!(summary.top_rules[0].name, "opaque.high_entropy");
    assert_eq!(summary.top_rules[0].count, 2);
    assert_eq!(summary.top_rules[1].name, "typed.email");
    assert_eq!(summary.top_rules[1].count, 1);
    assert_eq!(summary.top_hosts[0].name, "api.openai.com");
    assert_eq!(summary.top_hosts[0].count, 2);
    assert_eq!(summary.top_hosts[1].name, "stdin");
    assert_eq!(summary.top_hosts[1].count, 1);
    assert_eq!(summary.top_kinds[0].name, "opaque_token");
    assert_eq!(summary.top_kinds[0].count, 2);
    assert_eq!(summary.top_kinds[1].name, "email");
    assert_eq!(summary.top_kinds[1].count, 1);
}

#[test]
fn summarize_audit_log_treats_missing_file_as_empty() {
    let temp = tempfile::tempdir().expect("tempdir");

    let summary = summarize_audit_log(&temp.path().join("missing.log")).expect("empty summary");

    assert_eq!(summary.total_redactions, 0);
    assert!(summary.latest_event.is_none());
    assert!(summary.top_rules.is_empty());
    assert!(summary.top_hosts.is_empty());
    assert!(summary.top_kinds.is_empty());
}
