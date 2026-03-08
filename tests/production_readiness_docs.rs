#[test]
fn production_readiness_plan_locks_v0x_release_decisions() {
    let plan = std::fs::read_to_string("docs/plans/2026-03-07-production-readiness.md")
        .expect("read docs/plans/2026-03-07-production-readiness.md");

    assert!(
        plan.contains("## Locked v0.x Decisions"),
        "production readiness plan should record the resolved v0.x decisions: {plan}"
    );
    assert!(
        plan.contains("x86_64-unknown-linux-gnu")
            && plan.contains("x86_64-apple-darwin")
            && plan.contains("aarch64-apple-darwin"),
        "production readiness plan should name the supported platform matrix: {plan}"
    );
    assert!(
        plan.contains("machine-local") && plan.contains("vault.key"),
        "production readiness plan should record the chosen vault-key strategy: {plan}"
    );
    assert!(
        plan.contains("README-first") && plan.contains("no dedicated docs site"),
        "production readiness plan should record the documentation format decision: {plan}"
    );
    assert!(
        plan.contains("structured logging") && plan.contains("not a launch blocker"),
        "production readiness plan should record the logging-scope decision: {plan}"
    );
    assert!(
        plan.contains("notice") && plan.contains("deferred"),
        "production readiness plan should record the notice-mode decision: {plan}"
    );
    assert!(
        !plan.contains("## Open Decisions"),
        "production readiness plan should not leave v0.x release decisions open: {plan}"
    );
}

#[test]
fn production_readiness_project_marks_issue_one_done() {
    let project = std::fs::read_to_string("docs/plans/2026-03-07-production-readiness-project.md")
        .expect("read docs/plans/2026-03-07-production-readiness-project.md");
    let issue_one = issue_section(&project, "### Issue #1", "### Issue #2");

    assert!(
        issue_one.contains("Status: Done"),
        "issue #1 should be marked done in the project mirror: {issue_one}"
    );

    for criterion in [
        "- [x] The supported platform matrix is explicitly documented.",
        "- [x] The vault/key-management approach for v0.x is explicitly decided and recorded.",
        "- [x] The documentation format decision is recorded.",
        "- [x] The logging-scope decision is recorded.",
        "- [x] The notice-mode decision is recorded.",
        "- [x] The plan and project backlog reflect the final decisions with no remaining release-blocking ambiguity.",
    ] {
        assert!(
            issue_one.contains(criterion),
            "issue #1 acceptance should be checked off for `{criterion}`: {issue_one}"
        );
    }
}

fn issue_section<'a>(project: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = project.find(start_marker).expect("issue start");
    let rest = &project[start..];
    let end = rest.find(end_marker).expect("issue end");
    &rest[..end]
}
