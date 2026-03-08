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
fn production_readiness_project_records_issue_one_decisions() {
    let project = std::fs::read_to_string("docs/plans/2026-03-07-production-readiness-project.md")
        .expect("read docs/plans/2026-03-07-production-readiness-project.md");
    let issue_one = issue_section(&project, "### Issue #1", "### Issue #2");

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

    assert!(
        issue_one.contains("Decision summary:"),
        "issue #1 should preserve the locked-scope summary in the project mirror: {issue_one}"
    );
}

#[test]
fn production_readiness_project_mirror_defers_live_status_to_github() {
    let project = std::fs::read_to_string("docs/plans/2026-03-07-production-readiness-project.md")
        .expect("read docs/plans/2026-03-07-production-readiness-project.md");
    let sync_script = std::fs::read_to_string("scripts/sync-production-readiness-project.py")
        .expect("read scripts/sync-production-readiness-project.py");

    assert!(
        project.contains("GitHub is the source of truth for live issue state"),
        "project mirror should explicitly defer live issue state to GitHub: {project}"
    );
    assert!(
        project.contains("scripts/sync-production-readiness-project.py"),
        "project mirror should document the refresh script: {project}"
    );
    assert!(
        !project.contains("| Issue | Milestone | Status |"),
        "project mirror should not keep a manual status column that can drift: {project}"
    );
    assert!(
        !project.contains("\nStatus: "),
        "project mirror should not keep per-issue status fields that can drift: {project}"
    );
    assert!(
        sync_script.contains("docs/plans/2026-03-07-production-readiness-project.md"),
        "sync script should target the production-readiness mirror: {sync_script}"
    );
}

fn issue_section<'a>(project: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = project.find(start_marker).expect("issue start");
    let rest = &project[start..];
    let end = rest.find(end_marker).expect("issue end");
    &rest[..end]
}
