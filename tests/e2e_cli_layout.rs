#[test]
fn e2e_cli_file_stays_focused_on_scenarios() {
    let e2e_cli = std::fs::read_to_string("tests/e2e_cli.rs").expect("read tests/e2e_cli.rs");

    assert!(
        e2e_cli.contains("mod support;"),
        "tests/e2e_cli.rs should import shared CLI harness helpers from tests/support: {e2e_cli}"
    );

    for helper in [
        "fn run_mitm(",
        "fn run_mitm_with_log_level(",
        "fn keyclaw_command(",
        "fn doctor_command(",
        "fn rewrite_json_command(",
        "fn can_bind(",
        "fn wait_until(",
        "fn start_upstream(",
        "fn free_addr(",
    ] {
        assert!(
            !e2e_cli.contains(helper),
            "tests/e2e_cli.rs should not keep helper `{helper}` after the harness extraction: {e2e_cli}"
        );
    }
}

#[test]
fn slow_daemon_and_proxy_scenarios_are_explicitly_ignored() {
    let proxy = std::fs::read_to_string("tests/e2e_cli/proxy.rs").expect("read proxy.rs");
    let lifecycle = std::fs::read_to_string("tests/e2e_cli/process_lifecycle.rs")
        .expect("read process_lifecycle.rs");

    let marker = "#[ignore = \"slow daemon/proxy e2e\"]";
    assert!(
        proxy.contains(marker),
        "tests/e2e_cli/proxy.rs should mark slow daemon/proxy scenarios as ignored: {proxy}"
    );
    assert!(
        lifecycle.contains(marker),
        "tests/e2e_cli/process_lifecycle.rs should mark slow lifecycle scenarios as ignored: {lifecycle}"
    );
}
