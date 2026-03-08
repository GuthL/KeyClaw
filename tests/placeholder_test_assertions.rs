#[test]
fn generic_placeholder_assertions_use_shared_helpers() {
    for path in [
        "src/proxy/websocket.rs",
        "tests/e2e_cli_support.rs",
        "tests/integration_proxy.rs",
        "tests/pipeline.rs",
    ] {
        let source = std::fs::read_to_string(path).expect("read source");
        assert!(
            source.contains("contains_complete_placeholder"),
            "{path} should use the shared placeholder helper"
        );
        assert!(
            !source.contains("contains(\"{{KEYCLAW_SECRET_\")"),
            "{path} should not use raw placeholder-prefix assertions"
        );
        assert!(
            !source.contains("contains(\"KEYCLAW_SECRET_\")"),
            "{path} should not use raw placeholder marker assertions"
        );
    }
}
