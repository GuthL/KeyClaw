#[test]
fn bootstrap_module_stays_split_into_focused_components() {
    let source = std::fs::read_to_string("src/launcher/bootstrap.rs").expect("read bootstrap.rs");

    for module in [
        "mod autostart;",
        "mod detection;",
        "mod no_proxy;",
        "mod proxy_daemon;",
        "mod runner;",
    ] {
        assert!(
            source.contains(module),
            "src/launcher/bootstrap.rs should declare {module}"
        );
    }

    for legacy_marker in [
        "impl Runner {",
        "fn load_runtime_ruleset(",
        "fn read_and_validate_proxy_pid(",
        "enum NoProxyEntry",
        "fn wait_for_detached_proxy_ready(",
    ] {
        assert!(
            !source.contains(legacy_marker),
            "src/launcher/bootstrap.rs should delegate instead of containing `{legacy_marker}`"
        );
    }
}
