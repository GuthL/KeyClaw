#[test]
fn proxy_module_stays_split_into_focused_components() {
    let source = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    for module in [
        "mod common;",
        "mod http;",
        "mod streaming;",
        "mod websocket;",
    ] {
        assert!(
            source.contains(module),
            "src/proxy.rs should declare {module}"
        );
    }

    for legacy_marker in [
        "impl HttpHandler for KeyclawHttpHandler",
        "impl WebSocketHandler for KeyclawHttpHandler",
        "struct SseStreamResolver",
        "fn normalize_host(",
    ] {
        assert!(
            !source.contains(legacy_marker),
            "src/proxy.rs should delegate instead of containing `{legacy_marker}`"
        );
    }
}
