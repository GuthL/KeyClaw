#[test]
fn placeholder_prefix_fast_paths_stay_shared() {
    let placeholder = std::fs::read_to_string("src/placeholder.rs").expect("read placeholder.rs");
    assert!(
        placeholder.contains("pub(crate) fn contains_placeholder_prefix"),
        "src/placeholder.rs should own the shared fast-path helper"
    );

    for path in [
        "src/pipeline.rs",
        "src/proxy/http.rs",
        "src/proxy/websocket.rs",
    ] {
        let source = std::fs::read_to_string(path).expect("read source");
        let production = source.split("#[cfg(test)]").next().unwrap_or(&source);
        assert!(
            production.contains("contains_placeholder_prefix"),
            "{path} should use the shared fast-path helper"
        );
        assert!(
            !production.contains("\"{{KEYCLAW_SECRET_\""),
            "{path} should not hard-code the placeholder prefix"
        );
    }
}
