#[test]
fn docs_route_secret_pattern_work_to_gitleaks_rules() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("read AGENTS.md");
    let contributing = std::fs::read_to_string("CONTRIBUTING.md").expect("read CONTRIBUTING.md");
    let readme = std::fs::read_to_string("README.md").expect("read README.md");

    assert!(
        agents.contains("Edit `gitleaks.toml`"),
        "AGENTS.md should point new secret-pattern work at the bundled gitleaks rules: {agents}"
    );
    assert!(
        !agents.contains("Edit `src/placeholder.rs` → `replace_secrets()`"),
        "AGENTS.md should not point secret-pattern work at placeholder.rs anymore: {agents}"
    );
    assert!(
        contributing.contains("Adding new secret detection patterns to `gitleaks.toml`"),
        "CONTRIBUTING.md should point secret-pattern work at gitleaks.toml: {contributing}"
    );
    assert!(
        readme.contains("gitleaks.toml") && readme.contains("Bundled detection rules"),
        "README.md should describe the bundled rule source explicitly: {readme}"
    );
}

#[test]
fn docs_describe_the_current_placeholder_shape() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("read AGENTS.md");

    assert!(
        agents.contains("{{KEYCLAW_SECRET_<prefix>_<16 hex chars>}}"),
        "AGENTS.md should describe the current placeholder shape with the visible prefix segment: {agents}"
    );
}

#[test]
fn agent_guide_points_common_edits_at_split_modules() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("read AGENTS.md");

    assert!(
        agents.contains("src/proxy/http.rs")
            && agents.contains("src/proxy/streaming.rs")
            && agents.contains("src/proxy/websocket.rs"),
        "AGENTS.md should point proxy changes at the split proxy modules: {agents}"
    );
    assert!(
        !agents.contains("Edit `src/proxy.rs`. The `HttpHandler` impl on `KeyclawHttpHandler` has:"),
        "AGENTS.md should not describe proxy changes as if src/proxy.rs still held the handler implementation: {agents}"
    );
    assert!(
        agents.contains("src/launcher/bootstrap.rs"),
        "AGENTS.md should point CLI command behavior at the split launcher modules: {agents}"
    );
}

#[test]
fn agent_module_map_matches_the_current_source_tree() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("read AGENTS.md");

    for expected in [
        "`gitleaks_rules.rs`",
        "`proxy/common.rs`",
        "`proxy/http.rs`",
        "`proxy/streaming.rs`",
        "`proxy/websocket.rs`",
        "`launcher/bootstrap.rs`",
        "`launcher/doctor.rs`",
    ] {
        assert!(
            agents.contains(expected),
            "AGENTS.md should list {expected} in the module map: {agents}"
        );
    }

    for stale in [
        "`policy.rs`",
        "`detector/embedded.rs`",
        "`detector/gitleaks.rs`",
    ] {
        assert!(
            !agents.contains(stale),
            "AGENTS.md should not list stale module {stale}: {agents}"
        );
    }
}

#[test]
fn readme_project_structure_shows_split_proxy_and_launcher_modules() {
    let readme = std::fs::read_to_string("README.md").expect("read README.md");

    for expected in [
        "proxy/",
        "│   ├── http.rs",
        "│   ├── streaming.rs",
        "│   └── websocket.rs",
        "launcher/",
        "│   ├── bootstrap.rs",
        "│   └── doctor.rs",
    ] {
        assert!(
            readme.contains(expected),
            "README.md should include {expected} in the project structure section: {readme}"
        );
    }
}
