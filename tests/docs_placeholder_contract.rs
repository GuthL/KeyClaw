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
