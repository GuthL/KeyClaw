fn normalized_agent_guide(path: &str, expected_title: &str) -> String {
    let guide = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("read {path}"));
    guide.replacen(expected_title, "# AGENT_GUIDE — Agent Guide to KeyClaw", 1)
}

#[test]
fn contributor_and_agent_docs_point_at_the_sensitive_engine() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("read AGENTS.md");
    let claude = std::fs::read_to_string("CLAUDE.md").expect("read CLAUDE.md");
    let contributing = std::fs::read_to_string("CONTRIBUTING.md").expect("read CONTRIBUTING.md");

    for expected in [
        "`src/sensitive.rs`",
        "`tests/placeholder.rs`",
        "`tests/pipeline.rs`",
        "`tests/integration_proxy.rs`",
    ] {
        assert!(
            agents.contains(expected),
            "AGENTS.md missing {expected}: {agents}"
        );
        assert!(
            claude.contains(expected),
            "CLAUDE.md missing {expected}: {claude}"
        );
    }

    assert!(
        contributing.contains("src/sensitive.rs")
            && contributing.contains("cargo test --test pipeline"),
        "CONTRIBUTING.md should route detector work through the sensitive engine: {contributing}"
    );

    for stale in [
        "gitleaks.toml",
        "gitleaks_rules.rs",
        "KEYCLAW_GITLEAKS_CONFIG",
        "vault.enc",
        "vault.key",
    ] {
        assert!(
            !agents.contains(stale) && !claude.contains(stale) && !contributing.contains(stale),
            "Contributor-facing docs should not mention stale runtime detail {stale}"
        );
    }
}

#[test]
fn operator_docs_describe_session_scoped_runtime() {
    let readme = std::fs::read_to_string("README.md").expect("read README.md");
    let config =
        std::fs::read_to_string("docs/configuration.md").expect("read docs/configuration.md");
    let architecture =
        std::fs::read_to_string("docs/architecture.md").expect("read docs/architecture.md");
    let patterns =
        std::fs::read_to_string("docs/secret-patterns.md").expect("read docs/secret-patterns.md");
    let threat =
        std::fs::read_to_string("docs/threat-model.md").expect("read docs/threat-model.md");

    for expected in ["session-scoped", "KEYCLAW_OPAQUE", "opaque_token"] {
        assert!(
            readme.contains(expected),
            "README.md missing {expected}: {readme}"
        );
    }

    assert!(
        config.contains("[sensitive]") && config.contains("KEYCLAW_SENSITIVE_SESSION_TTL"),
        "docs/configuration.md should document typed sensitive-data config: {config}"
    );
    assert!(
        architecture.contains("session-scoped store") && architecture.contains("src/sensitive.rs"),
        "docs/architecture.md should describe the new runtime center: {architecture}"
    );
    assert!(
        patterns.contains("opaque token") && patterns.contains("src/sensitive.rs"),
        "docs/secret-patterns.md should describe the v2 detector model: {patterns}"
    );
    assert!(
        threat.contains("session-scoped store") && !threat.contains("vault"),
        "docs/threat-model.md should describe the new trust boundary: {threat}"
    );

    for stale in [
        "KEYCLAW_VAULT_PATH",
        "KEYCLAW_VAULT_PASSPHRASE",
        "KEYCLAW_GITLEAKS_CONFIG",
        "kingfisher",
        "gitleaks_rules.rs",
        "vault.rs",
    ] {
        assert!(
            !readme.contains(stale) && !config.contains(stale) && !architecture.contains(stale),
            "Operator docs should not mention stale runtime detail {stale}"
        );
    }
}

#[test]
fn agent_guides_stay_in_sync() {
    let agents = normalized_agent_guide("AGENTS.md", "# AGENTS.md — Agent Guide to KeyClaw");
    let claude = normalized_agent_guide("CLAUDE.md", "# CLAUDE.md — Agent Guide to KeyClaw");

    assert_eq!(
        agents, claude,
        "AGENTS.md and CLAUDE.md should stay in sync aside from the heading"
    );
}
