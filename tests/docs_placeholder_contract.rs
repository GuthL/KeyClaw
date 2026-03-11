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
fn removed_gitleaks_bin_env_stays_out_of_runtime_contract() {
    let readme = std::fs::read_to_string("README.md").expect("read README.md");
    let config = std::fs::read_to_string("src/config.rs").expect("read src/config.rs");

    assert!(
        readme.contains("KeyClaw does not use or require `KEYCLAW_GITLEAKS_BIN`"),
        "README.md should keep the removal of KEYCLAW_GITLEAKS_BIN explicit: {readme}"
    );
    assert!(
        !config.contains("KEYCLAW_GITLEAKS_BIN"),
        "src/config.rs should not mention the removed KEYCLAW_GITLEAKS_BIN env var: {config}"
    );
}

fn normalized_agent_guide(path: &str, expected_title: &str) -> String {
    let guide = std::fs::read_to_string(path).unwrap_or_else(|_| panic!("read {path}"));

    guide.replacen(expected_title, "# AGENT_GUIDE — Agent Guide to KeyClaw", 1)
}

fn documented_error_codes() -> Vec<String> {
    let errors = std::fs::read_to_string("src/errors.rs").expect("read src/errors.rs");

    errors
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("pub const CODE_") {
                return None;
            }

            let first_quote = trimmed.find('"')?;
            let rest = &trimmed[first_quote + 1..];
            let second_quote = rest.find('"')?;
            Some(rest[..second_quote].to_string())
        })
        .collect()
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
fn agent_guides_describe_current_error_codes() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("read AGENTS.md");
    let claude = std::fs::read_to_string("CLAUDE.md").expect("read CLAUDE.md");
    let readme = std::fs::read_to_string("README.md").expect("read README.md");

    let expected_codes = documented_error_codes();
    assert!(
        !expected_codes.is_empty(),
        "src/errors.rs should define at least one documented error code"
    );

    for expected in expected_codes {
        let rendered = format!("`{expected}`");
        assert!(
            agents.contains(&rendered),
            "AGENTS.md should document shipped error code {rendered}: {agents}"
        );
        assert!(
            claude.contains(&rendered),
            "CLAUDE.md should document shipped error code {rendered}: {claude}"
        );
        assert!(
            readme.contains(&rendered),
            "README.md should document shipped error code {rendered}: {readme}"
        );
    }

    for stale in ["`blocked_by_leak_policy`", "`gitleaks_unavailable`"] {
        assert!(
            !agents.contains(stale) && !claude.contains(stale) && !readme.contains(stale),
            "Published docs should not document stale error code {stale}"
        );
    }
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
        !agents
            .contains("Edit `src/proxy.rs`. The `HttpHandler` impl on `KeyclawHttpHandler` has:"),
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
fn agent_guides_share_the_same_current_content() {
    let agents = normalized_agent_guide("AGENTS.md", "# AGENTS.md — Agent Guide to KeyClaw");
    let claude = normalized_agent_guide("CLAUDE.md", "# CLAUDE.md — Agent Guide to KeyClaw");

    assert_eq!(
        agents, claude,
        "AGENTS.md and CLAUDE.md should stay in sync aside from the top-level filename heading"
    );
}

#[test]
fn agents_guide_uses_its_own_filename_in_the_title() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("read AGENTS.md");

    assert!(
        agents.starts_with("# AGENTS.md — Agent Guide to KeyClaw"),
        "AGENTS.md should identify itself in the title: {agents}"
    );
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

#[test]
fn docs_cover_hooks_and_macos_desktop_app_flow() {
    let readme = std::fs::read_to_string("README.md").expect("read README.md");
    let docs_readme = std::fs::read_to_string("docs/README.md").expect("read docs/README.md");
    let config =
        std::fs::read_to_string("docs/configuration.md").expect("read docs/configuration.md");
    let macos =
        std::fs::read_to_string("docs/macos-gui-apps.md").expect("read docs/macos-gui-apps.md");

    assert!(
        readme.contains("macOS desktop apps")
            && readme.contains("Finder-launched apps")
            && readme.contains("docs/macos-gui-apps.md"),
        "README.md should explain the supported macOS desktop-app path: {readme}"
    );
    assert!(
        docs_readme.contains("[macOS desktop-app guide](macos-gui-apps.md)"),
        "docs/README.md should link the macOS desktop-app guide: {docs_readme}"
    );
    assert!(
        config.contains("[[hooks]]") && config.contains("- `hooks`"),
        "docs/configuration.md should document hooks as a top-level config section: {config}"
    );
    assert!(
        macos.contains("security add-trusted-cert")
            && macos.contains("networksetup -setsecurewebproxystate")
            && macos.contains("keyclaw doctor")
            && macos.contains("Roll Back"),
        "docs/macos-gui-apps.md should document CA trust, doctor guidance, system proxy setup, and rollback: {macos}"
    );
}

#[test]
fn timeout_docs_cover_rewrite_budget_and_current_default() {
    let readme = std::fs::read_to_string("README.md").expect("read README.md");
    let config =
        std::fs::read_to_string("docs/configuration.md").expect("read docs/configuration.md");

    assert!(
        readme.contains("`KEYCLAW_DETECTOR_TIMEOUT` | `20s`")
            && readme.contains("request-body collection and rewrite")
            && readme.contains("Large top-level `prompt` or `instructions` strings"),
        "README.md should document the current timeout default and rewrite scope: {readme}"
    );
    assert!(
        config.contains("`KEYCLAW_DETECTOR_TIMEOUT` | `20s`")
            && config.contains("collection and rewrite")
            && config.contains("Large top-level `prompt` or `instructions` strings"),
        "docs/configuration.md should document the current timeout default and rewrite scope: {config}"
    );
}

#[test]
fn proxy_docs_prefer_sourcing_env_script_and_describe_reboot_behavior() {
    let agents = std::fs::read_to_string("AGENTS.md").expect("read AGENTS.md");
    let claude = std::fs::read_to_string("CLAUDE.md").expect("read CLAUDE.md");
    let readme = std::fs::read_to_string("README.md").expect("read README.md");

    for (name, doc) in [("AGENTS.md", &agents), ("CLAUDE.md", &claude)] {
        assert!(
            doc.contains("source ~/.keyclaw/env.sh"),
            "{name} should point operators at sourcing ~/.keyclaw/env.sh: {doc}"
        );
        assert!(
            !doc.contains("eval \"$(keyclaw proxy)\""),
            "{name} should not recommend eval-based shell setup anymore: {doc}"
        );
    }

    assert!(
        readme.contains("source ~/.keyclaw/env.sh"),
        "README.md should point operators at sourcing ~/.keyclaw/env.sh: {readme}"
    );
    assert!(
        readme.contains("One terminal:")
            && readme.contains("Two terminals:")
            && readme.contains("> **Warning:** `eval \"$(keyclaw proxy)\"`"),
        "README.md should lead with one-terminal and two-terminal source-based setup, and keep eval behind a warning: {readme}"
    );

    assert!(
        readme.contains("does not auto-start again after reboot")
            || readme.contains("does not auto-start after reboot"),
        "README.md should explain detached proxy reboot behavior: {readme}"
    );
}

#[test]
fn readme_configuration_section_covers_inline_and_persistent_env_overrides() {
    let readme = std::fs::read_to_string("README.md").expect("read README.md");

    assert!(
        readme.contains("~/.keyclaw/config.toml")
            && readme.contains("env vars > ~/.keyclaw/config.toml > built-in defaults"),
        "README.md should describe the TOML config file path and precedence: {readme}"
    );
    assert!(
        readme.contains("### Config File")
            && readme.contains("[proxy]")
            && readme.contains("[logging]")
            && readme.contains("[notice]")
            && readme.contains("[detection]")
            && readme.contains("[audit]")
            && readme.contains("[hosts]")
            && readme.contains("[allowlist]"),
        "README.md should include a concrete config.toml example with the supported sections: {readme}"
    );
    assert!(
        readme.contains("rule_ids")
            && readme.contains("patterns")
            && readme.contains("secret_sha256")
            && readme.contains("sha256sum")
            && readme.contains("KEYCLAW_AUDIT_LOG")
            && readme.contains("[audit] path = \"off\""),
        "README.md should document the allowlist entry types, audit log controls, and how to compute exact secret hashes: {readme}"
    );
    assert!(
        readme.contains("### Setting Variables"),
        "README.md should include a dedicated config-setting section: {readme}"
    );
    assert!(
        readme.contains("Inline for one command:")
            && readme.contains("Persistent for the current shell session:")
            && readme.contains("Persistent across new shells:"),
        "README.md should show inline, current-shell, and persistent-shell config flows: {readme}"
    );
    assert!(
        readme.contains("daemon-side settings are read when that proxy process starts")
            && readme.contains("restart the proxy so the running daemon picks them up")
            && readme.contains("After changing `~/.keyclaw/config.toml`"),
        "README.md should explain that detached proxy config changes require a restart: {readme}"
    );
}
