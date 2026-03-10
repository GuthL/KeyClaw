use keyclaw::gitleaks_rules::{MatchConfidence, MatchSource, RuleSet};
use keyclaw::placeholder::{
    contains_complete_placeholder, find_partial_placeholder_start, is_placeholder, make, make_id,
    replace_secrets, resolve_placeholders, CONTRACT_MARKER_KEY, EXAMPLE_PLACEHOLDER,
};

fn bundled_rules() -> RuleSet {
    RuleSet::bundled().expect("bundled rules")
}

fn bundled_rules_without_entropy() -> RuleSet {
    let mut rules = bundled_rules();
    rules.entropy_config.enabled = false;
    rules
}

#[test]
fn replace_and_resolve_placeholders_roundtrip() {
    let rules = bundled_rules();
    // Use generic-api-key pattern: "api_key = <high-entropy-value>"
    let input = "my api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v and secret_key: xY2zW4vU6tS8rQ0pO2nM4lK6jI8hG0f";
    let (rewritten, replacements) = replace_secrets(input, &rules, 0, |secret| {
        Ok(keyclaw::placeholder::make_id(secret))
    })
    .expect("replace should succeed");

    assert!(
        !replacements.is_empty(),
        "expected at least one replacement, input={input}, rewritten={rewritten}"
    );
    assert_ne!(rewritten, input);

    let resolved = resolve_placeholders(&rewritten, true, |id| {
        let found = replacements
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.secret.clone());
        Ok(found)
    })
    .expect("resolve should succeed");

    assert_eq!(resolved, input);
}

#[test]
fn strict_resolve_fails_on_missing_secret() {
    let err = resolve_placeholders("value {{KEYCLAW_SECRET_a_aaaaaaaaaaaaaaaa}}", true, |_| {
        Ok(None)
    });
    assert!(err.is_err());
}

#[test]
fn gitleaks_rules_load_successfully() {
    let rules = bundled_rules();
    assert!(
        rules.rules.len() > 200,
        "expected 200+ rules, got {}",
        rules.rules.len()
    );
}

#[test]
fn bundled_rule_allowlists_skip_known_gcp_example_keys() {
    let rules = bundled_rules_without_entropy();
    let matches = rules.find_secrets("AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs");

    assert!(
        matches.is_empty(),
        "bundled gcp example key should be allowlisted, got {matches:?}"
    );
}

#[test]
fn bundled_rule_match_allowlists_skip_generic_token_file_assignments() {
    let rules = bundled_rules_without_entropy();
    let input = "token_file = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
    let matches = rules.find_secrets(input);

    assert!(
        matches.is_empty(),
        "generic token_file assignment should be skipped by rule match allowlist, got {matches:?}"
    );
}

#[test]
fn bundled_rule_stopwords_skip_known_generic_examples() {
    let rules = bundled_rules_without_entropy();
    let input = "api_key = 6fe4476ee5a1832882e326b506d14126";
    let matches = rules.find_secrets(input);

    assert!(
        matches.is_empty(),
        "generic rule stopword should suppress known example, got {matches:?}"
    );
}

#[test]
fn generic_api_key_rule_preserves_assignment_boundaries() {
    let rules = bundled_rules();
    let input = concat!(
        "install K_API_KEY: f47ac10b-58cc-4372-a567-0e02b2c3d479 in .env\n",
        "then set K_API_KEY = c9bf9e57-1685-4d46-a09f-3a1c5ee70b82\n",
    );

    let (rewritten, replacements) = replace_secrets(input, &rules, 0, |secret| {
        Ok(keyclaw::placeholder::make_id(secret))
    })
    .expect("replace should succeed");

    assert_eq!(replacements.len(), 2, "rewritten={rewritten}");
    assert!(
        rewritten.contains("K_API_KEY: {{KEYCLAW_SECRET_"),
        "rewritten={rewritten}"
    );
    assert!(
        rewritten.contains("K_API_KEY = {{KEYCLAW_SECRET_"),
        "rewritten={rewritten}"
    );
    assert!(rewritten.contains("}} in .env"), "rewritten={rewritten}");
    assert!(rewritten.ends_with("}}\n"), "rewritten={rewritten}");
}

#[test]
fn partial_placeholder_detection_handles_short_marker_prefixes() {
    assert_eq!(find_partial_placeholder_start("{"), Some(0));
    assert_eq!(find_partial_placeholder_start("abc{{KE"), Some(3));
    assert_eq!(
        find_partial_placeholder_start("abc{{KEYCLAW_SECRET_prefx_0123456789abcde"),
        Some(3)
    );
    assert_eq!(
        find_partial_placeholder_start("{{KEYCLAW_SECRET_prefx_0123456789abcdef}}"),
        None
    );
}

#[test]
fn make_exact_matching_and_partial_detection_share_the_same_contract() {
    let placeholder = make("prefx_0123456789abcdef");

    assert!(is_placeholder(&placeholder));
    assert!(!is_placeholder(&format!("{placeholder}x")));
    assert_eq!(find_partial_placeholder_start(&placeholder), None);

    for len in 1..placeholder.len() {
        assert_eq!(
            find_partial_placeholder_start(&placeholder[..len]),
            Some(0),
            "prefix len={len}"
        );
    }
}

#[test]
fn resolve_placeholders_handles_star_prefixed_ids() {
    let secret = "é漢";
    let id = make_id(secret);
    let placeholder = make(&id);

    assert!(is_placeholder(&placeholder), "placeholder={placeholder}");
    assert_eq!(find_partial_placeholder_start(&placeholder), None);

    let resolved = resolve_placeholders(&placeholder, true, |seen_id| {
        assert_eq!(seen_id, id);
        Ok(Some(secret.to_string()))
    })
    .expect("resolve placeholder");

    assert_eq!(resolved, secret);
}

#[test]
fn overlap_resolution_prefers_higher_confidence_specific_rules() {
    let mut rules = RuleSet::from_toml(
        r#"
[[rules]]
id = "generic-api-key"
regex = 'token=([A-Z0-9]{16})'
secretGroup = 1
entropy = 1
keywords = ["token"]

[[rules]]
id = "anthropic-api-key"
regex = 'token=(ABCD[A-Z0-9]{12})'
secretGroup = 1
entropy = 1
keywords = ["token"]
"#,
    )
    .expect("rules");
    rules.entropy_config.enabled = false;

    let matches = rules.find_secrets("token=ABCD1234EFGH5678");

    assert_eq!(matches.len(), 1, "{matches:?}");
    assert_eq!(matches[0].rule_id, "anthropic-api-key");
    assert_eq!(matches[0].source, MatchSource::Regex);
    assert_eq!(matches[0].confidence, MatchConfidence::High);
    assert!(
        matches[0].confidence_score > 80,
        "expected strong confidence, got {:?}",
        matches[0]
    );
}

#[test]
fn replacements_keep_confidence_metadata() {
    let mut rules = RuleSet::from_toml(
        r#"
[[rules]]
id = "anthropic-api-key"
regex = 'token=(ABCD[A-Z0-9]{12})'
secretGroup = 1
entropy = 1
keywords = ["token"]
"#,
    )
    .expect("rules");
    rules.entropy_config.enabled = false;

    let (_rewritten, replacements) =
        replace_secrets("token=ABCD1234EFGH5678", &rules, 0, |secret| {
            Ok(keyclaw::placeholder::make_id(secret))
        })
        .expect("replace");

    assert_eq!(replacements.len(), 1);
    assert_eq!(replacements[0].source, MatchSource::Regex);
    assert_eq!(replacements[0].confidence, MatchConfidence::High);
    assert!(replacements[0].confidence_score > 80);
}

#[test]
fn complete_placeholder_detection_matches_only_real_placeholders() {
    let placeholder = make("prefx_0123456789abcdef");

    assert!(contains_complete_placeholder(&format!(
        "value {placeholder}"
    )));
    assert!(!contains_complete_placeholder(
        "value {{KEYCLAW_SECRET_xxxx}}"
    ));
    assert!(!contains_complete_placeholder(
        "value {{KEYCLAW_SECRET_prefx_0123456789abcde"
    ));
}

#[test]
fn resolve_placeholders_partially_resolves_when_later_ids_are_missing() {
    let known = make("prefx_0123456789abcdef");
    let missing = make("api_k_0123456789abcdef");
    let input = format!("before {known} after {missing}");

    let resolved = resolve_placeholders(&input, false, |id| {
        Ok((id == "prefx_0123456789abcdef").then(|| "super-secret".to_string()))
    })
    .expect("resolve placeholders");

    assert_eq!(resolved, format!("before super-secret after {missing}"));
}

#[test]
fn example_placeholder_stays_marker_shaped_but_not_resolvable() {
    assert!(
        !is_placeholder(EXAMPLE_PLACEHOLDER),
        "example placeholder should stay out of the resolvable contract"
    );
    assert!(
        !contains_complete_placeholder(EXAMPLE_PLACEHOLDER),
        "example placeholder should not trigger strict response resolution"
    );
}

#[test]
fn contract_header_name_matches_the_shipped_header() {
    assert_eq!(CONTRACT_MARKER_KEY, "x-keyclaw-contract");
}
