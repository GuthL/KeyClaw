use keyclaw::gitleaks_rules::RuleSet;
use keyclaw::placeholder::{
    contains_complete_placeholder, find_partial_placeholder_start, is_placeholder, make, make_id,
    replace_secrets, resolve_placeholders,
};

fn bundled_rules() -> RuleSet {
    RuleSet::bundled().expect("bundled rules")
}

#[test]
fn replace_and_resolve_placeholders_roundtrip() {
    let rules = bundled_rules();
    // Use generic-api-key pattern: "api_key = <high-entropy-value>"
    let input = "my api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v and secret_key: xY2zW4vU6tS8rQ0pO2nM4lK6jI8hG0f";
    let (rewritten, replacements) = replace_secrets(input, &rules, |secret| {
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
fn generic_api_key_rule_preserves_assignment_boundaries() {
    let rules = bundled_rules();
    let input = concat!(
        "install K_API_KEY: 11111111-2222-3333-4444-555555555555 in .env\n",
        "then set K_API_KEY = aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n",
    );

    let (rewritten, replacements) = replace_secrets(input, &rules, |secret| {
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
