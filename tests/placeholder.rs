use keyclaw::gitleaks_rules::RuleSet;
use keyclaw::placeholder::{replace_secrets, resolve_placeholders};

fn bundled_rules() -> RuleSet {
    RuleSet::bundled().expect("bundled rules")
}

#[test]
fn replace_and_resolve_placeholders_roundtrip() {
    let rules = bundled_rules();
    // Use generic-api-key pattern: "api_key = <high-entropy-value>"
    let input = "my api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v and secret_key: xY2zW4vU6tS8rQ0pO2nM4lK6jI8hG0f";
    let (rewritten, replacements) =
        replace_secrets(input, &rules, |secret| Ok(keyclaw::placeholder::make_id(secret)))
            .expect("replace should succeed");

    assert!(!replacements.is_empty(), "expected at least one replacement, input={input}, rewritten={rewritten}");
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
    assert!(rules.rules.len() > 200, "expected 200+ rules, got {}", rules.rules.len());
}
