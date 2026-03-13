use keyclaw::placeholder::{
    CONTRACT_MARKER_KEY, CONTRACT_MARKER_VALUE, EXAMPLE_PLACEHOLDER, contains_complete_placeholder,
    find_partial_placeholder_start, is_placeholder, make, make_id, make_typed,
    resolve_placeholders, resolve_placeholders_typed,
};
use keyclaw::sensitive::SensitiveKind;

#[test]
fn opaque_placeholders_roundtrip_through_legacy_resolver() {
    let secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
    let id = make_id(secret);
    let placeholder = make(secret, &id);

    assert!(is_placeholder(&placeholder), "placeholder={placeholder}");
    assert!(contains_complete_placeholder(&format!(
        "value {placeholder}"
    )));
    assert_eq!(find_partial_placeholder_start(&placeholder), None);

    let resolved = resolve_placeholders(&placeholder, true, |seen_id| {
        assert_eq!(seen_id, id);
        Ok(Some(secret.to_string()))
    })
    .expect("resolve placeholder");

    assert_eq!(resolved, secret);
}

#[test]
fn typed_placeholders_roundtrip_through_typed_resolver() {
    let placeholder = make_typed(
        SensitiveKind::Email,
        "alice@company.dev",
        "0123456789abcdef",
    );

    assert!(is_placeholder(&placeholder), "placeholder={placeholder}");
    assert_eq!(find_partial_placeholder_start(&placeholder), None);

    let resolved = resolve_placeholders_typed(&placeholder, true, |kind, id| {
        assert_eq!(kind, SensitiveKind::Email);
        assert_eq!(id, "0123456789abcdef");
        Ok(Some("alice@company.dev".to_string()))
    })
    .expect("resolve typed placeholder");

    assert_eq!(resolved, "alice@company.dev");
}

#[test]
fn typed_placeholders_do_not_leak_value_prefixes() {
    let first = make_typed(SensitiveKind::Password, "hunter2!", "0123456789abcdef");
    let second = make_typed(
        SensitiveKind::Password,
        "CorrectHorseBatteryStaple!",
        "fedcba9876543210",
    );

    assert!(first.starts_with("{{KEYCLAW_"), "{first}");
    assert!(second.starts_with("{{KEYCLAW_"), "{second}");
    assert!(first.contains("aaaaaa0x~p"), "{first}");
    assert!(second.contains("AaaaaaaAaaaaAaaaaaaAaaaaax~p"), "{second}");
    assert!(!first.contains("hunter2"), "{first}");
    assert!(!second.contains("hunter2"), "{second}");
}

#[test]
fn partial_placeholder_detection_handles_short_marker_prefixes() {
    assert_eq!(find_partial_placeholder_start("{"), Some(0));
    assert_eq!(find_partial_placeholder_start("abc{{KE"), Some(3));
    assert_eq!(
        find_partial_placeholder_start("abc{{KEYCLAW_Aaaa0000~odeadbeefcafeba"),
        Some(3)
    );
    assert_eq!(
        find_partial_placeholder_start("{{KEYCLAW_Aaaa0000~odeadbeefcafebabe}}"),
        None
    );
}

#[test]
fn complete_placeholder_detection_matches_only_real_placeholders() {
    let placeholder = make("deadbeefcafebabe", "deadbeefcafebabe");

    assert!(contains_complete_placeholder(&format!(
        "value {placeholder}"
    )));
    assert!(!contains_complete_placeholder(
        "value {{KEYCLAW_Aa0a-0000~oxxxx}}"
    ));
    assert!(!contains_complete_placeholder(
        "value {{KEYCLAW_Aaaa0000~odeadbeefcafeba"
    ));
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
fn contract_marker_reports_v2() {
    assert_eq!(CONTRACT_MARKER_KEY, "x-keyclaw-contract");
    assert_eq!(CONTRACT_MARKER_VALUE, "placeholder:v2");
}
