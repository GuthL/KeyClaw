use keyclaw::placeholder::{replace_secrets, resolve_placeholders};

#[test]
fn replace_and_resolve_placeholders_roundtrip() {
    let input = "my key is sk-ABCDEF0123456789ABCDEF0123456789 and anth sk-ant-ABCDEFGHIJKLMNOPQRSTUVWX123456";
    let (rewritten, replacements) =
        replace_secrets(input, |secret| Ok(keyclaw::placeholder::make_id(secret)))
            .expect("replace should succeed");

    assert_eq!(replacements.len(), 2);
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
