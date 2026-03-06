use std::sync::Arc;

use keyclaw::errors::{code_of, CODE_STRICT_RESOLVE_FAILED};
use keyclaw::gitleaks_rules::RuleSet;
use keyclaw::pipeline::Processor;
use keyclaw::vault::Store;

fn make_processor(strict: bool) -> Processor {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Store::new(
        dir.path().join("vault.enc"),
        "test-passphrase".to_string(),
    ));
    let ruleset = Arc::new(RuleSet::bundled().expect("bundled rules"));
    Processor {
        vault: Some(vault),
        ruleset,
        max_body_size: 1 << 20,
        strict_mode: strict,
    }
}

#[test]
fn resolve_text_strict_mode_errors_on_missing_placeholder() {
    let processor = make_processor(true);

    let err = processor
        .resolve_text(b"hello {{KEYCLAW_SECRET_abcde_aaaaaaaaaaaaaaaa}}")
        .expect_err("strict mode should fail when placeholder cannot be resolved");

    assert_eq!(code_of(&err), Some(CODE_STRICT_RESOLVE_FAILED));
}

#[test]
fn resolve_text_non_strict_mode_passes_through_missing_placeholder() {
    let processor = make_processor(false);

    let payload = b"hello {{KEYCLAW_SECRET_abcde_aaaaaaaaaaaaaaaa}}";
    let resolved = processor.resolve_text(payload).expect("non-strict pass-through");
    assert_eq!(resolved, payload);
}

#[test]
fn rewrite_detects_and_replaces_secrets() {
    let processor = make_processor(false);

    let body = br#"{"messages":[{"content":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"}]}"#;
    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    assert!(!result.replacements.is_empty());
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(rewritten.contains("KEYCLAW_SECRET_"));
    assert!(!rewritten.contains("aB3dE5fG"));
}
