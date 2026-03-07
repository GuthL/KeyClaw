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
    let resolved = processor
        .resolve_text(payload)
        .expect("non-strict pass-through");
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

#[test]
fn rewrite_input_only_ignores_hidden_instructions() {
    let processor = make_processor(false);

    let body = br#"{
        "input":[{"role":"user","content":"test"}],
        "instructions":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"
    }"#;
    let result = processor
        .rewrite_and_evaluate_input_only(body)
        .expect("rewrite");

    assert!(result.replacements.is_empty(), "{:?}", result.replacements);
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(rewritten.contains(r#""content":"test""#), "{rewritten}");
    assert!(rewritten.contains("api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"));
    assert!(!rewritten.contains("[KEYCLAW]"), "{rewritten}");
}

#[test]
fn rewrite_input_only_skips_developer_messages() {
    let processor = make_processor(false);

    let body = br#"{
        "input":[
            {"role":"developer","content":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"},
            {"role":"user","content":"test"}
        ]
    }"#;
    let result = processor
        .rewrite_and_evaluate_input_only(body)
        .expect("rewrite");

    assert!(result.replacements.is_empty(), "{:?}", result.replacements);
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(rewritten.contains(r#""role":"developer""#), "{rewritten}");
    assert!(rewritten.contains("api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"));
    assert!(rewritten.contains(r#""role":"user""#), "{rewritten}");
    assert!(rewritten.contains(r#""content":"test""#), "{rewritten}");
    assert!(!rewritten.contains("[KEYCLAW]"), "{rewritten}");
}

#[test]
fn rewrite_codex_ws_suppresses_notice_for_hidden_context_replacements() {
    let processor = make_processor(false);

    let body = br#"{
        "input":[
            {"role":"user","type":"message","content":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"},
            {"role":"user","type":"message","content":"test"}
        ]
    }"#;
    let result = processor
        .rewrite_and_evaluate_codex_ws(body)
        .expect("rewrite");

    assert_eq!(result.replacements.len(), 1, "{:?}", result.replacements);
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(rewritten.contains("KEYCLAW_SECRET_"), "{rewritten}");
    assert!(rewritten.contains(r#""content":"test""#), "{rewritten}");
    assert!(!rewritten.contains("[KEYCLAW]"), "{rewritten}");
}

#[test]
fn rewrite_ignores_anthropic_system_secrets() {
    let processor = make_processor(false);

    let body = br#"{
        "model":"claude-3-7-sonnet",
        "system":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v",
        "messages":[{"role":"user","content":"test"}]
    }"#;
    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    assert!(result.replacements.is_empty(), "{:?}", result.replacements);
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(rewritten.contains(r#""content":"test""#), "{rewritten}");
    assert!(rewritten.contains("api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"));
    assert!(!rewritten.contains("[KEYCLAW]"), "{rewritten}");
}
