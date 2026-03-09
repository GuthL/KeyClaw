use std::sync::Arc;

use keyclaw::errors::{code_of, CODE_STRICT_RESOLVE_FAILED};
use keyclaw::gitleaks_rules::RuleSet;
use keyclaw::pipeline::Processor;
use keyclaw::placeholder::{contains_complete_placeholder, make, EXAMPLE_PLACEHOLDER};
use keyclaw::redaction::NoticeMode;
use keyclaw::vault::Store;

fn make_processor(strict: bool) -> Processor {
    make_processor_with_notice_mode(strict, NoticeMode::Verbose)
}

fn make_processor_with_notice_mode(strict: bool, notice_mode: NoticeMode) -> Processor {
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
        notice_mode,
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
    assert!(contains_complete_placeholder(&rewritten), "{rewritten}");
    assert!(!rewritten.contains("aB3dE5fG"));
}

#[test]
fn rewrite_detects_and_replaces_secrets_without_notice_when_notice_mode_is_off() {
    let processor = make_processor_with_notice_mode(false, NoticeMode::Off);

    let body = br#"{"messages":[{"content":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"}]}"#;
    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    assert!(!result.replacements.is_empty());
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(contains_complete_placeholder(&rewritten), "{rewritten}");
    assert!(!rewritten.contains("aB3dE5fG"), "{rewritten}");
    assert!(!rewritten.contains("[KEYCLAW]"), "{rewritten}");
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
fn rewrite_skips_non_user_messages_in_general_mode() {
    let processor = make_processor(false);

    let body = br#"{
        "messages":[
            {"role":"developer","content":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"},
            {"role":"assistant","content":"api_key = zY8xW6vU4tS2rQ0pN8mL6kJ4hG2fD0s"},
            {"role":"user","content":"test"}
        ]
    }"#;
    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    assert!(result.replacements.is_empty(), "{:?}", result.replacements);
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(rewritten.contains(r#""role":"developer""#), "{rewritten}");
    assert!(rewritten.contains("api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"));
    assert!(rewritten.contains(r#""role":"assistant""#), "{rewritten}");
    assert!(rewritten.contains("api_key = zY8xW6vU4tS2rQ0pN8mL6kJ4hG2fD0s"));
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
    assert!(contains_complete_placeholder(&rewritten), "{rewritten}");
    assert!(rewritten.contains(r#""content":"test""#), "{rewritten}");
    assert!(!rewritten.contains("[KEYCLAW]"), "{rewritten}");
}

#[test]
fn rewrite_codex_ws_skips_non_user_messages() {
    let processor = make_processor(false);

    let body = br#"{
        "input":[
            {"role":"developer","type":"message","content":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"},
            {"role":"assistant","type":"message","content":"api_key = zY8xW6vU4tS2rQ0pN8mL6kJ4hG2fD0s"},
            {"role":"user","type":"message","content":"test"}
        ]
    }"#;
    let result = processor
        .rewrite_and_evaluate_codex_ws(body)
        .expect("rewrite");

    assert!(result.replacements.is_empty(), "{:?}", result.replacements);
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(rewritten.contains(r#""role":"developer""#), "{rewritten}");
    assert!(rewritten.contains("api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"));
    assert!(rewritten.contains(r#""role":"assistant""#), "{rewritten}");
    assert!(rewritten.contains("api_key = zY8xW6vU4tS2rQ0pN8mL6kJ4hG2fD0s"));
    assert!(rewritten.contains(r#""role":"user""#), "{rewritten}");
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

#[test]
fn resolve_text_reinjects_known_placeholders_even_with_example_notice_present() {
    let processor = make_processor(false);
    let vault = processor.vault.as_ref().expect("vault");
    let secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
    let id = vault.store_secret(secret).expect("store secret");
    let payload = format!(
        r#"{{"messages":[{{"content":"api_key = {}"}},{{"content":"[KEYCLAW] notice like {}","role":"developer"}}]}}"#,
        make(&id),
        EXAMPLE_PLACEHOLDER
    );

    let resolved = processor
        .resolve_text(payload.as_bytes())
        .expect("resolve text");
    let resolved = String::from_utf8(resolved).expect("utf8");

    assert!(resolved.contains(secret), "resolved={resolved}");
    assert!(
        resolved.contains(EXAMPLE_PLACEHOLDER),
        "resolved={resolved}"
    );
}

#[test]
fn rewrite_detects_high_entropy_token_not_matched_by_regex() {
    let processor = make_processor(false);

    // A custom internal token that has high entropy — entropy analysis should catch it
    let body = br#"{"messages":[{"role":"user","content":"connect with token xK9mP2vL8nQ4wR6tY0uI3oA5sD7fG1hJ"}]}"#;
    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(
        !rewritten.contains("xK9mP2vL8nQ4wR6tY0uI3oA5sD7fG1hJ"),
        "high-entropy token should be redacted: {rewritten}"
    );
}
