use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use keyclaw::allowlist::Allowlist;
use keyclaw::entropy::EntropyConfig;
use keyclaw::errors::{CODE_STRICT_RESOLVE_FAILED, code_of};
use keyclaw::pipeline::Processor;
use keyclaw::placeholder::{contains_complete_placeholder, is_placeholder};
use keyclaw::redaction::NoticeMode;
use keyclaw::sensitive::{DetectionEngine, SensitiveDataConfig, SensitiveKind, SessionStore};

fn make_processor(
    strict_mode: bool,
    notice_mode: NoticeMode,
    dry_run: bool,
    sensitive_config: SensitiveDataConfig,
) -> Processor {
    Processor::new(
        Arc::new(DetectionEngine::new(
            sensitive_config,
            EntropyConfig {
                enabled: true,
                threshold: 3.5,
                min_len: 20,
            },
            Allowlist::default(),
            None,
        )),
        Arc::new(SessionStore::new(Duration::from_secs(60))),
        1 << 20,
        strict_mode,
        notice_mode,
        dry_run,
        None,
    )
}

#[test]
fn resolve_text_strict_mode_errors_on_missing_placeholder() {
    let processor = make_processor(
        true,
        NoticeMode::Verbose,
        false,
        SensitiveDataConfig::default(),
    );

    let err = processor
        .resolve_text(b"hello {{KEYCLAW_OPAQUE_deadbeefcafebabe}}")
        .expect_err("strict mode should fail when placeholder cannot be resolved");

    assert_eq!(code_of(&err), Some(CODE_STRICT_RESOLVE_FAILED));
}

#[test]
fn resolve_text_non_strict_mode_passes_through_missing_placeholder() {
    let processor = make_processor(
        false,
        NoticeMode::Verbose,
        false,
        SensitiveDataConfig::default(),
    );

    let payload = b"hello {{KEYCLAW_OPAQUE_deadbeefcafebabe}}";
    let resolved = processor
        .resolve_text(payload)
        .expect("non-strict pass-through");
    assert_eq!(resolved, payload);
}

#[test]
fn rewrite_detects_and_replaces_opaque_tokens() {
    let processor = make_processor(
        false,
        NoticeMode::Off,
        false,
        SensitiveDataConfig::default(),
    );

    let body =
        br#"{"messages":[{"role":"user","content":"token = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"}]}"#;
    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    assert_eq!(result.replacements.len(), 1, "{:?}", result.replacements);
    assert_eq!(result.replacements[0].kind, SensitiveKind::OpaqueToken);
    assert_eq!(result.replacements[0].source.as_str(), "entropy");

    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(contains_complete_placeholder(&rewritten), "{rewritten}");
    assert!(rewritten.contains("{{KEYCLAW_OPAQUE_"), "{rewritten}");
    assert!(!rewritten.contains("aB3dE5fG"), "{rewritten}");

    let resolved = processor.resolve_json(&result.body).expect("resolve json");
    let resolved = String::from_utf8_lossy(&resolved);
    assert!(
        resolved.contains("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"),
        "{resolved}"
    );
}

#[test]
fn rewrite_detects_typed_sensitive_values_and_resolves_them() {
    let processor = make_processor(
        false,
        NoticeMode::Off,
        false,
        SensitiveDataConfig {
            passwords_enabled: true,
            emails_enabled: true,
            payment_cards_enabled: true,
            cvv_enabled: true,
            ..SensitiveDataConfig::default()
        },
    );

    let body = br#"{"messages":[{"role":"user","content":"password=\"S3cret!\"\nemail=alice@company.dev\ncard=4111 1111 1111 1111\ncvv=123"}]}"#;
    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    assert_eq!(result.replacements.len(), 4, "{:?}", result.replacements);
    assert!(
        result
            .replacements
            .iter()
            .all(|replacement| replacement.kind != SensitiveKind::OpaqueToken)
    );

    let rewritten = String::from_utf8_lossy(&result.body);
    for replacement in &result.replacements {
        assert!(rewritten.contains(&replacement.placeholder), "{rewritten}");
        assert!(is_placeholder(&replacement.placeholder), "{replacement:?}");
    }
    assert!(!rewritten.contains("alice@company.dev"), "{rewritten}");
    assert!(!rewritten.contains("4111 1111 1111 1111"), "{rewritten}");

    let resolved = processor.resolve_json(&result.body).expect("resolve json");
    let resolved = String::from_utf8_lossy(&resolved);
    assert!(resolved.contains("alice@company.dev"), "{resolved}");
    assert!(resolved.contains("4111 1111 1111 1111"), "{resolved}");
    assert!(resolved.contains("cvv=123"), "{resolved}");
}

#[test]
fn rewrite_dry_run_reports_typed_placeholders_without_prefix_leakage() {
    let processor = make_processor(
        false,
        NoticeMode::Off,
        true,
        SensitiveDataConfig {
            emails_enabled: true,
            ..SensitiveDataConfig::default()
        },
    );

    let body = br#"{"messages":[{"role":"user","content":"email=alice@company.dev"}]}"#;
    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    assert_eq!(
        String::from_utf8_lossy(&result.body),
        String::from_utf8_lossy(body)
    );
    assert_eq!(result.replacements.len(), 1);
    assert_eq!(result.replacements[0].kind, SensitiveKind::Email);
    assert!(
        result.replacements[0]
            .placeholder
            .starts_with("{{KEYCLAW_EMAIL_"),
        "{:?}",
        result.replacements[0]
    );
    assert!(
        !result.replacements[0].placeholder.contains("alice"),
        "{:?}",
        result.replacements[0]
    );
}

#[test]
fn rewrite_ignores_hidden_instructions_in_input_only_mode() {
    let processor = make_processor(
        false,
        NoticeMode::Off,
        false,
        SensitiveDataConfig::default(),
    );

    let body = br#"{
        "input":[{"role":"user","content":"test"}],
        "instructions":"token = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"
    }"#;
    let result = processor
        .rewrite_and_evaluate_input_only(body)
        .expect("rewrite");

    assert!(result.replacements.is_empty(), "{:?}", result.replacements);
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(rewritten.contains(r#""content":"test""#), "{rewritten}");
    assert!(rewritten.contains("token = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"));
}

#[test]
fn rewrite_recurses_into_base64_wrapped_json() {
    let processor = make_processor(
        false,
        NoticeMode::Off,
        false,
        SensitiveDataConfig {
            emails_enabled: true,
            ..SensitiveDataConfig::default()
        },
    );

    let nested = r#"{"email":"alice@company.dev"}"#;
    let encoded = base64::engine::general_purpose::STANDARD.encode(nested);
    let body = format!(r#"{{"messages":[{{"role":"user","content":"payload={encoded}"}}]}}"#);

    let result = processor
        .rewrite_and_evaluate(body.as_bytes())
        .expect("rewrite");

    assert_eq!(result.replacements.len(), 1, "{:?}", result.replacements);
    assert_eq!(result.replacements[0].kind, SensitiveKind::Email);

    let resolved = processor.resolve_json(&result.body).expect("resolve json");
    let resolved = String::from_utf8_lossy(&resolved);
    let encoded = resolved
        .split("payload=")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .expect("payload token");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("decode payload");
    let decoded = String::from_utf8(decoded).expect("utf8 payload");
    assert!(decoded.contains("alice@company.dev"), "{decoded}");
}
