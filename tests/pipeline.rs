use std::sync::Arc;

use base64::Engine;
use keyclaw::errors::{CODE_STRICT_RESOLVE_FAILED, code_of};
use keyclaw::gitleaks_rules::RuleSet;
use keyclaw::pipeline::Processor;
use keyclaw::placeholder::{EXAMPLE_PLACEHOLDER, contains_complete_placeholder, make};
use keyclaw::redaction::NoticeMode;
use keyclaw::vault::Store;

fn make_processor(strict: bool) -> Processor {
    make_processor_with_options(strict, NoticeMode::Verbose, false)
}

fn make_processor_with_notice_mode(strict: bool, notice_mode: NoticeMode) -> Processor {
    make_processor_with_options(strict, notice_mode, false)
}

fn make_processor_with_options(strict: bool, notice_mode: NoticeMode, dry_run: bool) -> Processor {
    make_processor_with_rules_and_second_pass(
        strict,
        notice_mode,
        dry_run,
        Arc::new(RuleSet::bundled().expect("bundled rules")),
        None,
    )
}

fn make_processor_with_rules_and_second_pass(
    strict: bool,
    notice_mode: NoticeMode,
    dry_run: bool,
    ruleset: Arc<RuleSet>,
    second_pass_scanner: Option<Arc<keyclaw::kingfisher::SecondPassScanner>>,
) -> Processor {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Store::new(
        dir.path().join("vault.enc"),
        "test-passphrase".to_string(),
    ));
    Processor {
        vault: Some(vault),
        ruleset,
        second_pass_scanner,
        max_body_size: 1 << 20,
        strict_mode: strict,
        notice_mode,
        dry_run,
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

#[test]
fn rewrite_dry_run_reports_replacements_without_mutating_body() {
    let processor = make_processor_with_options(false, NoticeMode::Verbose, true);
    let body =
        br#"{"messages":[{"role":"user","content":"api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"}]}"#;

    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    assert_eq!(result.body, body);
    assert_eq!(result.replacements.len(), 1, "{:?}", result.replacements);
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(rewritten.contains("aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v"));
    assert!(!contains_complete_placeholder(&rewritten), "{rewritten}");
    assert!(!rewritten.contains("[KEYCLAW]"), "{rewritten}");
}

#[test]
fn rewrite_detects_database_connection_string() {
    let processor = make_processor(false);
    let body = br#"{"messages":[{"role":"user","content":"DATABASE_URL=postgresql://app:Sup3rSecret!@db.example.com:5432/app?sslmode=require"}]}"#;

    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    assert_eq!(result.replacements.len(), 1, "{:?}", result.replacements);
    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(
        contains_complete_placeholder(&rewritten),
        "expected placeholder in rewritten body: {rewritten}"
    );
    assert!(
        !rewritten
            .contains("postgresql://app:Sup3rSecret!@db.example.com:5432/app?sslmode=require"),
        "database url should be redacted: {rewritten}"
    );
}

#[test]
fn rewrite_uses_kingfisher_binary_second_pass_when_configured() {
    let temp = tempfile::tempdir().expect("tempdir");
    let script = temp.path().join("fake-kingfisher");
    std::fs::write(
        &script,
        r#"#!/usr/bin/env bash
set -euo pipefail
input=""
output=""
while (($#)); do
  case "$1" in
    scan)
      shift
      input="$1"
      ;;
    --output|-o)
      shift
      output="$1"
      ;;
  esac
  shift || true
done
cat >"$output" <<JSON
{
  "findings": [
    {
      "rule": {"name": "Fake Kingfisher", "id": "kingfisher.fake.1"},
      "finding": {
        "snippet": "prefix KF_CUSTOM_SECRET suffix",
        "fingerprint": "fake-fingerprint",
        "confidence": "high",
        "entropy": "4.20",
        "validation": {"status": "unknown", "response": ""},
        "language": "Unknown",
        "line": 1,
        "column_start": 7,
        "column_end": 23,
        "path": "$input"
      }
    }
  ]
}
JSON
exit 200
"#,
    )
    .expect("write fake kingfisher");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod");
    }

    let mut rules = RuleSet::from_toml("rules = []").expect("empty ruleset");
    rules.entropy_config.enabled = false;
    let processor = make_processor_with_rules_and_second_pass(
        false,
        NoticeMode::Verbose,
        false,
        Arc::new(rules),
        Some(Arc::new(
            keyclaw::kingfisher::SecondPassScanner::from_binary(script.clone())
                .expect("binary second pass scanner"),
        )),
    );
    let body = br#"{"messages":[{"role":"user","content":"prefix KF_CUSTOM_SECRET suffix"}]}"#;

    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    let rewritten = String::from_utf8_lossy(&result.body);
    assert!(
        contains_complete_placeholder(&rewritten),
        "expected placeholder in rewritten body: {rewritten}"
    );
    assert!(
        result
            .replacements
            .iter()
            .any(|replacement| replacement.rule_id == "kingfisher.fake.1"
                && replacement.secret == "KF_CUSTOM_SECRET"),
        "expected fake kingfisher replacement metadata: {:?}",
        result.replacements
    );
}

#[test]
fn rewrite_detects_provider_key_inside_json_stringified_content() {
    let processor = make_processor(false);
    let inner = r#"{"aws_access_key":"AKI\u0041ABCDEFGHIJKLMNOP"}"#;
    let body = serde_json::json!({
        "messages": [
            {
                "role": "user",
                "content": inner
            }
        ]
    })
    .to_string();

    let result = processor
        .rewrite_and_evaluate(body.as_bytes())
        .expect("rewrite");

    assert_eq!(result.replacements.len(), 1, "{:?}", result.replacements);
    assert!(
        result.replacements[0].decoded_depth > 0,
        "{:?}",
        result.replacements
    );

    let rewritten: serde_json::Value =
        serde_json::from_slice(&result.body).expect("decode rewritten payload");
    let content = rewritten["messages"][0]["content"]
        .as_str()
        .expect("content string");
    assert!(
        contains_complete_placeholder(content),
        "expected placeholder in nested json string, got {content}"
    );
    assert!(
        !content.contains("AKIAABCDEFGHIJKLMNOP"),
        "aws access key should be redacted: {content}"
    );
}

#[test]
fn rewrite_detects_jwt_inside_base64_wrapped_content() {
    let processor = make_processor(false);
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.c2lnbmF0dXJlU2VjcmV0MTIz";
    let encoded = base64::engine::general_purpose::STANDARD.encode(
        serde_json::json!({
            "authorization": format!("Bearer {jwt}")
        })
        .to_string(),
    );
    let body = serde_json::json!({
        "messages": [
            {
                "role": "user",
                "content": encoded
            }
        ]
    })
    .to_string();

    let result = processor
        .rewrite_and_evaluate(body.as_bytes())
        .expect("rewrite");

    assert_eq!(result.replacements.len(), 1, "{:?}", result.replacements);
    assert!(
        result.replacements[0].decoded_depth > 0,
        "{:?}",
        result.replacements
    );

    let rewritten: serde_json::Value =
        serde_json::from_slice(&result.body).expect("decode rewritten payload");
    let content = rewritten["messages"][0]["content"]
        .as_str()
        .expect("content string");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(content)
        .expect("decode rewritten base64");
    let decoded = String::from_utf8(decoded).expect("utf8");

    assert!(
        contains_complete_placeholder(&decoded),
        "expected placeholder in decoded base64 payload, got {decoded}"
    );
    assert!(!decoded.contains(jwt), "jwt should be redacted: {decoded}");
}
