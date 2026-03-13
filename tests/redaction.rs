use keyclaw::placeholder::EXAMPLE_PLACEHOLDER;
use keyclaw::redaction::{NoticeMode, inject_redaction_notice, inject_redaction_notice_with_mode};

#[test]
fn inject_redaction_notice_uses_shared_placeholder_example() {
    let input = br#"{"messages":[{"role":"user","content":"hello"}]}"#;

    let rewritten = inject_redaction_notice(input, 2).expect("inject notice");
    let output = String::from_utf8(rewritten).expect("utf8");

    assert!(output.contains(EXAMPLE_PLACEHOLDER), "output={output}");
    assert!(
        output.contains("{{KEYCLAW_<shape>~<kind><id>}}"),
        "output={output}"
    );
}

#[test]
fn inject_redaction_notice_minimal_mode_uses_shorter_text() {
    let input = br#"{"messages":[{"role":"user","content":"hello"}]}"#;

    let rewritten =
        inject_redaction_notice_with_mode(input, 2, NoticeMode::Minimal).expect("inject notice");
    let output = String::from_utf8(rewritten).expect("utf8");

    assert!(output.contains(EXAMPLE_PLACEHOLDER), "output={output}");
    assert!(
        output.contains("{{KEYCLAW_<shape>~<kind><id>}}"),
        "output={output}"
    );
    assert!(output.contains("sensitive value(s)"), "output={output}");
    assert!(!output.contains("IMPORTANT:"), "output={output}");
}

#[test]
fn inject_redaction_notice_off_mode_leaves_json_unchanged() {
    let input = br#"{"messages":[{"role":"user","content":"hello"}]}"#;

    let rewritten =
        inject_redaction_notice_with_mode(input, 2, NoticeMode::Off).expect("inject notice");

    assert_eq!(rewritten, input);
}
