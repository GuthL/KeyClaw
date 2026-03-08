use keyclaw::placeholder::EXAMPLE_PLACEHOLDER;
use keyclaw::redaction::inject_redaction_notice;

#[test]
fn inject_redaction_notice_uses_shared_placeholder_example() {
    let input = br#"{"messages":[{"role":"user","content":"hello"}]}"#;

    let rewritten = inject_redaction_notice(input, 2).expect("inject notice");
    let output = String::from_utf8(rewritten).expect("utf8");

    assert!(output.contains(EXAMPLE_PLACEHOLDER), "output={output}");
}
