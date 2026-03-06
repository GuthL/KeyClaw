use keyclaw::detector::Detector;

#[test]
fn embedded_detector_finds_known_secrets() {
    let d = keyclaw::detector::EmbeddedDetector::new();
    let payload = br#"{"prompt":"use sk-ABCDEF0123456789ABCDEF0123456789 and sk-ant-ABCDEFGHIJKLMNOPQRSTUVWX123456"}"#;

    let findings = d.detect(payload).expect("detect");
    assert!(findings.len() >= 2);
}

#[test]
fn embedded_detector_false_positive_guards() {
    let d = keyclaw::detector::EmbeddedDetector::new();
    let payload = br#"{"prompt":"placeholder {{KEYCLAW_SECRET_aaaaaaaaaaaaaaaa}} api_key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;

    let findings = d.detect(payload).expect("detect");
    assert_eq!(findings.len(), 0);
}
