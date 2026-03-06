use std::sync::Arc;

use keyclaw::errors::{code_of, CODE_STRICT_RESOLVE_FAILED};
use keyclaw::pipeline::Processor;
use keyclaw::vault::Store;

#[test]
fn resolve_text_strict_mode_errors_on_missing_placeholder() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Store::new(
        dir.path().join("vault.enc"),
        "test-passphrase".to_string(),
    ));
    let processor = Processor {
        vault: Some(vault),
        policy: None,
        max_body_size: 1 << 20,
        strict_mode: true,
    };

    let err = processor
        .resolve_text(b"hello {{KEYCLAW_SECRET_abcde_aaaaaaaaaaaaaaaa}}")
        .expect_err("strict mode should fail when placeholder cannot be resolved");

    assert_eq!(code_of(&err), Some(CODE_STRICT_RESOLVE_FAILED));
}

#[test]
fn resolve_text_non_strict_mode_passes_through_missing_placeholder() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Store::new(
        dir.path().join("vault.enc"),
        "test-passphrase".to_string(),
    ));
    let processor = Processor {
        vault: Some(vault),
        policy: None,
        max_body_size: 1 << 20,
        strict_mode: false,
    };

    let payload = b"hello {{KEYCLAW_SECRET_abcde_aaaaaaaaaaaaaaaa}}";
    let resolved = processor.resolve_text(payload).expect("non-strict pass-through");
    assert_eq!(resolved, payload);
}
