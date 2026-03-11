use std::time::Duration;

use keyclaw::placeholder;

use crate::support::{
    TEST_SECRET_CLAUDE, TEST_SECRET_CODEX, free_addr, loopback_bind_available, run_mitm,
    run_mitm_with_args, run_mitm_with_include, run_tool_alias, start_upstream,
};

#[test]
fn mitm_codex_intercepts_and_sanitizes() {
    if !loopback_bind_available() {
        eprintln!("skipping MITM e2e test: bind not permitted");
        return;
    }

    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let body = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(
        !body.contains(TEST_SECRET_CODEX),
        "secret leaked to upstream: {body}"
    );
    assert!(
        placeholder::contains_complete_placeholder(&body),
        "no placeholder in upstream body: {body}"
    );
    assert!(!stderr.contains(TEST_SECRET_CODEX));
}

#[test]
fn mitm_claude_intercepts_and_sanitizes() {
    if !loopback_bind_available() {
        eprintln!("skipping MITM e2e test: bind not permitted");
        return;
    }

    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm(
        "claude",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"secret_key: {}"}}"#, TEST_SECRET_CLAUDE),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let body = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(
        !body.contains(TEST_SECRET_CLAUDE),
        "secret leaked to upstream: {body}"
    );
    assert!(
        placeholder::contains_complete_placeholder(&body),
        "no placeholder in upstream body: {body}"
    );
    assert!(!stderr.contains(TEST_SECRET_CLAUDE));
}

#[test]
fn codex_alias_intercepts_and_forwards_child_args() {
    if !loopback_bind_available() {
        eprintln!("skipping MITM e2e test: bind not permitted");
        return;
    }

    let (upstream_url, rx, _guard) = start_upstream();

    let run = run_tool_alias(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
        &["exec", "--model", "gpt-5"],
    );

    assert_eq!(run.exit_code, 0, "stderr={}", run.stderr);
    let body = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(
        !body.contains(TEST_SECRET_CODEX),
        "secret leaked to upstream: {body}"
    );
    assert!(
        placeholder::contains_complete_placeholder(&body),
        "no placeholder in upstream body: {body}"
    );
    assert_eq!(
        run.child_args,
        vec!["exec", "--model", "gpt-5"],
        "stderr={}",
        run.stderr
    );
}

#[test]
fn claude_alias_intercepts_and_sanitizes() {
    if !loopback_bind_available() {
        eprintln!("skipping MITM e2e test: bind not permitted");
        return;
    }

    let (upstream_url, rx, _guard) = start_upstream();

    let run = run_tool_alias(
        "claude",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"secret_key: {}"}}"#, TEST_SECRET_CLAUDE),
        &["--resume", "session-123"],
    );

    assert_eq!(run.exit_code, 0, "stderr={}", run.stderr);
    let body = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(
        !body.contains(TEST_SECRET_CLAUDE),
        "secret leaked to upstream: {body}"
    );
    assert!(
        placeholder::contains_complete_placeholder(&body),
        "no placeholder in upstream body: {body}"
    );
    assert_eq!(
        run.child_args,
        vec!["--resume", "session-123"],
        "stderr={}",
        run.stderr
    );
}

#[test]
fn mitm_codex_forwards_child_args_without_repeating_executable() {
    if !loopback_bind_available() {
        eprintln!("skipping MITM e2e test: bind not permitted");
        return;
    }

    let (upstream_url, rx, _guard) = start_upstream();

    let run = run_mitm_with_args(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
        &["exec", "--model", "gpt-5"],
    );

    assert_eq!(run.exit_code, 0, "stderr={}", run.stderr);
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert_eq!(
        run.child_args,
        vec!["exec", "--model", "gpt-5"],
        "stderr={}",
        run.stderr
    );
}

#[test]
fn mitm_include_glob_intercepts_custom_host() {
    if !loopback_bind_available() {
        eprintln!("skipping MITM e2e test: bind not permitted");
        return;
    }

    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm_with_include(
        "codex",
        "*127.0.0.1*",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let body = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(
        !body.contains(TEST_SECRET_CODEX),
        "secret leaked to upstream: {body}"
    );
    assert!(
        placeholder::contains_complete_placeholder(&body),
        "no placeholder in upstream body: {body}"
    );
    assert!(!stderr.contains(TEST_SECRET_CODEX));
}
