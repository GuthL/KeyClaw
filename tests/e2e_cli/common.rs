use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

use crate::support::rewrite_json_command;

pub(crate) fn allowlist_test_payload() -> (&'static str, String) {
    let secret = "AbC123DeF456GhI789JkL012MnO345";
    (secret, format!(r#"{{"prompt":"secret={secret}"}}"#))
}

pub(crate) fn run_rewrite_json_with_input(home: &Path, payload: &str) -> Output {
    let mut child = rewrite_json_command(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn rewrite-json");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");

    child.wait_with_output().expect("wait rewrite-json")
}
