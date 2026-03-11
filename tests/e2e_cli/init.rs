use std::io::Write;
use std::process::Stdio;

use crate::support::keyclaw_command;

#[test]
fn init_creates_first_run_artifacts_and_runs_doctor() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut child = keyclaw_command(temp.path())
        .arg("init")
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn init");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"n\n")
        .expect("write prompt response");

    let output = child.wait_with_output().expect("wait init");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("doctor:"), "stdout={out}");
    assert!(out.contains("env.sh"), "stdout={out}");
    assert!(
        out.contains("Session-scoped sensitive-data store"),
        "stdout={out}"
    );

    let keyclaw_dir = temp.path().join(".keyclaw");
    assert!(keyclaw_dir.join("ca.crt").exists(), "missing ca.crt");
    assert!(keyclaw_dir.join("ca.key").exists(), "missing ca.key");
    assert!(keyclaw_dir.join("env.sh").exists(), "missing env.sh");
    assert!(
        !keyclaw_dir.join("vault.key").exists(),
        "init should not create a machine-local vault key"
    );
}

#[test]
fn init_patches_shell_rc_once_when_confirmed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bashrc = temp.path().join(".bashrc");
    std::fs::write(&bashrc, "# existing\n").expect("write bashrc");

    for _ in 0..2 {
        let mut child = keyclaw_command(temp.path())
            .arg("init")
            .env("SHELL", "/bin/bash")
            .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
            .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn init");

        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(b"y\n")
            .expect("write prompt response");

        let output = child.wait_with_output().expect("wait init");
        assert_eq!(output.status.code(), Some(0));
    }

    let bashrc_contents = std::fs::read_to_string(&bashrc).expect("read bashrc");
    let marker = "[ -f ~/.keyclaw/env.sh ] && source ~/.keyclaw/env.sh";
    assert_eq!(
        bashrc_contents.matches(marker).count(),
        1,
        "bashrc={bashrc_contents}"
    );
}

#[test]
fn init_force_regenerates_broken_ca_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let keyclaw_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&keyclaw_dir).expect("create keyclaw dir");
    std::fs::write(keyclaw_dir.join("ca.crt"), "broken-cert").expect("write broken cert");
    std::fs::write(keyclaw_dir.join("ca.key"), "broken-key").expect("write broken key");

    let mut child = keyclaw_command(temp.path())
        .arg("init")
        .arg("--force")
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn init");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"n\n")
        .expect("write prompt response");

    let output = child.wait_with_output().expect("wait init");

    assert_eq!(output.status.code(), Some(0));
    let cert = std::fs::read_to_string(keyclaw_dir.join("ca.crt")).expect("read cert");
    let key = std::fs::read_to_string(keyclaw_dir.join("ca.key")).expect("read key");
    assert_ne!(cert, "broken-cert");
    assert_ne!(key, "broken-key");
}
