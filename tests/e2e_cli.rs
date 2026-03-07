use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tiny_http::{Response, Server as TinyServer, StatusCode};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(unix)]
use wait_timeout::ChildExt;

// Test secrets that match gitleaks generic-api-key rule (keyword + high-entropy value)
// Format: "api_key = <high-entropy-token>" triggers the generic-api-key rule
const TEST_SECRET_CODEX: &str = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
const TEST_SECRET_CLAUDE: &str = "xY2zW4vU6tS8rQ0pO2nM4lK6jI8hG0f";

#[test]
fn help_flag_returns_success_and_lists_supported_subcommands() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = keyclaw_command(temp.path())
        .arg("--help")
        .output()
        .expect("run --help");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(out.contains("Usage:"), "stdout={out}");
    assert!(out.contains("proxy"), "stdout={out}");
    assert!(out.contains("mitm"), "stdout={out}");
    assert!(out.contains("rewrite-json"), "stdout={out}");
    assert!(out.contains("doctor"), "stdout={out}");
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
}

#[test]
fn short_help_flag_returns_success_and_lists_supported_subcommands() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = keyclaw_command(temp.path())
        .arg("-h")
        .output()
        .expect("run -h");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(out.contains("Usage:"), "stdout={out}");
    assert!(out.contains("proxy"), "stdout={out}");
    assert!(out.contains("mitm"), "stdout={out}");
    assert!(out.contains("rewrite-json"), "stdout={out}");
    assert!(out.contains("doctor"), "stdout={out}");
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
}

#[test]
fn version_flag_returns_success_and_prints_crate_version() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = keyclaw_command(temp.path())
        .arg("--version")
        .output()
        .expect("run --version");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(out.trim(), format!("keyclaw {}", env!("CARGO_PKG_VERSION")));
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
}

#[test]
fn invalid_top_level_argument_returns_actionable_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = keyclaw_command(temp.path())
        .arg("--wat")
        .output()
        .expect("run invalid arg");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(out.trim().is_empty(), "stdout={out}");
    assert!(err.contains("--wat"), "stderr={err}");
    assert!(err.contains("Usage:"), "stderr={err}");
    assert!(err.contains("--help"), "stderr={err}");
}

#[test]
fn mitm_codex_intercepts_and_sanitizes() {
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
        body.contains("{{KEYCLAW_SECRET_"),
        "no placeholder in upstream body: {body}"
    );
    assert!(!stderr.contains(TEST_SECRET_CODEX));
}

#[test]
fn mitm_claude_intercepts_and_sanitizes() {
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
        body.contains("{{KEYCLAW_SECRET_"),
        "no placeholder in upstream body: {body}"
    );
    assert!(!stderr.contains(TEST_SECRET_CLAUDE));
}

#[test]
fn doctor_detects_proxy_bypass_attempt() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path())
        .env("NO_PROXY", "*")
        .output()
        .expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL proxy-bypass"), "output={out}");
    assert!(out.contains("mitm_not_effective"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
}

#[test]
fn doctor_detects_suffix_no_proxy_bypass_attempt() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path())
        .env("NO_PROXY", ".openai.com")
        .output()
        .expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL proxy-bypass"), "output={out}");
    assert!(out.contains(".openai.com"), "output={out}");
    assert!(out.contains("matches api.openai.com"), "output={out}");
}

#[test]
fn doctor_warns_on_unsafe_log_but_exits_zero() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path())
        .env("KEYCLAW_UNSAFE_LOG", "true")
        .output()
        .expect("run doctor");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("WARN unsafe-log"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
    assert!(!out.contains("FAIL "), "output={out}");
}

#[test]
fn doctor_fails_on_invalid_custom_gitleaks_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing-gitleaks.toml");
    let output = doctor_command(temp.path())
        .env("KEYCLAW_GITLEAKS_CONFIG", &missing)
        .output()
        .expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL ruleset"), "output={out}");
    assert!(out.contains("missing-gitleaks.toml"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
}

#[test]
fn doctor_warns_when_custom_ruleset_skips_invalid_rules() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = temp.path().join("gitleaks.toml");
    std::fs::write(
        &config,
        r#"
[[rules]]
id = "valid"
regex = '''([A-Za-z0-9]{8,})'''
keywords = ["api_key"]
secretGroup = 1

[[rules]]
id = "broken"
regex = "("
keywords = ["broken"]
"#,
    )
    .expect("write gitleaks config");

    let output = doctor_command(temp.path())
        .env("KEYCLAW_GITLEAKS_CONFIG", &config)
        .env("KEYCLAW_LOG_LEVEL", "error")
        .output()
        .expect("run doctor");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(out.contains("WARN ruleset"), "output={out}");
    assert!(out.contains("skipped 1 invalid rule"), "output={out}");
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
}

#[test]
fn doctor_reports_clean_healthcheck() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = doctor_command(temp.path()).output().expect("run doctor");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("PASS proxy-bind"), "output={out}");
    assert!(out.contains("PASS ca-cert"), "output={out}");
    assert!(out.contains("PASS ruleset"), "output={out}");
    assert!(out.contains("doctor: summary:"), "output={out}");
    assert!(!out.contains("WARN "), "output={out}");
    assert!(!out.contains("FAIL "), "output={out}");
}

#[test]
fn doctor_fails_when_existing_vault_key_is_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault.enc");
    let store = keyclaw::vault::Store::new(vault_path.clone(), "custom-passphrase".to_string());

    let mut entries = std::collections::HashMap::new();
    entries.insert(
        "api_key".to_string(),
        "sk-ABCDEF0123456789ABCDEF0123456789".to_string(),
    );
    store.save(&entries).expect("seed vault");

    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let output = Command::new(bin)
        .arg("doctor")
        .env_clear()
        .env("HOME", temp.path())
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "true")
        .env("KEYCLAW_VAULT_PATH", &vault_path)
        .output()
        .expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL vault-key"), "output={out}");
    assert!(out.contains("vault key"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
}

#[test]
fn doctor_fails_on_broken_generated_ca_pair() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ca_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&ca_dir).expect("create keyclaw dir");
    std::fs::write(ca_dir.join("ca.crt"), "not-a-cert").expect("write malformed cert");
    std::fs::write(ca_dir.join("ca.key"), "not-a-key").expect("write malformed key");

    let output = doctor_command(temp.path()).output().expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("FAIL ca-cert"), "output={out}");
    assert!(out.contains("hint:"), "output={out}");
    assert!(out.contains("remove the broken CA files"), "output={out}");
}

#[test]
fn proxy_fails_fast_on_broken_generated_ca_pair() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ca_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&ca_dir).expect("create keyclaw dir");
    std::fs::write(ca_dir.join("ca.crt"), "not-a-cert").expect("write malformed cert");
    std::fs::write(ca_dir.join("ca.key"), "not-a-key").expect("write malformed key");

    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let output = Command::new(bin)
        .arg("proxy")
        .env_clear()
        .env("HOME", temp.path())
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .output()
        .expect("run proxy");

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("keyclaw error:"), "stderr={stderr}");
    assert!(
        stderr.contains("remove the broken CA files"),
        "stderr={stderr}"
    );
}

#[test]
fn rewrite_json_respects_custom_gitleaks_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    let gitleaks_config = temp.path().join("gitleaks.toml");
    std::fs::write(&gitleaks_config, "rules = []\n").expect("write gitleaks config");
    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);

    let mut child = rewrite_json_command(temp.path())
        .env("KEYCLAW_GITLEAKS_CONFIG", &gitleaks_config)
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
    let output = child.wait_with_output().expect("wait rewrite-json");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert_eq!(out, payload);
}

#[test]
fn rewrite_json_creates_machine_local_vault_key_without_env_override() {
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault.enc");
    let payload = format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX);
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");

    let mut child = Command::new(bin)
        .arg("rewrite-json")
        .env_clear()
        .env("HOME", temp.path())
        .env("KEYCLAW_VAULT_PATH", &vault_path)
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
    let output = child.wait_with_output().expect("wait rewrite-json");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("{{KEYCLAW_SECRET_"), "output={out}");
    assert!(
        vault_path.with_extension("key").exists(),
        "vault key missing"
    );
}

#[test]
fn rewrite_json_preserves_env_style_assignment_boundaries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = r#"{"messages":[{"role":"user","content":"install K_API_KEY: 11111111-2222-3333-4444-555555555555 in .env\nthen set K_API_KEY = aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}"#;

    let mut child = rewrite_json_command(temp.path())
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
    let output = child.wait_with_output().expect("wait rewrite-json");

    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("K_API_KEY: {{KEYCLAW_SECRET_"), "output={out}");
    assert!(
        out.contains("K_API_KEY = {{KEYCLAW_SECRET_"),
        "output={out}"
    );
    assert!(out.contains("}} in .env"), "output={out}");
    assert!(!out.contains("install {{KEYCLAW_SECRET_"), "output={out}");
}

#[test]
fn logs_contain_no_raw_secrets() {
    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm_with_log_level(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
        Some("debug"),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(!stderr.contains(TEST_SECRET_CODEX));
    assert!(
        stderr.contains("request rewritten for host"),
        "stderr={stderr}"
    );
}

#[test]
fn mitm_info_log_level_hides_per_request_proxy_activity() {
    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm_with_log_level(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
        Some("info"),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(stderr.contains("keyclaw info:"), "stderr={stderr}");
    assert!(!stderr.contains("intercept POST /"), "stderr={stderr}");
    assert!(
        !stderr.contains("request rewritten for host"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("response: resolved placeholders back to secrets"),
        "stderr={stderr}"
    );
}

#[test]
fn mitm_debug_log_level_preserves_per_request_proxy_activity() {
    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm_with_log_level(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
        Some("debug"),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(
        stderr.contains("keyclaw debug: intercept POST /"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("keyclaw debug: request rewritten for host 127.0.0.1: replaced 1 secrets"),
        "stderr={stderr}"
    );
}

#[test]
fn coded_errors_emit_a_single_code_prefix() {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault.enc");

    let output = Command::new(bin)
        .arg("mitm")
        .arg("codex")
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg("print('not reached')")
        .env_clear()
        .env("HOME", temp.path())
        .env("NO_PROXY", "*")
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "true")
        .env("KEYCLAW_VAULT_PATH", &vault_path)
        .env("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase")
        .output()
        .expect("run mitm");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("keyclaw error: mitm_not_effective: NO_PROXY=*"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("mitm_not_effective: mitm_not_effective:"),
        "stderr={stderr}"
    );
}

#[test]
fn mitm_runtime_logs_use_leveled_prefixes() {
    let (upstream_url, rx, _guard) = start_upstream();

    let (stderr, exit_code) = run_mitm(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, TEST_SECRET_CODEX),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    let lines = stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert!(!lines.is_empty(), "stderr={stderr}");
    assert!(
        lines.iter().all(|line| line.starts_with("keyclaw info: ")),
        "stderr={stderr}"
    );
}

#[test]
fn rewrite_json_unsafe_logging_warning_uses_warn_prefix() {
    let temp = tempfile::tempdir().expect("tempdir");
    let payload = r#"{"prompt":"hello"}"#;

    let mut child = rewrite_json_command(temp.path())
        .env("KEYCLAW_UNSAFE_LOG", "true")
        .env("KEYCLAW_LOG_LEVEL", "warn")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rewrite-json");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload.as_bytes())
        .expect("write payload");
    let output = child.wait_with_output().expect("wait rewrite-json");

    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines = stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        lines,
        vec!["keyclaw warn: unsafe logging enabled; secrets may appear in logs"],
        "stderr={stderr}"
    );
}

#[cfg(unix)]
#[test]
fn mitm_releases_proxy_port_immediately_on_sigint() {
    let addr = free_addr();
    let socket_addr: SocketAddr = addr.parse().expect("parse socket addr");
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault.enc");

    let mut child = Command::new(bin)
        .arg("mitm")
        .arg("codex")
        .arg("--")
        .arg("bash")
        .arg("-lc")
        .arg("trap '' INT TERM; sleep 60")
        .env("KEYCLAW_PROXY_ADDR", &addr)
        .env("KEYCLAW_PROXY_URL", format!("http://{addr}"))
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "false")
        .env("KEYCLAW_VAULT_PATH", &vault_path)
        .env("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase")
        .env("KEYCLAW_CODEX_HOSTS", "127.0.0.1")
        .spawn()
        .expect("spawn keyclaw");

    wait_until(Duration::from_secs(3), || !can_bind(socket_addr));

    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }

    wait_until(Duration::from_millis(700), || can_bind(socket_addr));
    assert!(
        can_bind(socket_addr),
        "proxy listener still bound after SIGINT: {socket_addr}"
    );

    let status = child
        .wait_timeout(Duration::from_secs(5))
        .expect("wait timeout")
        .or_else(|| {
            let _ = child.kill();
            child.wait().ok()
        })
        .expect("wait child");
    assert!(
        status.code() == Some(130) || status.code() == Some(137) || status.signal().is_some(),
        "unexpected child status: {status}"
    );
}

#[cfg(unix)]
#[test]
fn mitm_returns_control_to_interactive_shell_after_child_exit() {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault.enc");
    let gitleaks_config = temp.path().join("gitleaks.toml");
    std::fs::write(&gitleaks_config, "rules = []\n").expect("write gitleaks config");

    let py = format!(
        r#"
import os
import pty
import re
import select
import signal
import subprocess
import sys
import time

bin_path = {bin_path:?}
vault_path = {vault_path:?}
gitleaks_config = {gitleaks_config:?}
cmd = (
    "KEYCLAW_REQUIRE_MITM_EFFECTIVE=false "
    "KEYCLAW_PROXY_ADDR=127.0.0.1:0 "
    f"KEYCLAW_VAULT_PATH={vault_path} "
    f"KEYCLAW_GITLEAKS_CONFIG={gitleaks_config} "
    "KEYCLAW_VAULT_PASSPHRASE=test-passphrase "
    f"{{bin_path}} mitm codex -- bash -lc 'exit 0'; "
    "printf '__RC__=%s\\n' \"$?\"; jobs -l; exit"
)

pid, fd = pty.fork()
if pid == 0:
    os.execvp("bash", ["bash", "--noprofile", "--norc", "-i"])

os.set_blocking(fd, False)
buf = bytearray()
sentinel = re.compile(rb"(?:\r\n|\n|\r)__RC__=")
ready = re.compile(rb"(?:\r\n|\n|\r)__READY__(?:\r\n|\n|\r)")

def pump(timeout, marker=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if fd not in ready:
            continue
        try:
            data = os.read(fd, 4096)
        except BlockingIOError:
            continue
        except OSError:
            return False
        if not data:
            return False
        buf.extend(data)
        if marker and marker.search(buf):
            return True
        if marker is None and sentinel.search(buf):
            return True
    return False

def write_all(data):
    view = memoryview(data)
    while view:
        _, writable, _ = select.select([], [fd], [], 0.1)
        if fd not in writable:
            continue
        try:
            written = os.write(fd, view)
        except BlockingIOError:
            continue
        view = view[written:]

time.sleep(1.0)
write_all(b"export PS1='PROMPT> '; printf '__READY__\\n'\r")
if not pump(10.0, ready):
    print(buf.decode("utf-8", "replace"))
    sys.exit(3)
write_all(cmd.encode())
write_all(b"\r")
ok = pump(5.0)
output = buf.decode("utf-8", "replace")
print(output)

if not ok:
    try:
        raw = subprocess.check_output(["pgrep", "-P", str(pid)], text=True)
        for child in raw.split():
            try:
                os.kill(int(child), signal.SIGKILL)
            except ProcessLookupError:
                pass
    except subprocess.CalledProcessError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    sys.exit(1)

if re.search(r"(^|[\r\n])__RC__=0(?:\r\n|\n|\r|$)", output) and "Stopped" not in output:
    sys.exit(0)

sys.exit(2)
"#,
        bin_path = bin.display().to_string(),
        vault_path = vault_path.display().to_string(),
        gitleaks_config = gitleaks_config.display().to_string(),
    );

    let output = Command::new("python3")
        .arg("-c")
        .arg(py)
        .output()
        .expect("run pty harness");

    assert_eq!(
        output.status.code(),
        Some(0),
        "pty harness failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_mitm(tool: &str, addr: String, upstream_url: &str, payload: &str) -> (String, i32) {
    run_mitm_with_log_level(tool, addr, upstream_url, payload, None)
}

fn run_mitm_with_log_level(
    tool: &str,
    addr: String,
    upstream_url: &str,
    payload: &str,
    log_level: Option<&str>,
) -> (String, i32) {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault.enc");
    let py = format!(
        "import os,urllib.request\nproxy=os.environ.get('HTTP_PROXY')\nurl=os.environ['UPSTREAM_URL']\ndata={:?}.encode()\nopener=urllib.request.build_opener(urllib.request.ProxyHandler({{'http':proxy,'https':proxy}}))\nreq=urllib.request.Request(url,data=data,headers={{'Content-Type':'application/json'}})\nwith opener.open(req,timeout=5):\n    pass\n",
        payload
    );

    let mut cmd = Command::new(bin);
    cmd.arg("mitm")
        .arg(tool)
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(py)
        .env("KEYCLAW_PROXY_ADDR", &addr)
        .env("KEYCLAW_PROXY_URL", format!("http://{}", &addr))
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "true")
        .env("KEYCLAW_MAX_BODY_BYTES", "1048576")
        .env("KEYCLAW_VAULT_PATH", &vault_path)
        .env("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase")
        .env("KEYCLAW_CODEX_HOSTS", "127.0.0.1")
        .env("KEYCLAW_CLAUDE_HOSTS", "127.0.0.1")
        .env("UPSTREAM_URL", upstream_url);
    if let Some(level) = log_level {
        cmd.env("KEYCLAW_LOG_LEVEL", level);
    }
    let output = cmd.output().expect("run mitm");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stderr, output.status.code().unwrap_or(1))
}

fn keyclaw_command(home: &std::path::Path) -> Command {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let mut cmd = Command::new(bin);
    cmd.env_clear().env("HOME", home);
    cmd
}

fn doctor_command(home: &std::path::Path) -> Command {
    let vault_path = home.join("vault.enc");

    let mut cmd = keyclaw_command(home);
    cmd.arg("doctor")
        .env_clear()
        .env("HOME", home)
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "true")
        .env("KEYCLAW_VAULT_PATH", vault_path)
        .env("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase");
    cmd
}

fn rewrite_json_command(home: &std::path::Path) -> Command {
    let vault_path = home.join("vault.enc");

    let mut cmd = keyclaw_command(home);
    cmd.arg("rewrite-json")
        .env("KEYCLAW_VAULT_PATH", vault_path)
        .env("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase");
    cmd
}

fn can_bind(addr: SocketAddr) -> bool {
    TcpListener::bind(addr).map(drop).is_ok()
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn start_upstream() -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = TinyServer::from_listener(listener, None).expect("server");

    let (tx, rx) = mpsc::channel();
    let join = thread::spawn(move || loop {
        match server.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(mut req)) => {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let _ = tx.send(body);
                let _ = req.respond(Response::empty(StatusCode(200)));
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    });

    (format!("http://{}", addr), rx, join)
}

fn free_addr() -> String {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    thread::sleep(Duration::from_millis(20));
    addr.to_string()
}
