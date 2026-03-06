use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tiny_http::{Response, Server as TinyServer, StatusCode};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(unix)]
use wait_timeout::ChildExt;

#[test]
fn mitm_codex_intercepts_and_sanitizes() {
    let (upstream_url, rx, _guard) = start_upstream();
    let secret = "sk-ABCDEF0123456789ABCDEF0123456789";

    let (stderr, exit_code) = run_mitm(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"{}"}}"#, secret),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let body = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(!body.contains(secret));
    assert!(body.contains("{{KEYCLAW_SECRET_"));
    assert!(!stderr.contains(secret));
}

#[test]
fn mitm_claude_intercepts_and_sanitizes() {
    let (upstream_url, rx, _guard) = start_upstream();
    let secret = "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWX123456";

    let (stderr, exit_code) = run_mitm(
        "claude",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"{}"}}"#, secret),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let body = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(!body.contains(secret));
    assert!(body.contains("{{KEYCLAW_SECRET_"));
    assert!(!stderr.contains(secret));
}

#[test]
fn doctor_detects_proxy_bypass_attempt() {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let output = Command::new(bin)
        .arg("doctor")
        .env("NO_PROXY", "*")
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "true")
        .output()
        .expect("run doctor");

    assert_ne!(output.status.code(), Some(0));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("mitm_not_effective"), "output={out}");
}

#[test]
fn logs_contain_no_raw_secrets() {
    let (upstream_url, rx, _guard) = start_upstream();
    let secret = "sk-ABCDEF0123456789ABCDEF0123456789";

    let (stderr, exit_code) = run_mitm(
        "codex",
        free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"{}"}}"#, secret),
    );

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(!stderr.contains(secret));
    assert!(stderr.contains("replaced"));
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

fn run_mitm(tool: &str, addr: String, upstream_url: &str, payload: &str) -> (String, i32) {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let temp = tempfile::tempdir().expect("tempdir");
    let vault_path = temp.path().join("vault.enc");
    let py = format!(
        "import os,urllib.request\nproxy=os.environ.get('HTTP_PROXY')\nurl=os.environ['UPSTREAM_URL']\ndata={:?}.encode()\nopener=urllib.request.build_opener(urllib.request.ProxyHandler({{'http':proxy,'https':proxy}}))\nreq=urllib.request.Request(url,data=data,headers={{'Content-Type':'application/json'}})\nwith opener.open(req,timeout=5):\n    pass\n",
        payload
    );

    let output = Command::new(bin)
        .arg("mitm")
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
        .env("UPSTREAM_URL", upstream_url)
        .output()
        .expect("run mitm");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stderr, output.status.code().unwrap_or(1))
}

fn can_bind(addr: SocketAddr) -> bool {
    TcpListener::bind(addr).map(|listener| drop(listener)).is_ok()
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
