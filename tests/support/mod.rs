#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tiny_http::{Response, Server as TinyServer, StatusCode};

pub const TEST_SECRET_CODEX: &str = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
pub const TEST_SECRET_CLAUDE: &str = "xY2zW4vU6tS8rQ0pO2nM4lK6jI8hG0f";

pub struct UpstreamGuard {
    shutdown: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl Drop for UpstreamGuard {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub fn run_mitm(tool: &str, addr: String, upstream_url: &str, payload: &str) -> (String, i32) {
    run_mitm_with_log_level(tool, addr, upstream_url, payload, None)
}

pub fn run_mitm_with_log_level(
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
    cmd.env_clear();
    preserve_base_env(&mut cmd);
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

pub fn keyclaw_command(home: &Path) -> Command {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let mut cmd = Command::new(bin);
    cmd.env_clear().env("HOME", home);
    cmd
}

pub fn doctor_command(home: &Path) -> Command {
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

pub fn rewrite_json_command(home: &Path) -> Command {
    let vault_path = home.join("vault.enc");

    let mut cmd = keyclaw_command(home);
    cmd.arg("rewrite-json")
        .env("KEYCLAW_VAULT_PATH", vault_path)
        .env("KEYCLAW_VAULT_PASSPHRASE", "test-passphrase");
    cmd
}

pub fn can_bind(addr: SocketAddr) -> bool {
    TcpListener::bind(addr).map(drop).is_ok()
}

pub fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn start_upstream() -> (String, mpsc::Receiver<String>, UpstreamGuard) {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = TinyServer::from_listener(listener, None).expect("server");

    let (tx, rx) = mpsc::channel();
    let guard = spawn_upstream(server, move |mut req| {
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);
        let _ = tx.send(body);
        let _ = req.respond(Response::empty(StatusCode(200)));
    });

    (format!("http://{}", addr), rx, guard)
}

pub fn free_addr() -> String {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    thread::sleep(Duration::from_millis(20));
    addr.to_string()
}

fn preserve_base_env(cmd: &mut Command) {
    for key in [
        "HOME",
        "PATH",
        "TMPDIR",
        "SystemRoot",
        "COMSPEC",
        "ComSpec",
        "USERPROFILE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
}

fn spawn_upstream(
    server: TinyServer,
    mut handle_request: impl FnMut(tiny_http::Request) + Send + 'static,
) -> UpstreamGuard {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let join = thread::spawn(move || loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }

        match server.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(req)) => handle_request(req),
            Ok(None) => continue,
            Err(_) => break,
        }
    });

    UpstreamGuard {
        shutdown: Some(shutdown_tx),
        join: Some(join),
    }
}
