#![allow(dead_code)]

use std::fs;
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

pub struct WrappedToolRun {
    pub stderr: String,
    pub exit_code: i32,
    pub child_args: Vec<String>,
}

struct ToolCommandOptions<'a> {
    log_level: Option<&'a str>,
    env_overrides: &'a [(&'a str, &'a str)],
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
    let run = run_tool_command(
        &["mitm", tool],
        tool,
        addr,
        upstream_url,
        payload,
        &[],
        ToolCommandOptions {
            log_level: None,
            env_overrides: &[],
        },
    );
    (run.stderr, run.exit_code)
}

pub fn run_mitm_with_log_level(
    tool: &str,
    addr: String,
    upstream_url: &str,
    payload: &str,
    log_level: Option<&str>,
) -> (String, i32) {
    let run = run_tool_command(
        &["mitm", tool],
        tool,
        addr,
        upstream_url,
        payload,
        &[],
        ToolCommandOptions {
            log_level,
            env_overrides: &[],
        },
    );
    (run.stderr, run.exit_code)
}

pub fn run_mitm_with_args(
    tool: &str,
    addr: String,
    upstream_url: &str,
    payload: &str,
    child_args: &[&str],
) -> WrappedToolRun {
    run_tool_command(
        &["mitm", tool],
        tool,
        addr,
        upstream_url,
        payload,
        child_args,
        ToolCommandOptions {
            log_level: None,
            env_overrides: &[],
        },
    )
}

pub fn run_tool_alias(
    tool: &str,
    addr: String,
    upstream_url: &str,
    payload: &str,
    child_args: &[&str],
) -> WrappedToolRun {
    run_tool_command(
        &[tool],
        tool,
        addr,
        upstream_url,
        payload,
        child_args,
        ToolCommandOptions {
            log_level: None,
            env_overrides: &[],
        },
    )
}

pub fn run_mitm_with_include(
    tool: &str,
    include: &str,
    addr: String,
    upstream_url: &str,
    payload: &str,
) -> (String, i32) {
    let run = run_tool_command(
        &["mitm", "--include", include, tool],
        tool,
        addr,
        upstream_url,
        payload,
        &[],
        ToolCommandOptions {
            log_level: None,
            env_overrides: &[
                ("KEYCLAW_CODEX_HOSTS", "api.openai.com"),
                ("KEYCLAW_CLAUDE_HOSTS", "api.anthropic.com"),
            ],
        },
    );
    (run.stderr, run.exit_code)
}

pub fn install_fake_tool(dir: &Path, tool: &str, script: &str) {
    let path = dir.join(tool);
    fs::write(&path, script).expect("write fake tool");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&path).expect("tool metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("chmod fake tool");
    }
}

pub fn prepend_path(cmd: &mut Command, dir: &Path) {
    let existing = std::env::var_os("PATH");
    let joined = if let Some(existing) = existing {
        std::env::join_paths(
            std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&existing)),
        )
        .expect("join PATH")
    } else {
        std::env::join_paths([dir.to_path_buf()]).expect("join PATH")
    };
    cmd.env("PATH", joined);
}

fn run_tool_command(
    command_args: &[&str],
    tool: &str,
    addr: String,
    upstream_url: &str,
    payload: &str,
    child_args: &[&str],
    options: ToolCommandOptions<'_>,
) -> WrappedToolRun {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let temp = tempfile::tempdir().expect("tempdir");
    let tool_dir = temp.path().join("bin");
    fs::create_dir_all(&tool_dir).expect("create fake tool dir");
    let args_path = temp.path().join("child-args.txt");
    install_fake_tool(
        &tool_dir,
        tool,
        r#"#!/usr/bin/env python3
import os
import sys
import urllib.request

with open(os.environ["KEYCLAW_TEST_ARGS_OUT"], "w", encoding="utf-8") as fh:
    for arg in sys.argv[1:]:
        fh.write(arg)
        fh.write("\n")

proxy = os.environ.get("HTTP_PROXY")
url = os.environ["UPSTREAM_URL"]
data = os.environ["PAYLOAD"].encode()
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": proxy, "https": proxy})
)
req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
with opener.open(req, timeout=5):
    pass
"#,
    );

    let mut cmd = Command::new(bin);
    cmd.env_clear();
    preserve_base_env(&mut cmd);
    prepend_path(&mut cmd, &tool_dir);
    for arg in command_args {
        cmd.arg(arg);
    }
    cmd.args(child_args)
        .env("KEYCLAW_PROXY_ADDR", &addr)
        .env("KEYCLAW_PROXY_URL", format!("http://{}", &addr))
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "true")
        .env("KEYCLAW_MAX_BODY_BYTES", "1048576")
        .env("KEYCLAW_CODEX_HOSTS", "127.0.0.1")
        .env("KEYCLAW_CLAUDE_HOSTS", "127.0.0.1")
        .env("KEYCLAW_TEST_ARGS_OUT", &args_path)
        .env("UPSTREAM_URL", upstream_url)
        .env("PAYLOAD", payload);
    for (key, value) in options.env_overrides {
        cmd.env(key, value);
    }
    if let Some(level) = options.log_level {
        cmd.env("KEYCLAW_LOG_LEVEL", level);
    }
    let output = cmd.output().expect("run mitm");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let child_args = fs::read_to_string(&args_path)
        .map(|raw| raw.lines().map(ToOwned::to_owned).collect())
        .unwrap_or_else(|_| Vec::new());
    WrappedToolRun {
        stderr,
        exit_code: output.status.code().unwrap_or(1),
        child_args,
    }
}

pub fn keyclaw_command(home: &Path) -> Command {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let mut cmd = Command::new(bin);
    cmd.env_clear().env("HOME", home);
    cmd
}

pub fn doctor_command(home: &Path) -> Command {
    let mut cmd = keyclaw_command(home);
    cmd.arg("doctor")
        .env_clear()
        .env("HOME", home)
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "true");
    cmd
}

pub fn rewrite_json_command(home: &Path) -> Command {
    let mut cmd = keyclaw_command(home);
    cmd.arg("rewrite-json");
    cmd
}

pub fn can_bind(addr: SocketAddr) -> bool {
    TcpListener::bind(addr).map(drop).is_ok()
}

pub fn loopback_bind_available() -> bool {
    TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .map(drop)
        .is_ok()
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
    let join = thread::spawn(move || {
        loop {
            if shutdown_rx.try_recv().is_ok() {
                break;
            }

            match server.recv_timeout(Duration::from_millis(100)) {
                Ok(Some(req)) => handle_request(req),
                Ok(None) => continue,
                Err(_) => break,
            }
        }
    });

    UpstreamGuard {
        shutdown: Some(shutdown_tx),
        join: Some(join),
    }
}
