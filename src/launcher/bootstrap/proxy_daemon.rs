use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::certgen::CaPair;
use crate::config::Config;
use crate::errors::KeyclawError;
use crate::pipeline::Processor;
use crate::proxy::Server;

pub(crate) fn run_proxy_foreground(cfg: &Config, processor: Arc<Processor>, ca: CaPair) -> i32 {
    let allowed_hosts = Config::allowed_hosts("all", cfg);

    let mut proxy_server = Server::new(
        cfg.proxy_listen_addr.clone(),
        allowed_hosts,
        processor,
        ca.cert_pem.clone(),
        ca.key_pem,
    );
    proxy_server.max_body_bytes = cfg.max_body_bytes;
    proxy_server.body_timeout = cfg.detector_timeout;
    proxy_server.audit_log_path = cfg.audit_log_path.clone();
    proxy_server.allow_addr_in_use_fallback = false;

    let running_proxy = match proxy_server.start() {
        Ok(p) => p,
        Err(err) => {
            super::super::print_error(&err);
            return 1;
        }
    };

    let proxy_url = format!("http://{}", running_proxy.addr);

    let keyclaw_dir = crate::certgen::keyclaw_dir();
    let ca_path = keyclaw_dir.join("ca.crt");

    let pid_path = keyclaw_dir.join("proxy.pid");
    let pid = std::process::id();
    let _ = fs::write(&pid_path, pid.to_string());

    let env_path = keyclaw_dir.join("env.sh");
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("keyclaw"));
    let env_content = render_proxy_env_script(pid, &proxy_url, &ca_path, &current_exe, &pid_path);
    if let Err(e) = fs::write(&env_path, &env_content) {
        crate::logging::error(&format!("failed to write env file: {e}"));
        return 1;
    }

    crate::logging::info(&format!("proxy listening on {}", running_proxy.addr));
    crate::logging::info("press Ctrl-C to stop");
    println!("source {}", env_path.display());

    let mut signals = match signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
    ]) {
        Ok(s) => s,
        Err(e) => {
            crate::logging::error(&format!("failed to register signals: {e}"));
            return 1;
        }
    };

    let _ = (&mut signals).into_iter().next();

    let _ = fs::remove_file(&pid_path);
    drop(running_proxy);

    crate::logging::info("proxy stopped");
    0
}

pub(crate) fn run_proxy_detached(cfg: &Config) -> Result<i32, KeyclawError> {
    let keyclaw_dir = crate::certgen::keyclaw_dir();
    fs::create_dir_all(&keyclaw_dir)
        .map_err(|e| KeyclawError::uncoded(format!("create keyclaw dir: {e}")))?;

    let pid_path = keyclaw_dir.join("proxy.pid");
    let env_path = keyclaw_dir.join("env.sh");
    let log_path = keyclaw_dir.join("proxy.log");

    let existing_addr = read_proxy_addr_from_env(&env_path);
    let existing_pid = read_and_validate_proxy_pid(&pid_path);
    let mut reset_tracking_files = existing_pid.is_none();
    if let Some(existing_pid) = existing_pid {
        if should_replace_existing_proxy(cfg, &env_path) {
            if let Some(existing_addr) = existing_addr.as_deref() {
                crate::logging::info(&format!(
                    "stopping existing proxy on {existing_addr} before restart"
                ));
            } else {
                crate::logging::info("stopping existing proxy before restart");
            }
            stop_proxy_process(&pid_path, existing_pid)?;
            if let Some(existing_addr) = existing_addr.as_deref() {
                wait_for_proxy_addr_to_stop_listening(existing_addr)?;
            }
            reset_tracking_files = true;
        }
    }

    if reset_tracking_files {
        let _ = fs::remove_file(&pid_path);
        let _ = fs::remove_file(&env_path);
    }

    let current_exe = std::env::current_exe()
        .map_err(|e| KeyclawError::uncoded(format!("resolve current executable: {e}")))?;
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| {
            KeyclawError::uncoded(format!("open proxy log {}: {e}", log_path.display()))
        })?;
    let log_file_err = log_file
        .try_clone()
        .map_err(|e| KeyclawError::uncoded(format!("clone proxy log handle: {e}")))?;

    let mut command = Command::new(current_exe);
    command
        .arg("proxy")
        .arg("--foreground")
        .envs(std::env::vars())
        .envs(detached_proxy_env(cfg))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err));

    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            // SAFETY: `pre_exec` runs in the child after `fork` and before
            // `exec`. Calling `setsid` here detaches the proxy into its own
            // session so parent-terminal teardown does not also tear it down.
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .map_err(|e| KeyclawError::uncoded(format!("start detached proxy: {e}")))?;

    wait_for_detached_proxy_ready(&mut child, &pid_path, &env_path, &log_path)?;

    crate::logging::info("proxy running in background");
    crate::logging::info(&format!("proxy log file: {}", log_path.display()));
    crate::logging::info(&format!(
        "starting the daemon does not reconfigure this shell; run `source {}` before launching clients here",
        env_path.display()
    ));
    println!("source {}", env_path.display());

    let _ = cfg;
    Ok(0)
}

pub(super) fn detached_proxy_env(cfg: &Config) -> Vec<(String, String)> {
    let mut env = vec![(
        "KEYCLAW_DRY_RUN".to_string(),
        if cfg.dry_run { "true" } else { "false" }.to_string(),
    )];
    if !cfg.include_hosts().is_empty() {
        env.push((
            "KEYCLAW_INCLUDE_HOSTS".to_string(),
            cfg.include_hosts().join(","),
        ));
    }
    env
}

pub(crate) fn run_proxy_stop() -> i32 {
    let keyclaw_dir = crate::certgen::keyclaw_dir();
    let pid_path = keyclaw_dir.join("proxy.pid");

    let pid = match read_and_validate_proxy_pid(&pid_path) {
        Some(pid) => pid,
        None => {
            crate::logging::info("no running proxy found");
            return 0;
        }
    };

    match stop_proxy_process(&pid_path, pid) {
        Ok(true) => {
            crate::logging::info(&format!("proxy stopped (pid={pid})"));
            0
        }
        Ok(false) => {
            crate::logging::info("no running proxy found");
            0
        }
        Err(err) => {
            crate::logging::error(&err.to_string());
            1
        }
    }
}

pub(crate) fn run_proxy_status() -> i32 {
    let keyclaw_dir = crate::certgen::keyclaw_dir();
    let pid_path = keyclaw_dir.join("proxy.pid");
    let env_path = keyclaw_dir.join("env.sh");

    let pid = match read_and_validate_proxy_pid(&pid_path) {
        Some(pid) => pid,
        None => {
            crate::logging::info("proxy not running");
            return 1;
        }
    };

    let addr = read_proxy_addr_from_env(&env_path).unwrap_or_else(|| "127.0.0.1:8877".to_string());
    if !proxy_addr_is_listening(&addr) {
        crate::logging::error(&format!(
            "proxy process is alive but not listening on {addr}"
        ));
        return 1;
    }
    crate::logging::info(&format!("proxy running (pid={pid}, addr={addr})"));
    0
}

pub(super) fn read_and_validate_proxy_pid(pid_path: &Path) -> Option<u32> {
    let pid_str = fs::read_to_string(pid_path).ok()?;

    let pid: u32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            let _ = fs::remove_file(pid_path);
            return None;
        }
    };

    let alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
    if !alive {
        let _ = fs::remove_file(pid_path);
        return None;
    }

    if !is_keyclaw_proxy_process(pid) {
        let _ = fs::remove_file(pid_path);
        return None;
    }

    Some(pid)
}

pub(super) fn is_keyclaw_proxy_process(pid: u32) -> bool {
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("keyclaw"));
    let current_exe_display = current_exe.display().to_string();
    let exe_name = current_exe
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("keyclaw");

    let comm = match Command::new("ps")
        .args(["-ww", "-o", "comm=", "-p", &pid.to_string()])
        .output()
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => return false,
    };

    let args = match Command::new("ps")
        .args(["-ww", "-o", "args=", "-p", &pid.to_string()])
        .output()
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => return false,
    };

    let argv0 = args.split_whitespace().next().unwrap_or_default();
    let argv0_matches = argv0 == current_exe_display
        || Path::new(argv0).file_name().and_then(|name| name.to_str()) == Some(exe_name);
    let comm_matches = comm == exe_name
        || Path::new(&comm).file_name().and_then(|name| name.to_str()) == Some(exe_name);

    if !argv0_matches && !comm_matches {
        return false;
    }

    args.contains(" proxy") && (args.ends_with(" proxy") || args.contains(" proxy "))
}

pub(super) fn read_proxy_addr_from_env(env_path: &Path) -> Option<String> {
    let content = fs::read_to_string(env_path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("export HTTP_PROXY=") {
            let url = rest.trim_matches('\'');
            return Some(url.strip_prefix("http://").unwrap_or(url).to_string());
        }
    }
    None
}

pub(super) fn proxy_addr_is_listening(addr: &str) -> bool {
    let timeout = Duration::from_millis(250);
    let addrs = match addr.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(_) => return false,
    };

    addrs
        .into_iter()
        .any(|socket_addr| TcpStream::connect_timeout(&socket_addr, timeout).is_ok())
}

fn proxy_addr_can_bind(addr: &str) -> bool {
    let addrs = match addr.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(_) => return false,
    };

    addrs
        .into_iter()
        .any(|socket_addr| TcpListener::bind(socket_addr).is_ok())
}

fn should_replace_existing_proxy(cfg: &Config, env_path: &Path) -> bool {
    match read_proxy_addr_from_env(env_path) {
        Some(existing_addr) => listen_addrs_match(&existing_addr, &cfg.proxy_listen_addr),
        None => true,
    }
}

fn listen_addrs_match(lhs: &str, rhs: &str) -> bool {
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    if lhs == rhs {
        return true;
    }

    match (lhs.parse::<SocketAddr>(), rhs.parse::<SocketAddr>()) {
        (Ok(lhs), Ok(rhs)) => lhs == rhs,
        _ => false,
    }
}

pub(crate) fn render_proxy_env_script(
    pid: u32,
    proxy_url: &str,
    ca_path: &Path,
    current_exe: &Path,
    pid_path: &Path,
) -> String {
    let exe_name = current_exe
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("keyclaw");
    let pid_value = shell_single_quote(&pid.to_string());
    let pid_file = shell_single_quote(&pid_path.display().to_string());
    let exe_name = shell_single_quote(exe_name);
    let proxy_url = shell_single_quote(proxy_url);
    let ca_path = shell_single_quote(&ca_path.display().to_string());

    format!(
        r#"# Generated by keyclaw proxy (PID {pid})
# Source this in any shell to route through keyclaw.
# Safe to keep in .bashrc — exports only while the same keyclaw proxy instance is still active.
keyclaw_proxy_pid={pid_value}
keyclaw_proxy_pid_file={pid_file}
keyclaw_proxy_exe_name={exe_name}

keyclaw_proxy_active() {{
  if ! kill -0 "$keyclaw_proxy_pid" 2>/dev/null; then
    return 1
  fi

  if ! command -v ps >/dev/null 2>&1; then
    return 1
  fi

  keyclaw_proxy_comm="$(ps -ww -o comm= -p "$keyclaw_proxy_pid" 2>/dev/null || true)"
  if [ "$keyclaw_proxy_comm" != "$keyclaw_proxy_exe_name" ]; then
    return 1
  fi

  keyclaw_proxy_args="$(ps -ww -o args= -p "$keyclaw_proxy_pid" 2>/dev/null || true)"
  case "$keyclaw_proxy_args" in
    *" proxy"|*" proxy "*) return 0 ;;
  esac

  return 1
}}

if keyclaw_proxy_active; then
  export HTTP_PROXY={proxy_url}
  export HTTPS_PROXY={proxy_url}
  export ALL_PROXY={proxy_url}
  export http_proxy={proxy_url}
  export https_proxy={proxy_url}
  export all_proxy={proxy_url}
  export SSL_CERT_FILE={ca_path}
  export REQUESTS_CA_BUNDLE={ca_path}
  export NODE_EXTRA_CA_CERTS={ca_path}
else
  rm -f "$keyclaw_proxy_pid_file"
  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
  unset SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS
fi
"#,
    )
}

fn shell_single_quote(value: &str) -> String {
    let escaped = value.replace('\'', r#"'\''"#);
    format!("'{escaped}'")
}

fn wait_for_detached_proxy_ready(
    child: &mut std::process::Child,
    pid_path: &Path,
    env_path: &Path,
    log_path: &Path,
) -> Result<(), KeyclawError> {
    let deadline = Instant::now() + Duration::from_secs(60);

    while Instant::now() < deadline {
        if pid_matches_child(pid_path, child.id())? && env_path.exists() {
            if let Some(addr) = read_proxy_addr_from_env(env_path) {
                if proxy_addr_is_listening(&addr) {
                    return Ok(());
                }
            }
        }

        if let Some(status) = child
            .try_wait()
            .map_err(|e| KeyclawError::uncoded(format!("check detached proxy status: {e}")))?
        {
            if let Some(detail) = detached_proxy_failure_detail(log_path) {
                return Err(KeyclawError::uncoded(format!(
                    "detached proxy exited early with status {status}: {detail}"
                )));
            }
            return Err(KeyclawError::uncoded(format!(
                "detached proxy exited early with status {status}; inspect {}",
                log_path.display()
            )));
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    Err(KeyclawError::uncoded(format!(
        "detached proxy did not become ready; inspect {}",
        log_path.display()
    )))
}

fn stop_proxy_process(pid_path: &Path, pid: u32) -> Result<bool, KeyclawError> {
    let kill_result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if kill_result != 0 {
        let _ = fs::remove_file(pid_path);
        return Ok(false);
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
        if !alive {
            let _ = fs::remove_file(pid_path);
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Err(KeyclawError::uncoded(format!(
        "proxy (pid={pid}) did not exit within 5 seconds after SIGTERM"
    )))
}

fn wait_for_proxy_addr_to_stop_listening(addr: &str) -> Result<(), KeyclawError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if proxy_addr_can_bind(addr) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    Err(KeyclawError::uncoded(format!(
        "proxy address {addr} did not stop listening within 5 seconds after SIGTERM"
    )))
}

fn pid_matches_child(pid_path: &Path, child_pid: u32) -> Result<bool, KeyclawError> {
    let pid = match fs::read_to_string(pid_path) {
        Ok(pid) => pid,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(KeyclawError::uncoded(format!(
                "read proxy pid file {}: {err}",
                pid_path.display()
            )));
        }
    };

    Ok(pid.trim() == child_pid.to_string())
}

fn detached_proxy_failure_detail(log_path: &Path) -> Option<String> {
    let log = fs::read_to_string(log_path).ok()?;
    log.lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            line.strip_prefix("keyclaw error: ")
                .or_else(|| line.strip_prefix("keyclaw warn: "))
                .or_else(|| line.strip_prefix("keyclaw info: "))
                .unwrap_or(line)
                .to_string()
        })
}
