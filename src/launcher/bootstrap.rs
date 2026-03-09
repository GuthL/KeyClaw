use std::fs;
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;

use crate::certgen::CaPair;
use crate::config::Config;
use crate::entropy::EntropyConfig;
use crate::errors::{KeyclawError, CODE_MITM_NOT_EFFECTIVE};
use crate::gitleaks_rules::RuleSet;
use crate::pipeline::Processor;
use crate::proxy::Server;
use crate::vault::Store;

pub(super) fn run_proxy_foreground(cfg: &Config, processor: Arc<Processor>, ca: CaPair) -> i32 {
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

    let running_proxy = match proxy_server.start() {
        Ok(p) => p,
        Err(err) => {
            super::print_error(&err);
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

pub(super) fn run_proxy_detached(cfg: &Config) -> Result<i32, KeyclawError> {
    let keyclaw_dir = crate::certgen::keyclaw_dir();
    fs::create_dir_all(&keyclaw_dir)
        .map_err(|e| KeyclawError::uncoded(format!("create keyclaw dir: {e}")))?;

    let pid_path = keyclaw_dir.join("proxy.pid");
    let env_path = keyclaw_dir.join("env.sh");
    let log_path = keyclaw_dir.join("proxy.log");
    let _ = fs::remove_file(&pid_path);
    let _ = fs::remove_file(&env_path);

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

    let mut child = Command::new(current_exe)
        .arg("proxy")
        .arg("--foreground")
        .envs(std::env::vars())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
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

pub(super) fn run_proxy_stop() -> i32 {
    let keyclaw_dir = crate::certgen::keyclaw_dir();
    let pid_path = keyclaw_dir.join("proxy.pid");

    let pid = match read_and_validate_proxy_pid(&pid_path) {
        Some(pid) => pid,
        None => {
            crate::logging::info("no running proxy found");
            return 0;
        }
    };

    // Send SIGTERM
    let kill_result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if kill_result != 0 {
        crate::logging::info("no running proxy found");
        let _ = fs::remove_file(&pid_path);
        return 0;
    }

    // Wait up to 5 seconds for the process to exit
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut exited = false;
    while Instant::now() < deadline {
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
        if !alive {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = fs::remove_file(&pid_path);

    if exited {
        crate::logging::info(&format!("proxy stopped (pid={pid})"));
        0
    } else {
        crate::logging::error(&format!(
            "proxy (pid={pid}) did not exit within 5 seconds after SIGTERM"
        ));
        1
    }
}

pub(super) fn run_proxy_status() -> i32 {
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
    crate::logging::info(&format!("proxy running (pid={pid}, addr={addr})"));
    0
}

#[cfg(target_os = "linux")]
const PROXY_AUTOSTART_UNIT_NAME: &str = "keyclaw-proxy.service";

#[cfg(target_os = "linux")]
pub(super) fn run_proxy_autostart_enable() -> i32 {
    match enable_proxy_autostart() {
        Ok(unit_path) => {
            crate::logging::info(&format!(
                "proxy autostart enabled via {}",
                unit_path.display()
            ));
            crate::logging::info(
                "autostart keeps the daemon alive after login/reboot; shells still need `source ~/.keyclaw/env.sh`",
            );
            0
        }
        Err(err) => {
            super::print_error(&err);
            1
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn run_proxy_autostart_enable() -> i32 {
    crate::logging::error("proxy autostart is currently supported only on Linux systemd");
    1
}

#[cfg(target_os = "linux")]
pub(super) fn run_proxy_autostart_disable() -> i32 {
    match disable_proxy_autostart() {
        Ok(message) => {
            crate::logging::info(&message);
            0
        }
        Err(err) => {
            super::print_error(&err);
            1
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn run_proxy_autostart_disable() -> i32 {
    crate::logging::error("proxy autostart is currently supported only on Linux systemd");
    1
}

#[cfg(target_os = "linux")]
pub(super) fn run_proxy_autostart_status() -> i32 {
    match proxy_autostart_status() {
        Ok((message, code)) => {
            crate::logging::info(&message);
            code
        }
        Err(err) => {
            super::print_error(&err);
            1
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn run_proxy_autostart_status() -> i32 {
    crate::logging::error("proxy autostart is currently supported only on Linux systemd");
    1
}

/// Read PID from file and validate that it is actually a keyclaw proxy process.
/// Returns `None` if no PID file, stale PID, or not a keyclaw proxy process.
/// Cleans up stale PID file as a side effect.
fn read_and_validate_proxy_pid(pid_path: &Path) -> Option<u32> {
    let pid_str = fs::read_to_string(pid_path).ok()?;

    let pid: u32 = match pid_str.trim().parse() {
        Ok(p) => p,
        Err(_) => {
            let _ = fs::remove_file(pid_path);
            return None;
        }
    };

    // Check if process is alive
    let alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
    if !alive {
        let _ = fs::remove_file(pid_path);
        return None;
    }

    // Validate the process is actually a keyclaw proxy by checking comm and args
    if !is_keyclaw_proxy_process(pid) {
        let _ = fs::remove_file(pid_path);
        return None;
    }

    Some(pid)
}

/// Check if a given PID is a keyclaw proxy process by inspecting process name and args.
fn is_keyclaw_proxy_process(pid: u32) -> bool {
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("keyclaw"));
    let exe_name = current_exe
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("keyclaw");

    // Check process comm (executable name)
    let comm = match Command::new("ps")
        .args(["-ww", "-o", "comm=", "-p", &pid.to_string()])
        .output()
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => return false,
    };

    if comm != exe_name {
        return false;
    }

    // Check process args contain "proxy"
    let args = match Command::new("ps")
        .args(["-ww", "-o", "args=", "-p", &pid.to_string()])
        .output()
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => return false,
    };

    // Match same pattern as env.sh: *" proxy" or *" proxy "*
    args.contains(" proxy") && (args.ends_with(" proxy") || args.contains(" proxy "))
}

/// Extract the proxy address from the env.sh script.
fn read_proxy_addr_from_env(env_path: &Path) -> Option<String> {
    let content = fs::read_to_string(env_path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        // Look for HTTP_PROXY= line (the export line)
        if let Some(rest) = line.strip_prefix("export HTTP_PROXY=") {
            let url = rest.trim_matches('\'');
            // Strip "http://" prefix to get just the address
            return Some(url.strip_prefix("http://").unwrap_or(url).to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn enable_proxy_autostart() -> Result<PathBuf, KeyclawError> {
    let unit_path = proxy_autostart_unit_path()?;
    if let Some(parent) = unit_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            KeyclawError::uncoded(format!("create autostart dir {}: {e}", parent.display()))
        })?;
    }
    fs::create_dir_all(crate::certgen::keyclaw_dir())
        .map_err(|e| KeyclawError::uncoded(format!("create keyclaw dir: {e}")))?;

    let current_exe = std::env::current_exe()
        .map_err(|e| KeyclawError::uncoded(format!("resolve current executable: {e}")))?;
    let unit_contents = render_proxy_autostart_unit(&current_exe);
    fs::write(&unit_path, unit_contents)
        .map_err(|e| KeyclawError::uncoded(format!("write {}: {e}", unit_path.display())))?;

    run_systemctl_user(["daemon-reload"])?;
    run_systemctl_user_with_path(["enable", "--now"], &unit_path)?;

    Ok(unit_path)
}

#[cfg(target_os = "linux")]
fn disable_proxy_autostart() -> Result<String, KeyclawError> {
    let unit_path = proxy_autostart_unit_path()?;
    if !unit_path.exists() {
        return Ok("proxy autostart is not configured".to_string());
    }

    run_systemctl_user(["disable", "--now", PROXY_AUTOSTART_UNIT_NAME])?;
    fs::remove_file(&unit_path)
        .map_err(|e| KeyclawError::uncoded(format!("remove {}: {e}", unit_path.display())))?;
    run_systemctl_user(["daemon-reload"])?;

    Ok(format!(
        "proxy autostart disabled and removed from {}",
        unit_path.display()
    ))
}

#[cfg(target_os = "linux")]
fn proxy_autostart_status() -> Result<(String, i32), KeyclawError> {
    let unit_path = proxy_autostart_unit_path()?;
    if !unit_path.exists() {
        return Ok(("proxy autostart is not configured".to_string(), 1));
    }

    let enabled = run_systemctl_user(["is-enabled", PROXY_AUTOSTART_UNIT_NAME]).is_ok();
    let active = run_systemctl_user(["is-active", PROXY_AUTOSTART_UNIT_NAME]).is_ok();
    Ok((
        format!(
            "proxy autostart unit present at {} (enabled={}, active={})",
            unit_path.display(),
            enabled,
            active
        ),
        0,
    ))
}

#[cfg(target_os = "linux")]
fn proxy_autostart_unit_path() -> Result<PathBuf, KeyclawError> {
    Ok(user_config_home()?
        .join("systemd")
        .join("user")
        .join(PROXY_AUTOSTART_UNIT_NAME))
}

#[cfg(target_os = "linux")]
fn render_proxy_autostart_unit(current_exe: &Path) -> String {
    let log_path = crate::certgen::keyclaw_dir().join("proxy.log");
    format!(
        "[Unit]\nDescription=KeyClaw proxy daemon\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} proxy --foreground\nRestart=always\nRestartSec=5\nStandardOutput=append:{}\nStandardError=append:{}\n\n[Install]\nWantedBy=default.target\n",
        current_exe.display(),
        log_path.display(),
        log_path.display()
    )
}

#[cfg(target_os = "linux")]
fn run_systemctl_user<const N: usize>(args: [&str; N]) -> Result<(), KeyclawError> {
    let xdg_config_home = user_config_home()?;
    let status = Command::new("systemctl")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--user")
        .args(args)
        .status()
        .map_err(|e| KeyclawError::uncoded(format!("run systemctl --user {:?}: {e}", args)))?;
    if status.success() {
        Ok(())
    } else {
        Err(KeyclawError::uncoded(format!(
            "systemctl --user {:?} exited with {status}",
            args
        )))
    }
}

#[cfg(target_os = "linux")]
fn run_systemctl_user_with_path<const N: usize>(
    args: [&str; N],
    unit_path: &Path,
) -> Result<(), KeyclawError> {
    let xdg_config_home = user_config_home()?;
    let status = Command::new("systemctl")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .arg("--user")
        .args(args)
        .arg(unit_path)
        .status()
        .map_err(|e| {
            KeyclawError::uncoded(format!(
                "run systemctl --user {:?} {}: {e}",
                args,
                unit_path.display()
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(KeyclawError::uncoded(format!(
            "systemctl --user {:?} {} exited with {status}",
            args,
            unit_path.display()
        )))
    }
}

#[cfg(target_os = "linux")]
fn user_config_home() -> Result<PathBuf, KeyclawError> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let trimmed = xdg.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }

    let home = std::env::var("HOME")
        .map_err(|_| KeyclawError::uncoded("HOME is required for proxy autostart"))?;
    Ok(PathBuf::from(home).join(".config"))
}

pub(super) fn render_proxy_env_script(
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

#[derive(Clone)]
pub(super) struct Runner {
    config: Config,
    processor: Arc<Processor>,
}

impl Runner {
    pub(super) fn new(config: Config, processor: Arc<Processor>) -> Self {
        Self { config, processor }
    }

    pub(super) fn launch(
        &mut self,
        tool: &str,
        child_args: Vec<String>,
    ) -> Result<i32, KeyclawError> {
        let allowed_hosts = Config::allowed_hosts(tool, &self.config);
        // In mitm mode with a TTY, redirect proxy logs to a file so they
        // do not interleave with the child CLI's TUI output.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 0 {
            let log_path = crate::certgen::keyclaw_dir().join("mitm.log");
            if let Err(e) = crate::proxy::set_log_file(&log_path) {
                crate::logging::warn(&format!(
                    "failed to open log file {}: {e}",
                    log_path.display()
                ));
            }
        }

        if let Some(reason) = launcher_bypass_risk(
            &std::env::var("NO_PROXY").unwrap_or_default(),
            &allowed_hosts,
        ) {
            crate::logging::warn_with_code(CODE_MITM_NOT_EFFECTIVE, &reason);
            if self.config.require_mitm_effective {
                return Err(KeyclawError::coded(CODE_MITM_NOT_EFFECTIVE, reason));
            }
        }

        let ca = crate::certgen::ensure_ca()?;

        let mut proxy_server = Server::new(
            self.config.proxy_listen_addr.clone(),
            allowed_hosts,
            self.processor.clone(),
            ca.cert_pem.clone(),
            ca.key_pem,
        );
        proxy_server.max_body_bytes = self.config.max_body_bytes;
        proxy_server.body_timeout = self.config.detector_timeout;

        let running_proxy = proxy_server.start()?;

        let proxy_url = if self.config.proxy_url.trim().is_empty()
            || running_proxy.addr != self.config.proxy_listen_addr.trim()
        {
            format!("http://{}", running_proxy.addr)
        } else {
            self.config.proxy_url.clone()
        };
        let running_proxy = Arc::new(Mutex::new(Some(running_proxy)));

        let (ca_path, _temp_ca) = resolve_ca_cert_path(&self.config.ca_cert_path)?;
        let (command, args) = build_command(tool, child_args);

        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        for (k, v) in with_proxy_env(proxy_url, ca_path.as_deref()) {
            cmd.env(k, v);
        }

        #[cfg(unix)]
        {
            unsafe {
                cmd.pre_exec(|| {
                    libc::setpgid(0, 0);
                    Ok(())
                });
            }
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| KeyclawError::uncoded(format!("start child process: {e}")))?;

        #[cfg(unix)]
        let original_pgrp = unsafe {
            let child_pid = child.id() as libc::pid_t;
            let original = libc::tcgetpgrp(libc::STDIN_FILENO);
            if original >= 0 {
                set_foreground_process_group(libc::STDIN_FILENO, child_pid);
            }
            original
        };

        #[cfg(unix)]
        let signal_thread = {
            let pid = child.id() as i32;
            let done = Arc::new(AtomicBool::new(false));
            let done_for_thread = Arc::clone(&done);
            let proxy_for_thread = Arc::clone(&running_proxy);
            std::thread::spawn(move || {
                let mut signals = match signal_hook::iterator::Signals::new([
                    signal_hook::consts::SIGINT,
                    signal_hook::consts::SIGTERM,
                    signal_hook::consts::SIGHUP,
                    signal_hook::consts::SIGQUIT,
                ]) {
                    Ok(s) => s,
                    Err(_) => return,
                };

                while !done_for_thread.load(Ordering::SeqCst) {
                    for sig in signals.pending() {
                        unsafe {
                            libc::killpg(pid, sig);
                        }

                        if let Ok(mut guard) = proxy_for_thread.lock() {
                            if let Some(proxy) = guard.take() {
                                drop(proxy);
                            }
                        }

                        if sig == signal_hook::consts::SIGINT || sig == signal_hook::consts::SIGTERM
                        {
                            std::thread::spawn(move || {
                                std::thread::sleep(Duration::from_secs(2));
                                let still_alive = unsafe { libc::kill(pid, 0) == 0 };
                                if still_alive {
                                    unsafe {
                                        libc::killpg(pid, libc::SIGKILL);
                                    }
                                }
                            });
                        }
                    }

                    std::thread::sleep(Duration::from_millis(50));
                }

                signals.handle().close();
            });

            done
        };

        let status = child
            .wait()
            .map_err(|e| KeyclawError::uncoded(format!("wait child process: {e}")))?;

        #[cfg(unix)]
        {
            signal_thread.store(true, Ordering::SeqCst);
            if original_pgrp >= 0 {
                set_foreground_process_group(libc::STDIN_FILENO, original_pgrp);
            }
        }

        std::thread::sleep(Duration::from_millis(50));

        let intercept_count = {
            let mut guard = running_proxy
                .lock()
                .map_err(|_| KeyclawError::uncoded("proxy state lock poisoned"))?;
            let count = guard
                .as_ref()
                .map(|proxy| proxy.intercept_count())
                .unwrap_or(0);
            let _ = guard.take();
            count
        };

        if intercept_count == 0 {
            let reason = "no intercepted requests observed; traffic may be bypassing proxy";
            crate::logging::warn_with_code(CODE_MITM_NOT_EFFECTIVE, reason);
            if self.config.require_mitm_effective {
                if let Some(code) = status.code() {
                    return Ok(code);
                }
                return Err(KeyclawError::coded(CODE_MITM_NOT_EFFECTIVE, reason));
            }
        }

        if let Some(code) = status.code() {
            return Ok(code);
        }

        #[cfg(unix)]
        {
            if let Some(signal) = status.signal() {
                return Ok(128 + signal);
            }
        }

        Ok(1)
    }
}

pub(super) fn configure_unsafe_logging(cfg: &Config) {
    crate::proxy::set_unsafe_log(cfg.unsafe_log);
    if cfg.unsafe_log {
        crate::logging::warn("unsafe logging enabled; secrets may appear in logs");
    }
}

pub(super) fn build_processor(cfg: &Config) -> Result<Arc<Processor>, KeyclawError> {
    let passphrase =
        crate::vault::resolve_vault_passphrase(&cfg.vault_path, cfg.vault_passphrase.as_deref())?;
    let vault = Arc::new(Store::new(cfg.vault_path.clone(), passphrase));

    let mut ruleset = load_runtime_ruleset(cfg)?;
    ruleset.entropy_config = EntropyConfig {
        enabled: cfg.entropy_enabled,
        threshold: cfg.entropy_threshold,
        min_len: cfg.entropy_min_len,
    };

    crate::logging::info(&format!("{} gitleaks rules loaded", ruleset.rules.len()));

    Ok(Arc::new(Processor {
        vault: Some(vault),
        ruleset: Arc::new(ruleset),
        max_body_size: cfg.max_body_bytes,
        strict_mode: cfg.fail_closed,
        notice_mode: cfg.notice_mode,
    }))
}

fn load_runtime_ruleset(cfg: &Config) -> Result<RuleSet, KeyclawError> {
    match cfg.gitleaks_config_path.as_deref() {
        Some(path) => match RuleSet::from_file(path) {
            Ok(ruleset) => {
                if ruleset.skipped_rules > 0 {
                    crate::logging::warn(&format!(
                        "loaded {} custom gitleaks rules from {}, skipped {} invalid rule(s)",
                        ruleset.rules.len(),
                        path.display(),
                        ruleset.skipped_rules
                    ));
                }
                Ok(ruleset)
            }
            Err(err) => {
                crate::logging::warn(&format!(
                    "failed to load custom rules from {}: {err}",
                    path.display()
                ));
                crate::logging::warn("falling back to bundled rules");
                load_bundled_ruleset()
            }
        },
        None => load_bundled_ruleset(),
    }
}

fn load_bundled_ruleset() -> Result<RuleSet, KeyclawError> {
    let ruleset = RuleSet::bundled()
        .map_err(|err| KeyclawError::uncoded(format!("load bundled gitleaks rules: {err}")))?;
    if ruleset.skipped_rules > 0 {
        crate::logging::info(&format!(
            "loaded {} bundled gitleaks rules, skipped {} invalid rule(s)",
            ruleset.rules.len(),
            ruleset.skipped_rules
        ));
    }
    Ok(ruleset)
}

fn with_proxy_env(proxy_url: String, ca_path: Option<&str>) -> Vec<(String, String)> {
    let mut env = std::env::vars().collect::<std::collections::HashMap<_, _>>();

    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        env.insert(key.to_string(), proxy_url.clone());
    }

    if let Some(path) = ca_path {
        for key in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"] {
            env.insert(key.to_string(), path.to_string());
        }
    }

    env.into_iter().collect()
}

fn resolve_ca_cert_path(
    explicit_path: &str,
) -> Result<(Option<String>, Option<NamedTempFile>), KeyclawError> {
    if !explicit_path.trim().is_empty() {
        super::doctor::validate_ca_cert_file(Path::new(explicit_path))?;
        return Ok((Some(explicit_path.to_string()), None));
    }

    let ca_path = crate::certgen::keyclaw_dir().join("ca.crt");
    if ca_path.exists() {
        return Ok((Some(ca_path.to_string_lossy().to_string()), None));
    }

    let ca = crate::certgen::ensure_ca()?;
    let temp = NamedTempFile::new()
        .map_err(|e| KeyclawError::uncoded(format!("create temp CA file: {e}")))?;
    fs::write(temp.path(), ca.cert_pem.as_bytes())
        .map_err(|e| KeyclawError::uncoded(format!("write temp CA file: {e}")))?;

    Ok((Some(temp.path().to_string_lossy().to_string()), Some(temp)))
}

#[cfg(unix)]
fn set_foreground_process_group(fd: libc::c_int, pgrp: libc::pid_t) {
    unsafe {
        let previous = libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::tcsetpgrp(fd, pgrp);
        libc::signal(libc::SIGTTOU, previous);
    }
}

fn build_command(tool: &str, child_args: Vec<String>) -> (String, Vec<String>) {
    let mut child_args = child_args;
    if child_args
        .first()
        .map(|first| first.eq_ignore_ascii_case(tool))
        .unwrap_or(false)
    {
        child_args.remove(0);
    }
    (tool.to_string(), child_args)
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
            return Ok(());
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

fn pid_matches_child(pid_path: &Path, child_pid: u32) -> Result<bool, KeyclawError> {
    let pid = match fs::read_to_string(pid_path) {
        Ok(pid) => pid,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(KeyclawError::uncoded(format!(
                "read proxy pid file {}: {err}",
                pid_path.display()
            )))
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

#[derive(Debug, PartialEq, Eq)]
enum NoProxyEntry {
    Wildcard,
    Host {
        raw: String,
        host: String,
        is_suffix: bool,
        has_port: bool,
    },
}

impl NoProxyEntry {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        if raw == "*" {
            return Some(Self::Wildcard);
        }

        let (host, has_port) = split_host_port(raw);
        let host = host.to_lowercase();
        let is_suffix = host.starts_with('.');
        let host = host.trim_start_matches('.').to_string();
        if host.is_empty() {
            return None;
        }

        Some(Self::Host {
            raw: raw.to_string(),
            host,
            is_suffix,
            has_port,
        })
    }

    fn match_reason(&self, intercepted_host: &str) -> Option<String> {
        match self {
            Self::Wildcard => Some("NO_PROXY=*".to_string()),
            Self::Host {
                raw,
                host,
                is_suffix,
                has_port,
            } => {
                let exact = intercepted_host == host;
                let suffix = intercepted_host.ends_with(&format!(".{host}"));
                if !(exact || *is_suffix && suffix) {
                    return None;
                }

                if *is_suffix || *has_port {
                    Some(format!(
                        "NO_PROXY includes {raw} (matches {intercepted_host})"
                    ))
                } else {
                    Some(format!("NO_PROXY includes {raw}"))
                }
            }
        }
    }
}

pub(super) fn launcher_bypass_risk(no_proxy: &str, hosts: &[String]) -> Option<String> {
    let entries = no_proxy
        .split(',')
        .filter_map(NoProxyEntry::parse)
        .collect::<Vec<_>>();

    for host in hosts
        .iter()
        .filter_map(|host| normalize_no_proxy_host(host))
    {
        for entry in &entries {
            if let Some(reason) = entry.match_reason(&host) {
                return Some(reason);
            }
        }
    }

    None
}

fn normalize_no_proxy_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    Some(split_host_port(host).0.to_lowercase())
}

fn split_host_port(value: &str) -> (&str, bool) {
    let value = value.trim();
    if value.matches(':').count() == 1 {
        if let Some((host, port)) = value.rsplit_once(':') {
            if !host.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
                return (host, true);
            }
        }
    }
    (value, false)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::config::Config;
    use crate::logging::LogLevel;

    fn test_config(vault_path: PathBuf) -> Config {
        Config {
            proxy_listen_addr: "127.0.0.1:8877".into(),
            proxy_url: "http://127.0.0.1:8877".into(),
            ca_cert_path: String::new(),
            vault_path,
            vault_passphrase: None,
            fail_closed: true,
            max_body_bytes: 2 * 1024 * 1024,
            detector_timeout: Duration::from_secs(4),
            known_codex_hosts: Vec::new(),
            known_claude_hosts: Vec::new(),
            gitleaks_config_path: None,
            log_level: LogLevel::Info,
            unsafe_log: false,
            require_mitm_effective: true,
            notice_mode: crate::redaction::NoticeMode::Verbose,
            entropy_enabled: true,
            entropy_threshold: 3.5,
            entropy_min_len: 20,
        }
    }

    #[test]
    fn load_runtime_ruleset_falls_back_to_bundled_rules_when_custom_file_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut cfg = test_config(temp.path().join("vault.enc"));
        cfg.gitleaks_config_path = Some(temp.path().join("missing-gitleaks.toml"));

        let ruleset = super::load_runtime_ruleset(&cfg).expect("fallback to bundled rules");

        assert!(
            !ruleset.rules.is_empty(),
            "bundled fallback should still load shipped rules"
        );
    }

    #[test]
    fn read_and_validate_proxy_pid_returns_none_for_missing_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_path = temp.path().join("proxy.pid");
        assert!(super::read_and_validate_proxy_pid(&pid_path).is_none());
    }

    #[test]
    fn read_and_validate_proxy_pid_returns_none_for_invalid_pid() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_path = temp.path().join("proxy.pid");
        std::fs::write(&pid_path, "not-a-number").expect("write");
        assert!(super::read_and_validate_proxy_pid(&pid_path).is_none());
        // Stale PID file should be cleaned up
        assert!(!pid_path.exists());
    }

    #[test]
    fn read_and_validate_proxy_pid_returns_none_for_dead_process() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_path = temp.path().join("proxy.pid");
        // PID 4294967 is very unlikely to be running
        std::fs::write(&pid_path, "4294967").expect("write");
        assert!(super::read_and_validate_proxy_pid(&pid_path).is_none());
        // Stale PID file should be cleaned up
        assert!(!pid_path.exists());
    }

    #[test]
    fn is_keyclaw_proxy_process_rejects_unrelated_process() {
        // The current test runner is not a keyclaw proxy process
        let pid = std::process::id();
        assert!(!super::is_keyclaw_proxy_process(pid));
    }

    #[test]
    fn read_proxy_addr_from_env_extracts_address() {
        let temp = tempfile::tempdir().expect("tempdir");
        let env_path = temp.path().join("env.sh");
        let content = "# comment\nexport HTTP_PROXY='http://127.0.0.1:9988'\nexport HTTPS_PROXY='http://127.0.0.1:9988'\n";
        std::fs::write(&env_path, content).expect("write");
        assert_eq!(
            super::read_proxy_addr_from_env(&env_path),
            Some("127.0.0.1:9988".to_string())
        );
    }

    #[test]
    fn read_proxy_addr_from_env_returns_none_for_missing_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let env_path = temp.path().join("env.sh");
        assert_eq!(super::read_proxy_addr_from_env(&env_path), None);
    }
}
