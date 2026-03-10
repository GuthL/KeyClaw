use std::fs;
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::NamedTempFile;

use crate::config::Config;
use crate::errors::{CODE_MITM_NOT_EFFECTIVE, KeyclawError};
use crate::pipeline::Processor;
use crate::proxy::Server;

use super::no_proxy::launcher_bypass_risk;

#[derive(Clone)]
pub(crate) struct Runner {
    config: Config,
    processor: Arc<Processor>,
}

impl Runner {
    pub(crate) fn new(config: Config, processor: Arc<Processor>) -> Self {
        Self { config, processor }
    }

    pub(crate) fn launch(
        &mut self,
        tool: &str,
        child_args: Vec<String>,
    ) -> Result<i32, KeyclawError> {
        let allowed_hosts = Config::allowed_hosts(tool, &self.config);
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
        proxy_server.audit_log_path = self.config.audit_log_path.clone();

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
        super::super::doctor::validate_ca_cert_file(Path::new(explicit_path))?;
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
