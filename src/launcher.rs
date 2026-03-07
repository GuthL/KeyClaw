use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};

use tempfile::NamedTempFile;
use url::Url;

use crate::config::Config;
use crate::errors::{code_of, KeyclawError, CODE_MITM_NOT_EFFECTIVE};
use crate::gitleaks_rules::RuleSet;
use crate::pipeline::Processor;
use crate::proxy::Server;
use crate::vault::{Store, VaultPassphraseStatus};

pub fn run_cli(args: Vec<String>) -> i32 {
    if args.is_empty() {
        print_usage(&mut io::stderr());
        return 2;
    }

    let cfg = Config::from_env();
    crate::logging::configure(cfg.log_level);

    match args[0].as_str() {
        "doctor" => run_doctor(&cfg),
        "mitm" => {
            configure_unsafe_logging(&cfg);
            match build_processor(&cfg) {
                Ok(processor) => run_mitm(&cfg, processor, &args[1..]),
                Err(err) => {
                    print_error(&err);
                    1
                }
            }
        }
        "proxy" => {
            configure_unsafe_logging(&cfg);
            match build_processor(&cfg) {
                Ok(processor) => run_proxy(&cfg, processor),
                Err(err) => {
                    print_error(&err);
                    1
                }
            }
        }
        "rewrite-json" => {
            configure_unsafe_logging(&cfg);
            match build_processor(&cfg) {
                Ok(processor) => run_rewrite_json(processor),
                Err(err) => {
                    print_error(&err);
                    1
                }
            }
        }
        _ => {
            print_usage(&mut io::stderr());
            2
        }
    }
}

fn run_mitm(cfg: &Config, processor: Arc<Processor>, args: &[String]) -> i32 {
    if args.is_empty() {
        crate::logging::error("usage: keyclaw mitm <codex|claude> [-- child args]");
        return 2;
    }

    let tool = args[0].trim().to_lowercase();
    if tool != "codex" && tool != "claude" {
        crate::logging::error(&format!("unsupported tool \"{tool}\""));
        return 2;
    }

    let child_args = if let Some(idx) = args[1..].iter().position(|a| a == "--") {
        args[1 + idx + 1..].to_vec()
    } else {
        args[1..].to_vec()
    };

    let mut runner = Runner::new(cfg.clone(), processor);
    match runner.launch(&tool, child_args) {
        Ok(code) => code,
        Err(err) => {
            print_error(&err);
            1
        }
    }
}

fn run_proxy(cfg: &Config, processor: Arc<Processor>) -> i32 {
    let allowed_hosts = Config::allowed_hosts("all", cfg);

    let ca = match crate::certgen::ensure_ca() {
        Ok(ca) => ca,
        Err(e) => {
            crate::logging::error(&e.to_string());
            return 1;
        }
    };

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
            print_error(&err);
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
    crate::logging::info("source ~/.keyclaw/env.sh in any shell to route through keyclaw");
    crate::logging::info("press Ctrl-C to stop");

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

fn render_proxy_env_script(
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

fn run_rewrite_json(processor: Arc<Processor>) -> i32 {
    let mut input = Vec::new();
    if io::stdin().read_to_end(&mut input).is_err() {
        crate::logging::error("failed to read stdin");
        return 1;
    }

    match processor.rewrite_and_evaluate(&input) {
        Ok(result) => {
            if io::stdout().write_all(&result.body).is_err() {
                crate::logging::error("failed to write stdout");
                return 1;
            }
            0
        }
        Err(err) => {
            print_error(&err);
            1
        }
    }
}

fn run_doctor(cfg: &Config) -> i32 {
    let checks = doctor_checks(cfg);
    let mut passed = 0usize;
    let mut warnings = 0usize;
    let mut failures = 0usize;

    for check in checks {
        match check.status {
            DoctorStatus::Pass => passed += 1,
            DoctorStatus::Warn => warnings += 1,
            DoctorStatus::Fail => failures += 1,
        }

        println!(
            "doctor: {} {} {}",
            check.status.label(),
            check.id,
            crate::logscrub::scrub(&check.message)
        );
        if let Some(hint) = check.hint {
            println!("doctor: hint: {}", crate::logscrub::scrub(&hint));
        }
    }

    println!("doctor: summary: {passed} passed, {warnings} warnings, {failures} blocking");

    if failures == 0 {
        0
    } else {
        1
    }
}

#[derive(Clone, Copy)]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

impl DoctorStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

struct DoctorCheck {
    status: DoctorStatus,
    id: &'static str,
    message: String,
    hint: Option<String>,
}

#[derive(Clone)]
pub struct Runner {
    config: Config,
    processor: Arc<Processor>,
}

impl Runner {
    pub fn new(config: Config, processor: Arc<Processor>) -> Self {
        Self { config, processor }
    }

    pub fn launch(&mut self, tool: &str, child_args: Vec<String>) -> Result<i32, KeyclawError> {
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

        // Give the child process group foreground terminal access so interactive
        // CLIs (codex, claude) can read from stdin without receiving SIGTTIN.
        #[cfg(unix)]
        let original_pgrp = unsafe {
            let child_pid = child.id() as libc::pid_t;
            let original = libc::tcgetpgrp(libc::STDIN_FILENO);
            // Only set foreground if stdin is a TTY (tcgetpgrp returns -1 otherwise)
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
            // Restore keyclaw as the foreground process group so we can
            // print post-run diagnostics without SIGTTOU.
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

fn configure_unsafe_logging(cfg: &Config) {
    crate::proxy::set_unsafe_log(cfg.unsafe_log);
    if cfg.unsafe_log {
        crate::logging::warn("unsafe logging enabled; secrets may appear in logs");
    }
}

fn doctor_checks(cfg: &Config) -> Vec<DoctorCheck> {
    vec![
        check_proxy_bind(cfg),
        check_proxy_url(cfg),
        check_ca_cert(cfg),
        check_vault_path(cfg),
        check_ruleset(cfg),
        check_proxy_bypass(cfg),
        check_unsafe_log(cfg),
        check_vault_passphrase(cfg),
    ]
}

fn check_proxy_bind(cfg: &Config) -> DoctorCheck {
    match TcpListener::bind(cfg.proxy_listen_addr.trim()) {
        Ok(listener) => {
            let addr = listener
                .local_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| cfg.proxy_listen_addr.clone());
            drop(listener);
            pass_check("proxy-bind", format!("can bind proxy listener on {addr}"))
        }
        Err(err) => fail_check(
            "proxy-bind",
            format!(
                "cannot bind proxy listener on {}: {err}",
                cfg.proxy_listen_addr.trim()
            ),
            "set KEYCLAW_PROXY_ADDR to a free local address, for example 127.0.0.1:8877"
                .to_string(),
        ),
    }
}

fn check_proxy_url(cfg: &Config) -> DoctorCheck {
    let proxy_url = cfg.proxy_url.trim();
    if proxy_url.is_empty() {
        return fail_check(
            "proxy-url",
            "proxy URL is empty".to_string(),
            "set KEYCLAW_PROXY_URL to an http://host:port URL".to_string(),
        );
    }

    match Url::parse(proxy_url) {
        Ok(url) if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() => {
            pass_check("proxy-url", format!("proxy URL {proxy_url} is valid"))
        }
        Ok(_) => fail_check(
            "proxy-url",
            format!("proxy URL {proxy_url} is missing a supported scheme or host"),
            "set KEYCLAW_PROXY_URL to an http://host:port URL".to_string(),
        ),
        Err(err) => fail_check(
            "proxy-url",
            format!("proxy URL {proxy_url} is invalid: {err}"),
            "set KEYCLAW_PROXY_URL to an http://host:port URL".to_string(),
        ),
    }
}

fn check_ca_cert(cfg: &Config) -> DoctorCheck {
    let explicit_path = cfg.ca_cert_path.trim();
    if !explicit_path.is_empty() {
        return match validate_ca_cert_file(Path::new(explicit_path)) {
            Ok(()) => pass_check(
                "ca-cert",
                format!("readable CA cert configured at {explicit_path}"),
            ),
            Err(err) => fail_check(
                "ca-cert",
                err.to_string(),
                "set KEYCLAW_CA_CERT to a readable PEM file or unset it to use ~/.keyclaw/ca.crt"
                    .to_string(),
            ),
        };
    }

    let keyclaw_dir = crate::certgen::keyclaw_dir();
    let cert_path = keyclaw_dir.join("ca.crt");
    let key_path = keyclaw_dir.join("ca.key");
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => match validate_generated_ca_pair(&cert_path, &key_path) {
            Ok(()) => pass_check(
                "ca-cert",
                format!("existing CA pair is ready at {}", cert_path.display()),
            ),
            Err(err) => fail_check(
                "ca-cert",
                err.to_string(),
                "remove the broken CA files in ~/.keyclaw or regenerate them with `keyclaw proxy`"
                    .to_string(),
            ),
        },
        (true, false) | (false, true) => fail_check(
            "ca-cert",
            format!(
                "incomplete CA state in {} (need both ca.crt and ca.key)",
                keyclaw_dir.display()
            ),
            "remove the partial CA files in ~/.keyclaw, then rerun `keyclaw proxy`".to_string(),
        ),
        (false, false) => match ensure_dir_writable(&keyclaw_dir) {
            Ok(()) => pass_check(
                "ca-cert",
                format!(
                    "CA files are not generated yet, but {} is writable",
                    keyclaw_dir.display()
                ),
            ),
            Err(err) => fail_check(
                "ca-cert",
                err.to_string(),
                "ensure ~/.keyclaw exists and is writable before starting the proxy".to_string(),
            ),
        },
    }
}

fn check_vault_path(cfg: &Config) -> DoctorCheck {
    match validate_vault_path(&cfg.vault_path) {
        Ok(()) => pass_check(
            "vault-path",
            format!("vault path is writable at {}", cfg.vault_path.display()),
        ),
        Err(err) => fail_check(
            "vault-path",
            err.to_string(),
            "set KEYCLAW_VAULT_PATH to a writable file path".to_string(),
        ),
    }
}

fn check_ruleset(cfg: &Config) -> DoctorCheck {
    match cfg.gitleaks_config_path.as_deref() {
        Some(path) => match RuleSet::from_file(path) {
            Ok(ruleset) if ruleset.skipped_rules > 0 => warn_check(
                "ruleset",
                format!(
                    "loaded {} custom gitleaks rules from {}, skipped {} invalid rule(s)",
                    ruleset.rules.len(),
                    path.display(),
                    ruleset.skipped_rules
                ),
                "fix the invalid rules in KEYCLAW_GITLEAKS_CONFIG or unset it to use the bundled rules".to_string(),
            ),
            Ok(ruleset) => pass_check(
                "ruleset",
                format!(
                    "loaded {} custom gitleaks rules from {}",
                    ruleset.rules.len(),
                    path.display()
                ),
            ),
            Err(err) => fail_check(
                "ruleset",
                format!(
                    "cannot load custom gitleaks rules from {}: {err}",
                    path.display()
                ),
                "fix KEYCLAW_GITLEAKS_CONFIG or unset it to use the bundled rules".to_string(),
            ),
        },
        None => pass_check("ruleset", "using bundled gitleaks rules".to_string()),
    }
}

fn check_proxy_bypass(cfg: &Config) -> DoctorCheck {
    match launcher_bypass_risk(
        &std::env::var("NO_PROXY").unwrap_or_default(),
        &Config::allowed_hosts("all", cfg),
    ) {
        Some(reason) if cfg.require_mitm_effective => fail_check(
            "proxy-bypass",
            format!("{CODE_MITM_NOT_EFFECTIVE}: {reason}"),
            "unset NO_PROXY or remove intercepted hosts from it before running KeyClaw".to_string(),
        ),
        Some(reason) => warn_check(
            "proxy-bypass",
            format!("{CODE_MITM_NOT_EFFECTIVE}: {reason}"),
            "unset NO_PROXY or enable KEYCLAW_REQUIRE_MITM_EFFECTIVE for stricter safety"
                .to_string(),
        ),
        None => pass_check(
            "proxy-bypass",
            "NO_PROXY does not bypass the intercepted hosts".to_string(),
        ),
    }
}

fn check_unsafe_log(cfg: &Config) -> DoctorCheck {
    if cfg.unsafe_log {
        warn_check(
            "unsafe-log",
            "KEYCLAW_UNSAFE_LOG is enabled; logs may contain raw secrets".to_string(),
            "unset KEYCLAW_UNSAFE_LOG for normal use".to_string(),
        )
    } else {
        pass_check(
            "unsafe-log",
            "unsafe logging is disabled; log scrubbing remains active".to_string(),
        )
    }
}

fn check_vault_passphrase(cfg: &Config) -> DoctorCheck {
    match crate::vault::inspect_vault_passphrase_status(
        &cfg.vault_path,
        cfg.vault_passphrase.as_deref(),
    ) {
        Ok(VaultPassphraseStatus::EnvOverride) => pass_check(
            "vault-key",
            "custom vault passphrase configured via KEYCLAW_VAULT_PASSPHRASE".to_string(),
        ),
        Ok(VaultPassphraseStatus::LegacyEnvOverride) => warn_check(
            "vault-key",
            "KEYCLAW_VAULT_PASSPHRASE is set to the legacy built-in default".to_string(),
            "set KEYCLAW_VAULT_PASSPHRASE to a unique value or remove it to use a generated machine-local key".to_string(),
        ),
        Ok(VaultPassphraseStatus::GeneratedKeyReady(path)) => pass_check(
            "vault-key",
            format!("machine-local vault key ready at {}", path.display()),
        ),
        Ok(VaultPassphraseStatus::GeneratedKeyWillBeCreated(path)) => pass_check(
            "vault-key",
            format!(
                "machine-local vault key will be created at {} on first write",
                path.display()
            ),
        ),
        Ok(VaultPassphraseStatus::LegacyVaultWillMigrate(path)) => warn_check(
            "vault-key",
            "existing vault still uses the legacy built-in default and will be migrated on next write"
                .to_string(),
            format!(
                "run a write path once to generate {} and re-encrypt the vault",
                path.display()
            ),
        ),
        Err(err) => fail_check(
            "vault-key",
            err.to_string(),
            "restore the machine-local vault key or set KEYCLAW_VAULT_PASSPHRASE to the correct value".to_string(),
        ),
    }
}

fn build_processor(cfg: &Config) -> Result<Arc<Processor>, KeyclawError> {
    let passphrase =
        crate::vault::resolve_vault_passphrase(&cfg.vault_path, cfg.vault_passphrase.as_deref())?;
    let vault = Arc::new(Store::new(cfg.vault_path.clone(), passphrase));

    let ruleset = load_runtime_ruleset(cfg);

    crate::logging::info(&format!("{} gitleaks rules loaded", ruleset.rules.len()));

    Ok(Arc::new(Processor {
        vault: Some(vault),
        ruleset: Arc::new(ruleset),
        max_body_size: cfg.max_body_bytes,
        strict_mode: cfg.fail_closed,
    }))
}

fn load_runtime_ruleset(cfg: &Config) -> RuleSet {
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
                ruleset
            }
            Err(err) => {
                crate::logging::warn(&format!(
                    "failed to load custom rules from {}: {err}",
                    path.display()
                ));
                crate::logging::warn("falling back to bundled rules");
                let ruleset = RuleSet::bundled().expect("bundled gitleaks rules must compile");
                if ruleset.skipped_rules > 0 {
                    crate::logging::info(&format!(
                        "loaded {} bundled gitleaks rules, skipped {} invalid rule(s)",
                        ruleset.rules.len(),
                        ruleset.skipped_rules
                    ));
                }
                ruleset
            }
        },
        None => {
            let ruleset = RuleSet::bundled().expect("bundled gitleaks rules must compile");
            if ruleset.skipped_rules > 0 {
                crate::logging::info(&format!(
                    "loaded {} bundled gitleaks rules, skipped {} invalid rule(s)",
                    ruleset.rules.len(),
                    ruleset.skipped_rules
                ));
            }
            ruleset
        }
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
        validate_ca_cert_file(Path::new(explicit_path))?;
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

fn validate_ca_cert_file(path: &Path) -> Result<(), KeyclawError> {
    let metadata = fs::metadata(path).map_err(|err| {
        KeyclawError::uncoded(format!("cannot access CA cert {}: {err}", path.display()))
    })?;
    if !metadata.is_file() {
        return Err(KeyclawError::uncoded(format!(
            "CA cert path {} is not a file",
            path.display()
        )));
    }
    fs::read_to_string(path).map_err(|err| {
        KeyclawError::uncoded(format!("cannot read CA cert {}: {err}", path.display()))
    })?;
    Ok(())
}

fn validate_generated_ca_pair(cert_path: &Path, key_path: &Path) -> Result<(), KeyclawError> {
    crate::certgen::validate_generated_ca_pair(cert_path, key_path).map(|_| ())
}

fn validate_vault_path(path: &Path) -> Result<(), KeyclawError> {
    if path.is_dir() {
        return Err(KeyclawError::uncoded(format!(
            "vault path {} is a directory, not a file",
            path.display()
        )));
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir_writable(dir)?;

    if path.exists() {
        let metadata = fs::metadata(path).map_err(|err| {
            KeyclawError::uncoded(format!(
                "cannot access vault path {}: {err}",
                path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Err(KeyclawError::uncoded(format!(
                "vault path {} is not a regular file",
                path.display()
            )));
        }
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|err| {
                KeyclawError::uncoded(format!("cannot open vault path {}: {err}", path.display()))
            })?;
    }

    Ok(())
}

fn ensure_dir_writable(path: &Path) -> Result<(), KeyclawError> {
    fs::create_dir_all(path)
        .map_err(|err| KeyclawError::uncoded(format!("cannot create {}: {err}", path.display())))?;
    NamedTempFile::new_in(path).map_err(|err| {
        KeyclawError::uncoded(format!("cannot write in {}: {err}", path.display()))
    })?;
    Ok(())
}

fn pass_check(id: &'static str, message: String) -> DoctorCheck {
    DoctorCheck {
        status: DoctorStatus::Pass,
        id,
        message,
        hint: None,
    }
}

fn warn_check(id: &'static str, message: String, hint: String) -> DoctorCheck {
    DoctorCheck {
        status: DoctorStatus::Warn,
        id,
        message,
        hint: Some(hint),
    }
}

fn fail_check(id: &'static str, message: String, hint: String) -> DoctorCheck {
    DoctorCheck {
        status: DoctorStatus::Fail,
        id,
        message,
        hint: Some(hint),
    }
}

#[cfg(unix)]
fn set_foreground_process_group(fd: libc::c_int, pgrp: libc::pid_t) {
    unsafe {
        // After handing the TTY to the child, keyclaw is in a background
        // process group. Restoring the original foreground group would
        // otherwise stop us with SIGTTOU before cleanup can run.
        let previous = libc::signal(libc::SIGTTOU, libc::SIG_IGN);
        libc::tcsetpgrp(fd, pgrp);
        libc::signal(libc::SIGTTOU, previous);
    }
}

fn build_command(tool: &str, child_args: Vec<String>) -> (String, Vec<String>) {
    if let Some((first, rest)) = child_args.split_first() {
        return (first.clone(), rest.to_vec());
    }
    (tool.to_string(), Vec::new())
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

pub fn launcher_bypass_risk(no_proxy: &str, hosts: &[String]) -> Option<String> {
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

fn print_error(err: &KeyclawError) {
    let code = code_of(err);
    let msg = err.display_without_code();
    if let Some(code) = code {
        crate::logging::error_with_code(code, &msg);
    } else {
        crate::logging::error(&msg);
    }
}

fn print_usage(w: &mut dyn Write) {
    let _ = writeln!(w, "Usage:");
    let _ = writeln!(
        w,
        "  keyclaw proxy                      # start global proxy daemon"
    );
    let _ = writeln!(w, "  keyclaw mitm codex -- [codex args]");
    let _ = writeln!(w, "  keyclaw mitm claude -- [claude args]");
    let _ = writeln!(w, "  keyclaw rewrite-json < payload.json");
    let _ = writeln!(w, "  keyclaw doctor");
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn launcher_bypass_risk_detects_exact_host_matches() {
        let risk = super::launcher_bypass_risk(
            "api.openai.com",
            &[
                String::from("api.openai.com"),
                String::from("api.anthropic.com"),
            ],
        );

        assert_eq!(risk.as_deref(), Some("NO_PROXY includes api.openai.com"));
    }

    #[test]
    fn launcher_bypass_risk_detects_suffix_matches() {
        let risk = super::launcher_bypass_risk(".openai.com", &[String::from("api.openai.com")]);

        assert_eq!(
            risk.as_deref(),
            Some("NO_PROXY includes .openai.com (matches api.openai.com)")
        );
    }

    #[test]
    fn launcher_bypass_risk_detects_host_port_matches() {
        let risk =
            super::launcher_bypass_risk("api.openai.com:443", &[String::from("api.openai.com")]);

        assert_eq!(
            risk.as_deref(),
            Some("NO_PROXY includes api.openai.com:443 (matches api.openai.com)")
        );
    }

    #[test]
    fn launcher_bypass_risk_normalizes_case_and_whitespace() {
        let risk =
            super::launcher_bypass_risk(" API.OPENAI.COM:443 ", &[String::from("api.openai.com")]);

        assert_eq!(
            risk.as_deref(),
            Some("NO_PROXY includes API.OPENAI.COM:443 (matches api.openai.com)")
        );
    }

    #[test]
    fn launcher_bypass_risk_ignores_unrelated_entries() {
        let risk = super::launcher_bypass_risk(
            "example.com,.internal.local",
            &[String::from("api.openai.com")],
        );

        assert_eq!(risk, None);
    }

    #[cfg(unix)]
    #[test]
    fn proxy_env_script_disables_stale_pid_reused_by_unrelated_process() {
        let temp = tempfile::tempdir().expect("tempdir");
        let env_path = temp.path().join("env.sh");
        let pid_path = temp.path().join("proxy.pid");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut unrelated = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn unrelated process");

        fs::write(&pid_path, unrelated.id().to_string()).expect("write proxy.pid");
        let script = super::render_proxy_env_script(
            unrelated.id(),
            "http://127.0.0.1:8877",
            Path::new("/tmp/keyclaw-ca.crt"),
            Path::new("/tmp/keyclaw"),
            &pid_path,
        );
        fs::write(&env_path, script).expect("write env.sh");

        let output = Command::new("bash")
            .arg("-lc")
            .arg(format!(
                "source \"{}\"; \
                 if [ -n \"${{HTTP_PROXY:-}}\" ]; then echo proxy=enabled; else echo proxy=disabled; fi; \
                 if [ -e \"{}\" ]; then echo pid=present; else echo pid=missing; fi",
                env_path.display(),
                pid_path.display()
            ))
            .env_clear()
            .env("PATH", path)
            .output()
            .expect("source env.sh");

        let _ = unrelated.kill();
        let _ = unrelated.wait();

        assert_eq!(
            output.status.code(),
            Some(0),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("proxy=disabled"), "stdout={stdout}");
        assert!(stdout.contains("pid=missing"), "stdout={stdout}");
    }
}
