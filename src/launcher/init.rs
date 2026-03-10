use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::errors::KeyclawError;

const SHELL_SNIPPET: &str = "[ -f ~/.keyclaw/env.sh ] && source ~/.keyclaw/env.sh";

pub(super) fn run_init(cfg: &Config, force: bool) -> i32 {
    println!("KeyClaw first-run setup");
    println!("=======================");

    let result = run_init_inner(cfg, force);
    let doctor_code = match result {
        Ok(()) => {
            println!();
            println!("Running doctor...");
            super::doctor::run_doctor(cfg)
        }
        Err(err) => {
            super::print_error(&err);
            return 1;
        }
    };

    if doctor_code == 0 {
        println!("Setup complete. Run `keyclaw proxy` to start.");
    }

    doctor_code
}

fn run_init_inner(cfg: &Config, force: bool) -> Result<(), KeyclawError> {
    let keyclaw_dir = crate::certgen::keyclaw_dir();
    fs::create_dir_all(&keyclaw_dir)
        .map_err(|err| KeyclawError::uncoded(format!("create {}: {err}", keyclaw_dir.display())))?;

    let (ca_cert_path, ca_key_path) = ensure_ca_artifacts(force)?;
    println!("[ok] CA certificate ready at {}", ca_cert_path.display());
    println!("[ok] CA key ready at {}", ca_key_path.display());

    if let Some(vault_key_path) = ensure_vault_key(cfg, force)? {
        println!("[ok] Vault key ready at {}", vault_key_path.display());
    } else {
        println!("[ok] Vault passphrase override is configured; skipped machine-local vault key");
    }

    let env_path = ensure_env_script(cfg, force)?;
    println!("[ok] Env script ready at {}", env_path.display());

    maybe_patch_shell_rc()?;
    Ok(())
}

fn ensure_ca_artifacts(force: bool) -> Result<(PathBuf, PathBuf), KeyclawError> {
    let keyclaw_dir = crate::certgen::keyclaw_dir();
    let cert_path = keyclaw_dir.join("ca.crt");
    let key_path = keyclaw_dir.join("ca.key");

    if force {
        let _ = fs::remove_file(&cert_path);
        let _ = fs::remove_file(&key_path);
    }

    crate::certgen::ensure_ca()?;
    Ok((cert_path, key_path))
}

fn ensure_vault_key(cfg: &Config, force: bool) -> Result<Option<PathBuf>, KeyclawError> {
    if cfg.vault_passphrase.is_some() {
        return Ok(None);
    }

    let key_path = crate::vault::vault_key_path(&cfg.vault_path);
    if force && key_path.exists() && !cfg.vault_path.exists() {
        let _ = fs::remove_file(&key_path);
    }

    let _ =
        crate::vault::resolve_vault_passphrase(&cfg.vault_path, cfg.vault_passphrase.as_deref())?;
    Ok(Some(key_path))
}

fn ensure_env_script(cfg: &Config, force: bool) -> Result<PathBuf, KeyclawError> {
    let keyclaw_dir = crate::certgen::keyclaw_dir();
    let env_path = keyclaw_dir.join("env.sh");
    if env_path.exists() && !force {
        return Ok(env_path);
    }

    let current_exe = std::env::current_exe()
        .map_err(|err| KeyclawError::uncoded(format!("resolve current executable: {err}")))?;
    let ca_path = if cfg.ca_cert_path.trim().is_empty() {
        keyclaw_dir.join("ca.crt")
    } else {
        PathBuf::from(cfg.ca_cert_path.trim())
    };
    let pid_path = keyclaw_dir.join("proxy.pid");
    let content = render_init_env_script(&cfg.proxy_url, &ca_path, &current_exe, &pid_path);
    fs::write(&env_path, content)
        .map_err(|err| KeyclawError::uncoded(format!("write {}: {err}", env_path.display())))?;
    Ok(env_path)
}

fn maybe_patch_shell_rc() -> Result<(), KeyclawError> {
    let Some(rc_path) = detect_shell_rc_path() else {
        println!(
            "[skip] Could not detect a shell rc file; add `{SHELL_SNIPPET}` manually if needed."
        );
        return Ok(());
    };

    if shell_rc_contains_snippet(&rc_path)? {
        println!(
            "[ok] Shell rc already sources ~/.keyclaw/env.sh ({})",
            rc_path.display()
        );
        return Ok(());
    }

    println!("Add KeyClaw to your shell? [Y/n]");
    println!("  Detected: {}", rc_path.display());
    println!("  Will add: {SHELL_SNIPPET}");

    if !prompt_yes_default_yes()? {
        println!("[skip] Shell rc unchanged");
        return Ok(());
    }

    append_shell_snippet(&rc_path)?;
    println!("[ok] Updated {}", rc_path.display());
    Ok(())
}

fn detect_shell_rc_path() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok().map(PathBuf::from)?;
    let shell = std::env::var("SHELL").unwrap_or_default();

    let preferred = if shell.ends_with("zsh") {
        home.join(".zshrc")
    } else {
        home.join(".bashrc")
    };
    let fallback = if preferred.ends_with(".zshrc") {
        home.join(".bashrc")
    } else {
        home.join(".zshrc")
    };

    if preferred.exists() || !fallback.exists() {
        Some(preferred)
    } else {
        Some(fallback)
    }
}

fn shell_rc_contains_snippet(path: &Path) -> Result<bool, KeyclawError> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(contents.contains(SHELL_SNIPPET)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(KeyclawError::uncoded(format!(
            "read shell rc {}: {err}",
            path.display()
        ))),
    }
}

fn append_shell_snippet(path: &Path) -> Result<(), KeyclawError> {
    let existing = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(KeyclawError::uncoded(format!(
                "read shell rc {}: {err}",
                path.display()
            )));
        }
    };

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(SHELL_SNIPPET);
    updated.push('\n');

    fs::write(path, updated)
        .map_err(|err| KeyclawError::uncoded(format!("write shell rc {}: {err}", path.display())))
}

fn prompt_yes_default_yes() -> Result<bool, KeyclawError> {
    print!("> ");
    io::stdout()
        .flush()
        .map_err(|err| KeyclawError::uncoded(format!("flush stdout: {err}")))?;

    let mut line = String::new();
    let bytes = io::stdin()
        .read_line(&mut line)
        .map_err(|err| KeyclawError::uncoded(format!("read stdin: {err}")))?;

    if bytes == 0 {
        return Ok(false);
    }

    let trimmed = line.trim().to_ascii_lowercase();
    Ok(trimmed.is_empty() || trimmed == "y" || trimmed == "yes")
}

fn render_init_env_script(
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
    let pid_file = shell_single_quote(&pid_path.display().to_string());
    let exe_name = shell_single_quote(exe_name);
    let proxy_url = shell_single_quote(proxy_url);
    let ca_path = shell_single_quote(&ca_path.display().to_string());

    format!(
        r#"# Generated by keyclaw init.
# Safe to keep in .bashrc or .zshrc — exports only while the keyclaw proxy is running.
keyclaw_proxy_pid_file={pid_file}
keyclaw_proxy_exe_name={exe_name}

keyclaw_proxy_active() {{
  if [ ! -r "$keyclaw_proxy_pid_file" ]; then
    return 1
  fi

  keyclaw_proxy_pid="$(cat "$keyclaw_proxy_pid_file" 2>/dev/null || true)"
  case "$keyclaw_proxy_pid" in
    ''|*[!0-9]*) return 1 ;;
  esac

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
