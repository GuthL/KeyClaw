#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use crate::errors::KeyclawError;

#[cfg(target_os = "linux")]
const PROXY_AUTOSTART_UNIT_NAME: &str = "keyclaw-proxy.service";

#[cfg(target_os = "linux")]
pub(crate) fn run_proxy_autostart_enable() -> i32 {
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
            super::super::print_error(&err);
            1
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn run_proxy_autostart_enable() -> i32 {
    crate::logging::error("proxy autostart is currently supported only on Linux systemd");
    1
}

#[cfg(target_os = "linux")]
pub(crate) fn run_proxy_autostart_disable() -> i32 {
    match disable_proxy_autostart() {
        Ok(message) => {
            crate::logging::info(&message);
            0
        }
        Err(err) => {
            super::super::print_error(&err);
            1
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn run_proxy_autostart_disable() -> i32 {
    crate::logging::error("proxy autostart is currently supported only on Linux systemd");
    1
}

#[cfg(target_os = "linux")]
pub(crate) fn run_proxy_autostart_status() -> i32 {
    match proxy_autostart_status() {
        Ok((message, code)) => {
            crate::logging::info(&message);
            code
        }
        Err(err) => {
            super::super::print_error(&err);
            1
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn run_proxy_autostart_status() -> i32 {
    crate::logging::error("proxy autostart is currently supported only on Linux systemd");
    1
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
