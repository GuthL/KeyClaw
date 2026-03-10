#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::errors::KeyclawError;

#[cfg(target_os = "linux")]
const PROXY_AUTOSTART_UNIT_NAME: &str = "keyclaw-proxy.service";
#[cfg(target_os = "macos")]
const PROXY_AUTOSTART_LABEL: &str = "com.keyclaw.proxy";

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn run_proxy_autostart_enable() -> i32 {
    match enable_proxy_autostart() {
        Ok(path) => {
            crate::logging::info(&format!("proxy autostart enabled via {}", path.display()));
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn run_proxy_autostart_enable() -> i32 {
    crate::logging::error(
        "proxy autostart is currently supported only on Linux systemd and macOS launchd",
    );
    1
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn run_proxy_autostart_disable() -> i32 {
    crate::logging::error(
        "proxy autostart is currently supported only on Linux systemd and macOS launchd",
    );
    1
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn run_proxy_autostart_status() -> i32 {
    crate::logging::error(
        "proxy autostart is currently supported only on Linux systemd and macOS launchd",
    );
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

#[cfg(target_os = "macos")]
fn enable_proxy_autostart() -> Result<PathBuf, KeyclawError> {
    let plist_path = proxy_autostart_plist_path()?;
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            KeyclawError::uncoded(format!("create autostart dir {}: {e}", parent.display()))
        })?;
    }
    fs::create_dir_all(crate::certgen::keyclaw_dir())
        .map_err(|e| KeyclawError::uncoded(format!("create keyclaw dir: {e}")))?;

    let current_exe = std::env::current_exe()
        .map_err(|e| KeyclawError::uncoded(format!("resolve current executable: {e}")))?;
    let plist_contents = render_proxy_autostart_plist(&current_exe);
    fs::write(&plist_path, plist_contents)
        .map_err(|e| KeyclawError::uncoded(format!("write {}: {e}", plist_path.display())))?;

    let label_target = launchctl_label_target();
    let domain = launchctl_gui_domain();
    let plist = plist_path.display().to_string();

    let _ = run_launchctl(&["bootout", label_target.as_str()]);
    let _ = run_launchctl(&["enable", label_target.as_str()]);
    run_launchctl(&["bootstrap", domain.as_str(), plist.as_str()])?;
    run_launchctl(&["kickstart", "-k", label_target.as_str()])?;

    Ok(plist_path)
}

#[cfg(target_os = "macos")]
fn disable_proxy_autostart() -> Result<String, KeyclawError> {
    let plist_path = proxy_autostart_plist_path()?;
    if !plist_path.exists() {
        return Ok("proxy autostart is not configured".to_string());
    }

    let label_target = launchctl_label_target();
    let _ = run_launchctl(&["bootout", label_target.as_str()]);
    let _ = run_launchctl(&["disable", label_target.as_str()]);

    fs::remove_file(&plist_path)
        .map_err(|e| KeyclawError::uncoded(format!("remove {}: {e}", plist_path.display())))?;

    Ok(format!(
        "proxy autostart disabled and removed from {}",
        plist_path.display()
    ))
}

#[cfg(target_os = "macos")]
fn proxy_autostart_status() -> Result<(String, i32), KeyclawError> {
    let plist_path = proxy_autostart_plist_path()?;
    if !plist_path.exists() {
        return Ok(("proxy autostart is not configured".to_string(), 1));
    }

    let active = run_launchctl(&["print", launchctl_label_target().as_str()]).is_ok();
    Ok((
        format!(
            "proxy autostart agent present at {} (active={})",
            plist_path.display(),
            active
        ),
        0,
    ))
}

#[cfg(target_os = "macos")]
fn proxy_autostart_plist_path() -> Result<PathBuf, KeyclawError> {
    Ok(home_dir()?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{PROXY_AUTOSTART_LABEL}.plist")))
}

#[cfg(target_os = "macos")]
fn render_proxy_autostart_plist(current_exe: &Path) -> String {
    let current_exe = xml_escape(&current_exe.display().to_string());
    let log_path = xml_escape(
        &crate::certgen::keyclaw_dir()
            .join("proxy.log")
            .display()
            .to_string(),
    );
    let label = xml_escape(PROXY_AUTOSTART_LABEL);

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{current_exe}</string>
    <string>proxy</string>
    <string>--foreground</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log_path}</string>
  <key>StandardErrorPath</key>
  <string>{log_path}</string>
</dict>
</plist>
"#
    )
}

#[cfg(target_os = "macos")]
fn launchctl_gui_domain() -> String {
    format!("gui/{}", unsafe { libc::geteuid() })
}

#[cfg(target_os = "macos")]
fn launchctl_label_target() -> String {
    format!("{}/{}", launchctl_gui_domain(), PROXY_AUTOSTART_LABEL)
}

#[cfg(target_os = "macos")]
fn run_launchctl(args: &[&str]) -> Result<(), KeyclawError> {
    let status = Command::new("launchctl")
        .args(args)
        .status()
        .map_err(|e| KeyclawError::uncoded(format!("run launchctl {:?}: {e}", args)))?;
    if status.success() {
        Ok(())
    } else {
        Err(KeyclawError::uncoded(format!(
            "launchctl {:?} exited with {status}",
            args
        )))
    }
}

#[cfg(target_os = "macos")]
fn home_dir() -> Result<PathBuf, KeyclawError> {
    let home = std::env::var("HOME")
        .map_err(|_| KeyclawError::uncoded("HOME is required for proxy autostart"))?;
    Ok(PathBuf::from(home))
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
