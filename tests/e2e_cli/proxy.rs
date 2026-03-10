use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;

use crate::support::{
    can_bind, free_addr, install_fake_tool, keyclaw_command, prepend_path, wait_until,
};

#[test]
fn proxy_fails_fast_on_broken_generated_ca_pair() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ca_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&ca_dir).expect("create keyclaw dir");
    std::fs::write(ca_dir.join("ca.crt"), "not-a-cert").expect("write malformed cert");
    std::fs::write(ca_dir.join("ca.key"), "not-a-key").expect("write malformed key");

    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let output = Command::new(bin)
        .arg("proxy")
        .env_clear()
        .env("HOME", temp.path())
        .env("KEYCLAW_PROXY_ADDR", "127.0.0.1:0")
        .env("KEYCLAW_PROXY_URL", "http://127.0.0.1:0")
        .output()
        .expect("run proxy");

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("keyclaw error:"), "stderr={stderr}");
    assert!(
        stderr.contains("remove the broken CA files"),
        "stderr={stderr}"
    );
}

#[cfg(unix)]
#[test]
fn proxy_detaches_by_default_and_prints_stop_instructions() {
    struct ProxyGuard(Vec<i32>);

    impl Drop for ProxyGuard {
        fn drop(&mut self) {
            for pid in self.0.drain(..) {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let addr = free_addr();
    let socket_addr: SocketAddr = addr.parse().expect("parse socket addr");
    let output = keyclaw_command(temp.path())
        .arg("proxy")
        .env("KEYCLAW_PROXY_ADDR", &addr)
        .env("KEYCLAW_PROXY_URL", format!("http://{addr}"))
        .output()
        .expect("run proxy");

    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("proxy running in background"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("does not reconfigure this shell"),
        "stderr should explain that plain `keyclaw proxy` does not update the current shell env: {stderr}"
    );
    assert!(
        stderr.contains("source") && stderr.contains("env.sh"),
        "stderr should point users at sourcing env.sh for the current shell: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("source") && stdout.contains("env.sh"),
        "stdout should contain eval-able source command: stdout={stdout}"
    );

    let pid_path = temp.path().join(".keyclaw").join("proxy.pid");
    let env_path = temp.path().join(".keyclaw").join("env.sh");
    wait_until(Duration::from_secs(3), || {
        pid_path.exists() && env_path.exists() && !can_bind(socket_addr)
    });

    assert!(pid_path.exists(), "proxy pid file missing");
    assert!(env_path.exists(), "proxy env.sh missing");
    assert!(!can_bind(socket_addr), "proxy listener was not started");

    let pid: i32 = std::fs::read_to_string(&pid_path)
        .expect("read proxy pid")
        .trim()
        .parse()
        .expect("parse proxy pid");
    let mut guard = ProxyGuard(vec![pid]);

    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    wait_until(Duration::from_secs(3), || can_bind(socket_addr));
    assert!(
        can_bind(socket_addr),
        "proxy listener still bound: {socket_addr}"
    );
    guard.0.clear();
}

#[cfg(unix)]
#[test]
fn proxy_relaunch_on_same_addr_replaces_existing_daemon() {
    fn process_alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    struct ProxyGuard(Vec<i32>);

    impl Drop for ProxyGuard {
        fn drop(&mut self) {
            for pid in self.0.drain(..) {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let addr = free_addr();
    let socket_addr: SocketAddr = addr.parse().expect("parse socket addr");
    let pid_path = temp.path().join(".keyclaw").join("proxy.pid");
    let env_path = temp.path().join(".keyclaw").join("env.sh");

    let first = keyclaw_command(temp.path())
        .arg("proxy")
        .env("KEYCLAW_PROXY_ADDR", &addr)
        .env("KEYCLAW_PROXY_URL", format!("http://{addr}"))
        .output()
        .expect("start first proxy");
    assert_eq!(first.status.code(), Some(0));

    wait_until(Duration::from_secs(3), || {
        pid_path.exists() && env_path.exists() && !can_bind(socket_addr)
    });

    let first_pid: i32 = std::fs::read_to_string(&pid_path)
        .expect("read first proxy pid")
        .trim()
        .parse()
        .expect("parse first proxy pid");
    let mut guard = ProxyGuard(vec![first_pid]);

    let second = keyclaw_command(temp.path())
        .arg("proxy")
        .env("KEYCLAW_PROXY_ADDR", &addr)
        .env("KEYCLAW_PROXY_URL", format!("http://{addr}"))
        .output()
        .expect("restart proxy on same address");
    assert_eq!(
        second.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );

    wait_until(Duration::from_secs(3), || {
        let second_pid = std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|raw| raw.trim().parse::<i32>().ok());
        match second_pid {
            Some(second_pid) => {
                second_pid != first_pid && process_alive(second_pid) && !process_alive(first_pid)
            }
            None => false,
        }
    });

    let second_pid: i32 = std::fs::read_to_string(&pid_path)
        .expect("read second proxy pid")
        .trim()
        .parse()
        .expect("parse second proxy pid");
    assert_ne!(second_pid, first_pid, "restart should replace the daemon");
    assert!(
        !process_alive(first_pid),
        "original proxy should be stopped on restart"
    );
    assert!(
        process_alive(second_pid),
        "replacement proxy should be alive after restart"
    );
    assert!(
        !can_bind(socket_addr),
        "replacement proxy should still own {socket_addr}"
    );

    guard.0.push(second_pid);
    unsafe {
        libc::kill(second_pid, libc::SIGTERM);
    }
    wait_until(Duration::from_secs(3), || can_bind(socket_addr));
    assert!(
        can_bind(socket_addr),
        "replacement proxy listener still bound: {socket_addr}"
    );
    guard.0.clear();
}

#[cfg(unix)]
#[test]
fn proxy_relaunch_on_different_addr_keeps_existing_daemon() {
    fn process_alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    struct ProxyGuard(Vec<i32>);

    impl Drop for ProxyGuard {
        fn drop(&mut self) {
            for pid in self.0.drain(..) {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let first_addr = free_addr();
    let second_addr = free_addr();
    let first_socket_addr: SocketAddr = first_addr.parse().expect("parse first socket addr");
    let second_socket_addr: SocketAddr = second_addr.parse().expect("parse second socket addr");
    let pid_path = temp.path().join(".keyclaw").join("proxy.pid");
    let env_path = temp.path().join(".keyclaw").join("env.sh");

    let first = keyclaw_command(temp.path())
        .arg("proxy")
        .env("KEYCLAW_PROXY_ADDR", &first_addr)
        .env("KEYCLAW_PROXY_URL", format!("http://{first_addr}"))
        .output()
        .expect("start first proxy");
    assert_eq!(first.status.code(), Some(0));

    wait_until(Duration::from_secs(3), || {
        pid_path.exists() && env_path.exists() && !can_bind(first_socket_addr)
    });

    let first_pid: i32 = std::fs::read_to_string(&pid_path)
        .expect("read first proxy pid")
        .trim()
        .parse()
        .expect("parse first proxy pid");
    let mut guard = ProxyGuard(vec![first_pid]);

    let second = keyclaw_command(temp.path())
        .arg("proxy")
        .env("KEYCLAW_PROXY_ADDR", &second_addr)
        .env("KEYCLAW_PROXY_URL", format!("http://{second_addr}"))
        .output()
        .expect("start second proxy");
    assert_eq!(
        second.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );

    wait_until(Duration::from_secs(3), || {
        let second_pid = std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|raw| raw.trim().parse::<i32>().ok());
        match second_pid {
            Some(second_pid) => {
                second_pid != first_pid
                    && process_alive(first_pid)
                    && process_alive(second_pid)
                    && !can_bind(second_socket_addr)
            }
            None => false,
        }
    });

    let second_pid: i32 = std::fs::read_to_string(&pid_path)
        .expect("read second proxy pid")
        .trim()
        .parse()
        .expect("parse second proxy pid");
    assert_ne!(second_pid, first_pid, "new proxy should become the tracked daemon");
    assert!(
        process_alive(first_pid),
        "original proxy should stay alive when a different address is requested"
    );
    assert!(
        process_alive(second_pid),
        "new proxy should also be alive on the requested address"
    );
    assert!(
        !can_bind(first_socket_addr),
        "original proxy should still own {first_socket_addr}"
    );
    assert!(
        !can_bind(second_socket_addr),
        "new proxy should own {second_socket_addr}"
    );

    guard.0.push(second_pid);
    unsafe {
        libc::kill(first_pid, libc::SIGTERM);
        libc::kill(second_pid, libc::SIGTERM);
    }
    wait_until(Duration::from_secs(3), || {
        can_bind(first_socket_addr) && can_bind(second_socket_addr)
    });
    assert!(
        can_bind(first_socket_addr),
        "original proxy listener still bound: {first_socket_addr}"
    );
    assert!(
        can_bind(second_socket_addr),
        "new proxy listener still bound: {second_socket_addr}"
    );
    guard.0.clear();
}

#[cfg(target_os = "linux")]
#[test]
fn proxy_autostart_enable_writes_systemd_unit_and_invokes_systemctl() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir_all(&fake_bin).expect("create fake bin");
    let systemctl_log = temp.path().join("systemctl.log");

    install_fake_tool(
        &fake_bin,
        "systemctl",
        r#"#!/usr/bin/env bash
printf '%s\n' "$*" >> "$KEYCLAW_TEST_SYSTEMCTL_LOG"
exit 0
"#,
    );

    let mut cmd = keyclaw_command(temp.path());
    prepend_path(&mut cmd, &fake_bin);
    let output = cmd
        .arg("proxy")
        .arg("autostart")
        .arg("enable")
        .env("KEYCLAW_TEST_SYSTEMCTL_LOG", &systemctl_log)
        .output()
        .expect("enable autostart");

    assert_eq!(output.status.code(), Some(0));
    let service_path = temp
        .path()
        .join(".config")
        .join("systemd")
        .join("user")
        .join("keyclaw-proxy.service");
    let service = std::fs::read_to_string(&service_path).expect("read service file");
    assert!(
        service.contains("ExecStart=") && service.contains("proxy --foreground"),
        "service={service}"
    );

    let calls = std::fs::read_to_string(&systemctl_log).expect("read systemctl log");
    assert!(
        calls.contains("--user daemon-reload"),
        "calls should reload user systemd units: {calls}"
    );
    assert!(
        calls.contains("--user enable --now")
            && calls.contains(&service_path.display().to_string()),
        "calls should enable and start the service by path: {calls}"
    );
}
