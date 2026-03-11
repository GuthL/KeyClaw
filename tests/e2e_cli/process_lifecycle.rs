use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(unix)]
use wait_timeout::ChildExt;

use crate::support::{can_bind, free_addr, install_fake_tool, prepend_path, wait_until};

#[cfg(unix)]
#[test]
#[ignore = "slow daemon/proxy e2e"]
fn mitm_releases_proxy_port_immediately_on_sigint() {
    let addr = free_addr();
    let socket_addr: SocketAddr = addr.parse().expect("parse socket addr");
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let temp = tempfile::tempdir().expect("tempdir");
    let tool_dir = temp.path().join("bin");
    std::fs::create_dir_all(&tool_dir).expect("create tool dir");
    install_fake_tool(
        &tool_dir,
        "codex",
        "#!/usr/bin/env bash\ntrap '' INT TERM\nsleep 60\n",
    );

    let mut command = Command::new(bin);
    command
        .arg("mitm")
        .arg("codex")
        .env("KEYCLAW_PROXY_ADDR", &addr)
        .env("KEYCLAW_PROXY_URL", format!("http://{addr}"))
        .env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", "false")
        .env("KEYCLAW_CODEX_HOSTS", "127.0.0.1")
        .env("HOME", temp.path());
    prepend_path(&mut command, &tool_dir);
    let mut child = command.spawn().expect("spawn keyclaw");

    wait_until(Duration::from_secs(3), || !can_bind(socket_addr));

    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }

    wait_until(Duration::from_millis(700), || can_bind(socket_addr));
    assert!(
        can_bind(socket_addr),
        "proxy listener still bound after SIGINT: {socket_addr}"
    );

    let status = child
        .wait_timeout(Duration::from_secs(5))
        .expect("wait timeout")
        .or_else(|| {
            let _ = child.kill();
            child.wait().ok()
        })
        .expect("wait child");
    assert!(
        status.code() == Some(130) || status.code() == Some(137) || status.signal().is_some(),
        "unexpected child status: {status}"
    );
}

#[cfg(unix)]
#[test]
#[ignore = "slow daemon/proxy e2e"]
fn mitm_returns_control_to_interactive_shell_after_child_exit() {
    let bin = assert_cmd::cargo::cargo_bin!("keyclaw");
    let temp = tempfile::tempdir().expect("tempdir");
    let tool_dir = temp.path().join("bin");
    std::fs::create_dir_all(&tool_dir).expect("create tool dir");
    install_fake_tool(&tool_dir, "codex", "#!/usr/bin/env bash\nexit 0\n");

    let py = format!(
        r#"
import os
import pty
import re
import select
import signal
import subprocess
import sys
import time

bin_path = {bin_path:?}
tool_dir = {tool_dir:?}
cmd = (
    "KEYCLAW_REQUIRE_MITM_EFFECTIVE=false "
    "KEYCLAW_PROXY_ADDR=127.0.0.1:0 "
    f"PATH={tool_dir}:$PATH {{bin_path}} mitm codex; "
    "printf '__RC__=%s\\n' \"$?\"; jobs -l; exit"
)

pid, fd = pty.fork()
if pid == 0:
    os.execvp("bash", ["bash", "--noprofile", "--norc", "-i"])

os.set_blocking(fd, False)
buf = bytearray()
sentinel = re.compile(rb"(?:\r\n|\n|\r)__RC__=")
ready = re.compile(rb"(?:\r\n|\n|\r)__READY__(?:\r\n|\n|\r)")

def pump(timeout, marker=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if fd not in ready:
            continue
        try:
            data = os.read(fd, 4096)
        except BlockingIOError:
            continue
        except OSError:
            return False
        if not data:
            return False
        buf.extend(data)
        if marker and marker.search(buf):
            return True
        if marker is None and sentinel.search(buf):
            return True
    return False

def write_all(data):
    view = memoryview(data)
    while view:
        _, writable, _ = select.select([], [fd], [], 0.1)
        if fd not in writable:
            continue
        try:
            written = os.write(fd, view)
        except BlockingIOError:
            continue
        view = view[written:]

time.sleep(1.0)
write_all(b"export PS1='PROMPT> '; printf '__READY__\\n'\r")
if not pump(10.0, ready):
    print(buf.decode("utf-8", "replace"))
    sys.exit(3)
write_all(cmd.encode())
write_all(b"\r")
ok = pump(5.0)
output = buf.decode("utf-8", "replace")
print(output)

if not ok:
    try:
        raw = subprocess.check_output(["pgrep", "-P", str(pid)], text=True)
        for child in raw.split():
            try:
                os.kill(int(child), signal.SIGKILL)
            except ProcessLookupError:
                pass
    except subprocess.CalledProcessError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    sys.exit(1)

if re.search(r"(^|[\r\n])__RC__=0(?:\r\n|\n|\r|$)", output) and "Stopped" not in output:
    sys.exit(0)

sys.exit(2)
"#,
        bin_path = bin.display().to_string(),
        tool_dir = tool_dir.display().to_string(),
    );

    let output = Command::new("python3")
        .arg("-c")
        .arg(py)
        .output()
        .expect("run pty harness");

    assert_eq!(
        output.status.code(),
        Some(0),
        "pty harness failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
