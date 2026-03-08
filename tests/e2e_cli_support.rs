mod support;

use std::env;
use std::net::{SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use keyclaw::placeholder;

#[test]
fn upstream_guard_drop_releases_listener() {
    let (upstream_url, _rx, upstream_guard) = support::start_upstream();
    let addr = url_socket_addr(&upstream_url);

    drop(upstream_guard);

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(1) {
        if TcpListener::bind(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }

    panic!("support upstream listener {addr} stayed bound after guard drop");
}

#[test]
fn run_mitm_ignores_ambient_no_proxy() {
    let (upstream_url, rx, _guard) = support::start_upstream();
    let original = env::var_os("NO_PROXY");
    env::set_var("NO_PROXY", "*");

    let (stderr, exit_code) = support::run_mitm(
        "codex",
        support::free_addr(),
        &upstream_url,
        &format!(r#"{{"prompt":"api_key = {}"}}"#, support::TEST_SECRET_CODEX),
    );

    match original {
        Some(value) => env::set_var("NO_PROXY", value),
        None => env::remove_var("NO_PROXY"),
    }

    assert_eq!(exit_code, 0, "stderr={stderr}");
    let body = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream body");
    assert!(
        placeholder::contains_complete_placeholder(&body),
        "ambient NO_PROXY bypassed the proxy: {body}"
    );
}

fn url_socket_addr(url: &str) -> SocketAddr {
    let parsed = url::Url::parse(url).expect("parse upstream url");
    let host = parsed.host_str().expect("upstream host");
    let port = parsed.port().expect("upstream port");
    SocketAddr::new(host.parse().expect("parse upstream ip"), port)
}
