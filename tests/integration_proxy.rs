use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use keyclaw::gitleaks_rules::RuleSet;
use keyclaw::pipeline::Processor;
use keyclaw::placeholder;
use keyclaw::proxy::Server;
use keyclaw::vault::Store;
use once_cell::sync::Lazy;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyUsagePurpose,
};
use reqwest::blocking::Client;
use serde_json::json;
use tiny_http::{Response, Server as TinyServer, StatusCode};

struct UpstreamCapture {
    body: String,
    headers: Vec<(String, String)>,
}

struct UpstreamGuard {
    shutdown: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl Drop for UpstreamGuard {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

// Use secrets in "api_key = <value>" format so gitleaks generic-api-key rule matches
const CODEX_SECRET: &str = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
const CLAUDE_SECRET: &str = "xY2zW4vU6tS8rQ0pO2nM4lK6jI8hG0f";

static HOME_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// Reuse immutable test fixtures so integration tests exercise the proxy path,
// not repeated CA parsing and gitleaks rule compilation.
static TEST_CA: Lazy<(String, String)> = Lazy::new(build_test_ca);
static TEST_RULESET: Lazy<Arc<RuleSet>> =
    Lazy::new(|| Arc::new(RuleSet::bundled().expect("bundled rules")));

fn test_ca() -> (String, String) {
    (TEST_CA.0.clone(), TEST_CA.1.clone())
}

fn build_test_ca() -> (String, String) {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "KeyClaw Integration Test CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "KeyClaw Tests");
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let key_pair = rcgen::KeyPair::generate().expect("generate test CA key");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-sign test CA cert");

    (cert.pem(), key_pair.serialize_pem())
}

#[test]
fn codex_payload_rewritten_before_upstream() {
    let (upstream_url, rx, _upstream_guard) = start_upstream();
    let (processor, ca_cert, ca_key) = new_processor_with_ca();

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec![host],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");

    let client = Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", running.addr)).expect("proxy"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let resp = client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"messages":[{{"content":"api_key = {}"}}]}}"#,
            CODEX_SECRET
        ))
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);

    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    assert!(
        !capture.body.contains(CODEX_SECRET),
        "secret leaked: {}",
        capture.body
    );
    assert!(
        placeholder::contains_complete_placeholder(&capture.body),
        "no placeholder: {}",
        capture.body
    );
    assert!(capture.headers.iter().any(|(k, v)| {
        k == placeholder::CONTRACT_MARKER_KEY && v == placeholder::CONTRACT_MARKER_VALUE
    }));
}

#[test]
fn claude_payload_rewritten_before_upstream() {
    let (upstream_url, rx, _upstream_guard) = start_upstream();
    let (processor, ca_cert, ca_key) = new_processor_with_ca();

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec![host],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");

    let client = Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", running.addr)).expect("proxy"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let resp = client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(format!(r#"{{"prompt":"secret_key: {}"}}"#, CLAUDE_SECRET))
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);

    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    assert!(
        !capture.body.contains(CLAUDE_SECRET),
        "secret leaked: {}",
        capture.body
    );
    assert!(
        placeholder::contains_complete_placeholder(&capture.body),
        "no placeholder: {}",
        capture.body
    );
}

#[test]
fn untrusted_host_passes_through_without_rewriting() {
    let (upstream_url, rx, _upstream_guard) = start_upstream();
    let (processor, ca_cert, ca_key) = new_processor_with_ca();

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec!["example.com".to_string()],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");

    let client = Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", running.addr)).expect("proxy"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let resp = client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(format!(r#"{{"prompt":"api_key = {}"}}"#, CODEX_SECRET))
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);
    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    // Secret should NOT be replaced — host is not in the allowlist
    assert!(capture.body.contains(CODEX_SECRET));
}

#[test]
fn response_placeholders_resolved_back_to_secrets() {
    let (upstream_url, rx, _upstream_guard) = start_echo_upstream();
    let (processor, ca_cert, ca_key) = new_processor_with_ca();
    let expected_placeholder = placeholder::make(&placeholder::make_id(CODEX_SECRET));

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec![host],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");

    let client = Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", running.addr)).expect("proxy"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    // Send a request with a secret — the proxy will replace it with a placeholder.
    // The echo upstream bounces the (rewritten) body back as the response.
    // The proxy's response handler should resolve the placeholder back to the real secret.
    let resp = client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"messages":[{{"content":"api_key = {}"}}]}}"#,
            CODEX_SECRET
        ))
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);

    // Verify the upstream received the placeholder (not the secret)
    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    assert!(
        !capture.body.contains(CODEX_SECRET),
        "secret leaked to upstream"
    );
    assert!(
        capture.body.contains(&expected_placeholder),
        "expected upstream to receive exact placeholder {expected_placeholder}, got {}",
        capture.body
    );

    // Verify the client received the real secret back (placeholder resolved)
    let resp_body = resp.text().expect("response body");
    assert!(
        resp_body.contains(CODEX_SECRET),
        "secret not reinjected in response: {}",
        resp_body
    );
    // Check no *real* placeholders remain (the redaction notice contains an example
    // `{{KEYCLAW_SECRET_xxxx}}` which is fine — it doesn't match the full pattern).
    assert!(
        !placeholder::contains_complete_placeholder(&resp_body),
        "unresolved real placeholder in response: {}",
        resp_body
    );
}

#[test]
fn oversized_body_is_rejected_without_upstream_forwarding() {
    let (upstream_url, rx, _upstream_guard) = start_upstream();
    let (processor, ca_cert, ca_key) = new_processor_with_ca();

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec![host],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 32;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");

    let client = Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", running.addr)).expect("proxy"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let resp = client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"messages":[{{"content":"api_key = {}"}}]}}"#,
            CODEX_SECRET
        ))
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 413);
    let body = resp.text().expect("response body");
    assert!(body.contains("body_too_large"), "body={body}");
    assert!(
        body.contains("request body exceeded maximum size"),
        "body={body}"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "oversized request should not reach upstream"
    );
}

#[test]
fn malformed_json_is_passed_through_unchanged() {
    let (upstream_url, rx, _upstream_guard) = start_echo_upstream();
    let (processor, ca_cert, ca_key) = new_processor_with_ca();
    let malformed = format!(r#"{{"prompt":"api_key = {}""#, CODEX_SECRET);

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec![host],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");

    let client = Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", running.addr)).expect("proxy"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let resp = client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(malformed.clone())
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);
    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    assert_eq!(capture.body, malformed);

    let resp_body = resp.text().expect("response body");
    assert_eq!(resp_body, malformed);
}

#[test]
fn request_body_timeout_returns_request_timeout_error() {
    let (upstream_url, rx, _upstream_guard) = start_upstream();
    let (processor, ca_cert, ca_key) = new_processor_with_ca();

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec![host],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_millis(150);
    let running = proxy.start().expect("start proxy");

    let response = send_partial_proxy_request(&running.addr, &upstream_url, r#"{"messages":["#, 64);

    assert!(
        response.contains("408 Request Timeout"),
        "response={response}"
    );
    assert!(response.contains("request_timeout"), "response={response}");
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "timed out request should not reach upstream"
    );
}

#[test]
fn sse_input_json_delta_fragments_resolve_split_placeholders() {
    let placeholder = placeholder::make(&placeholder::make_id(CODEX_SECRET));
    let split = placeholder.len() / 2;
    let first_fragment = format!("{{\"content\":\"{}", &placeholder[..split]);
    let second_fragment = format!("{}\"}}", &placeholder[split..]);
    let event_one = json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {
            "type": "input_json_delta",
            "partial_json": first_fragment,
        }
    })
    .to_string();
    let event_two = json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {
            "type": "input_json_delta",
            "partial_json": second_fragment,
        }
    })
    .to_string();
    let sse_body = format!(
        "event: content_block_delta\ndata: {event_one}\n\nevent: content_block_delta\ndata: {event_two}\n\n"
    );

    let (upstream_url, rx, _upstream_guard) = start_sse_upstream(sse_body);
    let (processor, ca_cert, ca_key) = new_processor_with_ca();

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec![host],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");

    let client = Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", running.addr)).expect("proxy"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let resp = client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"messages":[{{"content":"api_key = {}"}}]}}"#,
            CODEX_SECRET
        ))
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);

    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    assert!(
        !capture.body.contains(CODEX_SECRET),
        "secret leaked to upstream"
    );
    assert!(
        capture.body.contains(&placeholder),
        "expected upstream to receive exact placeholder {placeholder}, got {}",
        capture.body
    );

    let resp_body = resp.text().expect("response body");
    let deltas = collect_input_json_deltas(&resp_body);
    assert_eq!(
        deltas.concat(),
        format!("{{\"content\":\"{}\"}}", CODEX_SECRET)
    );
    assert!(
        deltas
            .iter()
            .all(|delta| !delta.contains("KEYCLAW_SECRET") && !delta.contains("{{")),
        "placeholder fragments leaked to client SSE: {:?}",
        deltas
    );
}

#[test]
fn chunked_non_sse_responses_are_resolved_as_normal_bodies() {
    let (upstream_url, rx, _upstream_guard) = start_chunked_echo_upstream();
    let (processor, ca_cert, ca_key) = new_processor_with_ca();
    let expected_placeholder = placeholder::make(&placeholder::make_id(CODEX_SECRET));

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec![host],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");

    let client = Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{}", running.addr)).expect("proxy"))
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    let resp = client
        .post(&upstream_url)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"messages":[{{"content":"api_key = {}"}}]}}"#,
            CODEX_SECRET
        ))
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);

    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    assert!(
        capture.body.contains(&expected_placeholder),
        "expected upstream to receive exact placeholder {expected_placeholder}, got {}",
        capture.body
    );

    let resp_body = resp.text().expect("response body");
    assert!(
        resp_body.contains(CODEX_SECRET),
        "secret not reinjected in chunked response: {resp_body}"
    );
    assert!(
        !placeholder::contains_complete_placeholder(&resp_body),
        "placeholder leaked in chunked response: {resp_body}"
    );
}

#[test]
fn ca_fixture_ignores_broken_home_state() {
    let _home_lock = HOME_LOCK.lock().expect("lock HOME");
    let original_home = std::env::var_os("HOME");
    let temp = tempfile::tempdir().expect("tempdir");
    let keyclaw_dir = temp.path().join(".keyclaw");
    std::fs::create_dir_all(&keyclaw_dir).expect("create keyclaw dir");
    std::fs::write(keyclaw_dir.join("ca.crt"), "not-a-cert").expect("write broken cert");
    std::fs::write(keyclaw_dir.join("ca.key"), "not-a-key").expect("write broken key");

    std::env::set_var("HOME", temp.path());
    let result = std::panic::catch_unwind(build_test_ca);

    match original_home {
        Some(home) => std::env::set_var("HOME", home),
        None => std::env::remove_var("HOME"),
    }

    assert!(
        result.is_ok(),
        "integration proxy CA fixture should ignore broken ~/.keyclaw state"
    );
}

#[test]
fn upstream_guard_drop_releases_listener() {
    let (upstream_url, _rx, upstream_guard) = start_upstream();
    let addr = url_socket_addr(&upstream_url);

    drop(upstream_guard);

    assert_listener_released(addr, "upstream listener");
}

#[test]
fn proxy_server_drop_releases_listener_without_traffic() {
    let (processor, ca_cert, ca_key) = new_processor_with_ca();
    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec!["127.0.0.1".to_string()],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");
    let addr = running.addr.parse().expect("parse proxy addr");

    drop(running);

    assert_listener_released(addr, "proxy listener without traffic");
}

#[test]
fn proxy_server_drop_releases_listener_after_request() {
    let (upstream_url, rx, _upstream_guard) = start_upstream();
    let (processor, ca_cert, ca_key) = new_processor_with_ca();

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec![host],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);
    let running = proxy.start().expect("start proxy");
    let addr = running.addr.parse().expect("parse proxy addr");

    {
        let client = Client::builder()
            .proxy(reqwest::Proxy::http(format!("http://{}", running.addr)).expect("proxy"))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("client");

        let resp = client
            .post(&upstream_url)
            .header("content-type", "application/json")
            .body(format!(r#"{{"prompt":"api_key = {}"}}"#, CODEX_SECRET))
            .send()
            .expect("request");

        assert_eq!(resp.status().as_u16(), 200);
        rx.recv_timeout(Duration::from_secs(2))
            .expect("upstream capture");
    }

    drop(running);

    assert_listener_released(addr, "proxy listener after request");
}

#[test]
fn proxy_server_lifecycle_is_fast_without_traffic() {
    let (processor, ca_cert, ca_key) = new_processor_with_ca();
    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec!["127.0.0.1".to_string()],
        Arc::new(processor),
        ca_cert,
        ca_key,
    );
    proxy.max_body_bytes = 1 << 20;
    proxy.body_timeout = Duration::from_secs(2);

    let startup_start = std::time::Instant::now();
    let running = proxy.start().expect("start proxy");
    let startup_elapsed = startup_start.elapsed();

    let shutdown_start = std::time::Instant::now();
    drop(running);
    let shutdown_elapsed = shutdown_start.elapsed();

    assert!(
        startup_elapsed < Duration::from_secs(2),
        "proxy startup took {startup_elapsed:?}, shutdown took {shutdown_elapsed:?}"
    );
    assert!(
        shutdown_elapsed < Duration::from_secs(2),
        "proxy shutdown took {shutdown_elapsed:?}, startup took {startup_elapsed:?}"
    );
}

#[test]
fn warmed_processor_fixture_setup_is_fast() {
    let _ = new_processor_with_ca();

    let start = std::time::Instant::now();
    let _ = new_processor_with_ca();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "warmed new_processor_with_ca took {elapsed:?}"
    );
}

fn new_processor_with_ca() -> (Processor, String, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.enc");
    let vault = Arc::new(Store::new(vault_path, "test-pass".to_string()));
    let ruleset = Arc::clone(&TEST_RULESET);
    let (ca_cert, ca_key) = test_ca();

    let processor = Processor {
        vault: Some(vault),
        ruleset,
        max_body_size: 1 << 20,
        strict_mode: true,
    };

    (processor, ca_cert, ca_key)
}

/// Upstream that echoes the request body back as the response body.
fn start_echo_upstream() -> (String, mpsc::Receiver<UpstreamCapture>, UpstreamGuard) {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = TinyServer::from_listener(listener, None).expect("server");

    let (tx, rx) = mpsc::channel();

    let guard = spawn_upstream(server, move |mut req| {
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_lowercase(),
                    h.value.as_str().to_string(),
                )
            })
            .collect();
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);
        let _ = tx.send(UpstreamCapture {
            body: body.clone(),
            headers,
        });
        // Echo the request body back as the response
        let _ = req.respond(
            Response::from_string(body)
                .with_header(
                    tiny_http::Header::from_bytes(&b"content-type"[..], &b"application/json"[..])
                        .unwrap(),
                )
                .with_status_code(StatusCode(200)),
        );
    });

    (format!("http://{}", addr), rx, guard)
}

fn start_upstream() -> (String, mpsc::Receiver<UpstreamCapture>, UpstreamGuard) {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = TinyServer::from_listener(listener, None).expect("server");

    let (tx, rx) = mpsc::channel();

    let guard = spawn_upstream(server, move |mut req| {
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_lowercase(),
                    h.value.as_str().to_string(),
                )
            })
            .collect();
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);
        let _ = tx.send(UpstreamCapture { body, headers });
        let _ = req.respond(Response::empty(StatusCode(200)));
    });

    (format!("http://{}", addr), rx, guard)
}

fn start_sse_upstream(
    response_body: String,
) -> (String, mpsc::Receiver<UpstreamCapture>, UpstreamGuard) {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = TinyServer::from_listener(listener, None).expect("server");

    let (tx, rx) = mpsc::channel();

    let guard = spawn_upstream(server, move |mut req| {
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_lowercase(),
                    h.value.as_str().to_string(),
                )
            })
            .collect();
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);
        let _ = tx.send(UpstreamCapture { body, headers });
        let _ = req.respond(
            Response::from_string(response_body.clone())
                .with_header(
                    tiny_http::Header::from_bytes(&b"content-type"[..], &b"text/event-stream"[..])
                        .unwrap(),
                )
                .with_status_code(StatusCode(200)),
        );
    });

    (format!("http://{}", addr), rx, guard)
}

fn start_chunked_echo_upstream() -> (String, mpsc::Receiver<UpstreamCapture>, UpstreamGuard) {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = TinyServer::from_listener(listener, None).expect("server");

    let (tx, rx) = mpsc::channel();

    let guard = spawn_upstream(server, move |mut req| {
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_lowercase(),
                    h.value.as_str().to_string(),
                )
            })
            .collect();
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);
        let _ = tx.send(UpstreamCapture {
            body: body.clone(),
            headers,
        });
        let _ = req.respond(
            Response::from_string(body)
                .with_header(
                    tiny_http::Header::from_bytes(&b"content-type"[..], &b"application/json"[..])
                        .unwrap(),
                )
                .with_chunked_threshold(0)
                .with_status_code(StatusCode(200)),
        );
    });

    (format!("http://{}", addr), rx, guard)
}

fn collect_input_json_deltas(body: &str) -> Vec<String> {
    body.split("\n\n")
        .filter_map(|event| {
            let data = event
                .lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .collect::<Vec<_>>()
                .join("\n");
            if data.is_empty() {
                return None;
            }
            let parsed: serde_json::Value = serde_json::from_str(&data).ok()?;
            let delta = parsed.get("delta")?;
            if delta.get("type")?.as_str()? != "input_json_delta" {
                return None;
            }
            Some(delta.get("partial_json")?.as_str()?.to_string())
        })
        .collect()
}

fn url_socket_addr(url: &str) -> SocketAddr {
    let parsed = url::Url::parse(url).expect("parse upstream url");
    let host = parsed.host_str().expect("upstream host");
    let port = parsed.port().expect("upstream port");
    SocketAddr::new(host.parse().expect("parse upstream ip"), port)
}

fn assert_listener_released(addr: SocketAddr, label: &str) {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(1) {
        if TcpListener::bind(addr).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }

    panic!("{label} {addr} stayed bound after drop");
}

fn spawn_upstream(
    server: TinyServer,
    mut handle_request: impl FnMut(tiny_http::Request) + Send + 'static,
) -> UpstreamGuard {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let join = thread::spawn(move || loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }

        match server.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(req)) => handle_request(req),
            Ok(None) => continue,
            Err(_) => break,
        }
    });

    UpstreamGuard {
        shutdown: Some(shutdown_tx),
        join: Some(join),
    }
}

fn send_partial_proxy_request(
    proxy_addr: &str,
    upstream_url: &str,
    partial_body: &str,
    declared_content_length: usize,
) -> String {
    let host = url::Url::parse(upstream_url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(port) => format!("{h}:{port}"),
                None => h.to_string(),
            })
        })
        .expect("upstream host");

    let mut stream = TcpStream::connect(proxy_addr).expect("connect proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let request = format!(
        "POST {upstream_url} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {declared_content_length}\r\nConnection: close\r\n\r\n{partial_body}"
    );
    stream
        .write_all(request.as_bytes())
        .expect("write partial request");
    stream.flush().expect("flush request");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read proxy response");
    response
}
