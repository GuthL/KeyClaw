use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use keyclaw::certgen;
use keyclaw::gitleaks_rules::RuleSet;
use keyclaw::pipeline::Processor;
use keyclaw::placeholder;
use keyclaw::proxy::Server;
use keyclaw::vault::Store;
use reqwest::blocking::Client;
use serde_json::json;
use tiny_http::{Response, Server as TinyServer, StatusCode};

struct UpstreamCapture {
    body: String,
    headers: Vec<(String, String)>,
}

// Use secrets in "api_key = <value>" format so gitleaks generic-api-key rule matches
const CODEX_SECRET: &str = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
const CLAUDE_SECRET: &str = "xY2zW4vU6tS8rQ0pO2nM4lK6jI8hG0f";

fn test_ca() -> (String, String) {
    let ca = certgen::ensure_ca().expect("generate test CA");
    (ca.cert_pem, ca.key_pem)
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
        capture.body.contains("{{KEYCLAW_SECRET_"),
        "no placeholder: {}",
        capture.body
    );
    assert!(capture
        .headers
        .iter()
        .any(|(k, v)| k == "x-keyclaw-contract" && v == "placeholder:v1"));
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
        capture.body.contains("{{KEYCLAW_SECRET_"),
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
    let real_placeholder_re =
        regex::Regex::new(r"\{\{KEYCLAW_SECRET_[A-Za-z0-9*_-]{1,5}_[a-f0-9]{16}\}\}").unwrap();
    assert!(
        !real_placeholder_re.is_match(&resp_body),
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

fn new_processor_with_ca() -> (Processor, String, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.enc");
    let vault = Arc::new(Store::new(vault_path, "test-pass".to_string()));
    let ruleset = Arc::new(RuleSet::bundled().expect("bundled rules"));
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
fn start_echo_upstream() -> (
    String,
    mpsc::Receiver<UpstreamCapture>,
    thread::JoinHandle<()>,
) {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = TinyServer::from_listener(listener, None).expect("server");

    let (tx, rx) = mpsc::channel();

    let join = thread::spawn(move || loop {
        match server.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(mut req)) => {
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
                            tiny_http::Header::from_bytes(
                                &b"content-type"[..],
                                &b"application/json"[..],
                            )
                            .unwrap(),
                        )
                        .with_status_code(StatusCode(200)),
                );
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    });

    (format!("http://{}", addr), rx, join)
}

fn start_upstream() -> (
    String,
    mpsc::Receiver<UpstreamCapture>,
    thread::JoinHandle<()>,
) {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = TinyServer::from_listener(listener, None).expect("server");

    let (tx, rx) = mpsc::channel();

    let join = thread::spawn(move || loop {
        match server.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(mut req)) => {
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
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    });

    (format!("http://{}", addr), rx, join)
}

fn start_sse_upstream(
    response_body: String,
) -> (
    String,
    mpsc::Receiver<UpstreamCapture>,
    thread::JoinHandle<()>,
) {
    let listener =
        TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = TinyServer::from_listener(listener, None).expect("server");

    let (tx, rx) = mpsc::channel();

    let join = thread::spawn(move || loop {
        match server.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(mut req)) => {
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
                            tiny_http::Header::from_bytes(
                                &b"content-type"[..],
                                &b"text/event-stream"[..],
                            )
                            .unwrap(),
                        )
                        .with_status_code(StatusCode(200)),
                );
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    });

    (format!("http://{}", addr), rx, join)
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
