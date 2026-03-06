use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use keyclaw::certgen;
use keyclaw::gitleaks_rules::RuleSet;
use keyclaw::pipeline::Processor;
use keyclaw::proxy::Server;
use keyclaw::vault::Store;
use reqwest::blocking::Client;
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
        .body(format!(r#"{{"messages":[{{"content":"api_key = {}"}}]}}"#, CODEX_SECRET))
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);

    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    assert!(!capture.body.contains(CODEX_SECRET), "secret leaked: {}", capture.body);
    assert!(capture.body.contains("{{KEYCLAW_SECRET_"), "no placeholder: {}", capture.body);
    assert!(
        capture
            .headers
            .iter()
            .any(|(k, v)| k == "x-keyclaw-contract" && v == "placeholder:v1")
    );
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
    assert!(!capture.body.contains(CLAUDE_SECRET), "secret leaked: {}", capture.body);
    assert!(capture.body.contains("{{KEYCLAW_SECRET_"), "no placeholder: {}", capture.body);
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

fn start_upstream() -> (String, mpsc::Receiver<UpstreamCapture>, thread::JoinHandle<()>) {
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
