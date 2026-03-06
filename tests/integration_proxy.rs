use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use keyclaw::detector::{Detector, Finding, Severity};
use keyclaw::errors::{KeyclawError, CODE_GITLEAKS_UNAVAILABLE};
use keyclaw::pipeline::Processor;
use keyclaw::policy::{Executor, Mode};
use keyclaw::proxy::Server;
use keyclaw::vault::Store;
use reqwest::blocking::Client;
use tiny_http::{Response, Server as TinyServer, StatusCode};

#[derive(Clone)]
struct StubDetector {
    findings: Vec<Finding>,
    err: Option<KeyclawError>,
}

impl Detector for StubDetector {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn detect(&self, _payload: &[u8]) -> Result<Vec<Finding>, KeyclawError> {
        if let Some(err) = &self.err {
            return Err(err.clone());
        }
        Ok(self.findings.clone())
    }
}

struct UpstreamCapture {
    body: String,
    headers: Vec<(String, String)>,
}

#[test]
fn codex_payload_rewritten_before_upstream() {
    let (upstream_url, rx, _upstream_guard) = start_upstream();
    let processor = new_processor(
        StubDetector {
            findings: vec![],
            err: None,
        },
        StubDetector {
            findings: vec![],
            err: None,
        },
    );

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new("127.0.0.1:0".to_string(), vec![host], Arc::new(processor));
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
        .body(r#"{"messages":[{"content":"use sk-ABCDEF0123456789ABCDEF0123456789"}]}"#)
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);

    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    assert!(!capture.body.contains("sk-ABCDEF"));
    assert!(capture.body.contains("{{KEYCLAW_SECRET_"));
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
    let processor = new_processor(
        StubDetector {
            findings: vec![],
            err: None,
        },
        StubDetector {
            findings: vec![],
            err: None,
        },
    );

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new("127.0.0.1:0".to_string(), vec![host], Arc::new(processor));
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
        .body(r#"{"prompt":"sk-ant-ABCDEFGHIJKLMNOPQRSTUVWX123456"}"#)
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);

    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    assert!(!capture.body.contains("sk-ant-"));
    assert!(capture.body.contains("{{KEYCLAW_SECRET_"));
}

#[test]
fn gitleaks_finding_warns_but_allows_request() {
    let (upstream_url, _rx, _upstream_guard) = start_upstream();

    let high = Finding {
        detector: "gitleaks".to_string(),
        rule_id: "rule".to_string(),
        message: "finding".to_string(),
        secret: "***".to_string(),
        severity: Severity::High,
    };

    let processor = new_processor(
        StubDetector {
            findings: vec![high],
            err: None,
        },
        StubDetector {
            findings: vec![],
            err: None,
        },
    );

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new("127.0.0.1:0".to_string(), vec![host], Arc::new(processor));
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
        .body(r#"{"prompt":"hi"}"#)
        .send()
        .expect("request");

    // Findings no longer block — secrets are replaced, request passes through
    assert_eq!(resp.status().as_u16(), 200);
}

#[test]
fn gitleaks_timeout_fallback_allows_when_clean() {
    let (upstream_url, rx, _upstream_guard) = start_upstream();

    let processor = new_processor(
        StubDetector {
            findings: vec![],
            err: Some(KeyclawError::coded(CODE_GITLEAKS_UNAVAILABLE, "timeout")),
        },
        StubDetector {
            findings: vec![],
            err: None,
        },
    );

    let host = url::Url::parse(&upstream_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .expect("host");

    let mut proxy = Server::new("127.0.0.1:0".to_string(), vec![host], Arc::new(processor));
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
        .body(r#"{"prompt":"safe"}"#)
        .send()
        .expect("request");

    assert_eq!(resp.status().as_u16(), 200);
    let _ = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
}

#[test]
fn untrusted_host_passes_through_without_rewriting() {
    let (upstream_url, rx, _upstream_guard) = start_upstream();

    let processor = new_processor(
        StubDetector {
            findings: vec![],
            err: None,
        },
        StubDetector {
            findings: vec![],
            err: None,
        },
    );

    let mut proxy = Server::new(
        "127.0.0.1:0".to_string(),
        vec!["example.com".to_string()],
        Arc::new(processor),
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
        .body(r#"{"prompt":"sk-ABCDEF0123456789ABCDEF0123456789"}"#)
        .send()
        .expect("request");

    // Non-allowed hosts pass through without rewriting
    assert_eq!(resp.status().as_u16(), 200);
    let capture = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("upstream capture");
    // Secret should NOT be replaced — host is not in the allowlist
    assert!(capture.body.contains("sk-ABCDEF"));
}

fn new_processor(primary: StubDetector, fallback: StubDetector) -> Processor {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.enc");
    let vault = Arc::new(Store::new(vault_path, "test-pass".to_string()));

    let exec = Arc::new(Executor::new(
        Some(Arc::new(primary)),
        Some(Arc::new(fallback)),
        Mode::Block,
        true,
    ));

    Processor {
        vault: Some(vault),
        policy: Some(exec),
        max_body_size: 1 << 20,
        strict_mode: true,
    }
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
