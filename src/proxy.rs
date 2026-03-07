use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{
        header::{CONTENT_LENGTH, CONTENT_TYPE, HOST},
        Method, Request, Response, StatusCode,
    },
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::Message,
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext,
    WebSocketHandler,
};

use crate::errors::{
    code_of, KeyclawError, CODE_BODY_TOO_LARGE, CODE_INVALID_JSON, CODE_REQUEST_TIMEOUT,
};
use crate::logscrub;
use crate::pipeline::Processor;


static UNSAFE_LOG: AtomicBool = AtomicBool::new(false);

pub fn set_unsafe_log(enabled: bool) {
    UNSAFE_LOG.store(enabled, Ordering::SeqCst);
}

fn unsafe_log_enabled() -> bool {
    UNSAFE_LOG.load(Ordering::Relaxed)
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}


pub struct Server {
    pub listen_addr: String,
    pub allowed_hosts: Vec<String>,
    pub processor: Arc<Processor>,
    pub max_body_bytes: i64,
    pub body_timeout: Duration,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    intercepted: Arc<AtomicI64>,
}

pub struct RunningServer {
    pub addr: String,
    intercepted: Arc<AtomicI64>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl RunningServer {
    pub fn intercept_count(&self) -> i64 {
        self.intercepted.load(Ordering::SeqCst)
    }
}

impl Server {
    pub fn new(listen_addr: String, allowed_hosts: Vec<String>, processor: Arc<Processor>, ca_cert_pem: String, ca_key_pem: String) -> Self {
        Self {
            listen_addr,
            allowed_hosts: normalize_hosts(&allowed_hosts),
            processor,
            max_body_bytes: 2 * 1024 * 1024,
            body_timeout: Duration::from_secs(3),
            ca_cert_pem,
            ca_key_pem,
            intercepted: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn start(&self) -> Result<RunningServer, KeyclawError> {
        let bind_addr = if self.listen_addr.trim().is_empty() {
            "127.0.0.1:8877".to_string()
        } else {
            self.listen_addr.clone()
        };

        let listener = match TcpListener::bind(&bind_addr) {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                let fallback = "127.0.0.1:0";
                log_line(format!(
                    "proxy listen address {bind_addr} is busy, falling back to {fallback}"
                ));
                TcpListener::bind(fallback).map_err(|fallback_err| {
                    KeyclawError::uncoded(format!(
                        "listen on {bind_addr} failed ({e}); fallback {fallback} failed ({fallback_err})"
                    ))
                })?
            }
            Err(e) => {
                return Err(KeyclawError::uncoded(format!(
                    "listen on {bind_addr} failed: {e}"
                )));
            }
        };
        let addr = listener
            .local_addr()
            .map_err(|e| KeyclawError::uncoded(format!("read local addr failed: {e}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| KeyclawError::uncoded(format!("set listener nonblocking failed: {e}")))?;

        let allowed_hosts = self.allowed_hosts.clone();
        let processor = Arc::clone(&self.processor);
        let intercepted = Arc::clone(&self.intercepted);
        let max_body_bytes = self.max_body_bytes;
        let body_timeout = self.body_timeout;

        let ca_cert_pem = self.ca_cert_pem.clone();
        let ca_key_pem = self.ca_key_pem.clone();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let ready_tx_err = ready_tx.clone();

        let join = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx_err.send(Err(format!("create tokio runtime failed: {e}")));
                    return;
                }
            };

            let result = runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .map_err(|e| format!("adopt listener failed: {e}"))?;

                let ca = build_ca_authority(&ca_cert_pem, &ca_key_pem).map_err(|e| e.to_string())?;

                let handler = KeyclawHttpHandler {
                    allowed_hosts,
                    processor,
                    max_body_bytes,
                    body_timeout,
                    intercepted,
                    request_had_secrets: false,
                };

                let shutdown = async move {
                    let _ = shutdown_rx.await;
                };

                let proxy = Proxy::builder()
                    .with_listener(listener)
                    .with_ca(ca)
                    .with_rustls_connector(aws_lc_rs::default_provider())
                    .with_http_handler(handler.clone())
                    .with_websocket_handler(handler)
                    .with_graceful_shutdown(shutdown)
                    .build()
                    .map_err(|e| format!("build proxy failed: {e}"))?;

                let _ = ready_tx.send(Ok(()));

                proxy
                    .start()
                    .await
                    .map_err(|e| format!("proxy exited with error: {e}"))
            });

            if let Err(err) = result {
                let _ = ready_tx_err.send(Err(err));
            }
        });

        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(RunningServer {
                addr: addr.to_string(),
                intercepted: Arc::clone(&self.intercepted),
                shutdown: Some(shutdown_tx),
                join: Some(join),
            }),
            Ok(Err(msg)) => Err(KeyclawError::uncoded(msg)),
            Err(_) => Err(KeyclawError::uncoded("proxy startup timeout")),
        }
    }
}

#[derive(Clone)]
struct KeyclawHttpHandler {
    allowed_hosts: Vec<String>,
    processor: Arc<Processor>,
    max_body_bytes: i64,
    body_timeout: Duration,
    intercepted: Arc<AtomicI64>,
    /// Set to true when handle_request replaced secrets in this request.
    /// Used by handle_response to decide whether to buffer streaming responses.
    request_had_secrets: bool,
}

impl HttpHandler for KeyclawHttpHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let host = match request_host(&req) {
            Some(host) => host,
            None => {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    CODE_INVALID_JSON,
                    "unable to determine target host",
                )
                .into();
            }
        };

        if !allowed(&self.allowed_hosts, &host) {
            // Pass through without rewriting — only inspect known API hosts
            return req.into();
        }
        self.intercepted.fetch_add(1, Ordering::SeqCst);
        log_line(format!("intercept {} {} (host={})", req.method(), req.uri().path(), host));

        if req.method() == Method::CONNECT {
            return req.into();
        }

        // WebSocket upgrade: strip compression extensions so the server
        // doesn't negotiate permessage-deflate (tungstenite can't handle RSV1 bits)
        if req.headers().get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        {
            let (mut parts, body) = req.into_parts();
            parts.headers.remove("sec-websocket-extensions");
            log_line("ws upgrade: stripped sec-websocket-extensions to disable compression".to_string());
            return Request::from_parts(parts, body).into();
        }

        let content_type = header_value(&req, CONTENT_TYPE.as_str()).unwrap_or_default();
        let content_type_is_json = is_json(&content_type);

        if self.max_body_bytes > 0 {
            if let Some(content_len) = header_value(&req, CONTENT_LENGTH.as_str())
                .and_then(|v| v.parse::<i64>().ok())
            {
                if content_len > self.max_body_bytes {
                    return json_error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        CODE_BODY_TOO_LARGE,
                        "request body exceeded maximum size",
                    )
                    .into();
                }
            }
        }

        let (parts, body) = req.into_parts();

        // Skip empty body requests (e.g. GET, OPTIONS, HEAD)
        let collected = match tokio::time::timeout(self.body_timeout, body.collect()).await {
            Ok(Ok(collected)) => collected,
            Ok(Err(_)) => {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    CODE_INVALID_JSON,
                    "cannot read request body",
                )
                .into();
            }
            Err(_) => {
                log_line("body read timeout — returning timeout error".to_string());
                return json_error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    CODE_REQUEST_TIMEOUT,
                    "request body read timed out",
                )
                .into();
            }
        };

        let body_bytes = collected.to_bytes();
        if self.max_body_bytes > 0 && (body_bytes.len() as i64) > self.max_body_bytes {
            return json_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                CODE_BODY_TOO_LARGE,
                "request body exceeded maximum size",
            )
            .into();
        }

        let original_payload = body_bytes.to_vec();

        if original_payload.is_empty() || (!content_type_is_json && !is_json_payload(&original_payload)) {
            return Request::from_parts(parts, body_from_vec(original_payload)).into();
        }

        let processor = Arc::clone(&self.processor);
        let payload = original_payload.clone();

        let rewritten = match tokio::time::timeout(
            self.body_timeout,
            tokio::task::spawn_blocking(move || processor.rewrite_and_evaluate(&payload)),
        )
        .await
        {
            Ok(Ok(Ok(result))) => result,
            Ok(Ok(Err(err))) => {
                let code = code_of(&err).unwrap_or("unknown");
                log_line(format!("rewrite error ({code}): {err} — passing through"));
                return Request::from_parts(parts, body_from_vec(original_payload)).into();
            }
            Ok(Err(err)) => {
                log_line(format!("request processing failed: {err} — passing through"));
                return Request::from_parts(parts, body_from_vec(original_payload)).into();
            }
            Err(_) => {
                log_line("rewrite timeout — passing request through".to_string());
                return Request::from_parts(parts, body_from_vec(original_payload)).into();
            }
        };

        self.request_had_secrets = !rewritten.replacements.is_empty();
        if self.request_had_secrets {
            log_line(format!(
                "request rewritten for host {host}: {}",
                self.processor.replacement_summary(&rewritten.replacements)
            ));
            log_replacements(&host, &original_payload, &rewritten.replacements);
        }

        let mut rewritten_req = Request::from_parts(parts, body_from_vec(rewritten.body.clone()));
        if let Ok(v) = rewritten.body.len().to_string().parse() {
            rewritten_req.headers_mut().insert(CONTENT_LENGTH, v);
        }
        if !rewritten.replacements.is_empty() {
            if let Ok(v) = crate::placeholder::CONTRACT_MARKER_VALUE.parse() {
                rewritten_req.headers_mut().insert("x-keyclaw-contract", v);
            }
        }

        // Always strip accept-encoding so the upstream sends uncompressed
        // responses.  The streaming resolver needs plain-text frames to detect
        // and replace placeholders that span multiple SSE events.
        rewritten_req.headers_mut().remove("accept-encoding");

        rewritten_req.into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        // SSE/streaming: pass through without buffering
        let is_streaming = res.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/event-stream") || ct.contains("stream"))
            .unwrap_or(false)
            || res.headers().get("transfer-encoding")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("chunked"))
                .unwrap_or(false);

        if res.status() == StatusCode::SWITCHING_PROTOCOLS || res.status().is_informational() {
            return res;
        }

        // SSE/streaming: wrap body to resolve placeholders per-chunk with carry-over
        // for placeholders that span frame boundaries.
        if is_streaming {
            let processor = Arc::clone(&self.processor);
            let (parts, body) = res.into_parts();
            let mut carry: Vec<u8> = Vec::new();
            let new_body = body.map_frame(move |frame| {
                match frame.into_data() {
                    Ok(data) => {
                        // Prepend any carry from previous frame
                        let combined = if carry.is_empty() {
                            data.to_vec()
                        } else {
                            let mut c = std::mem::take(&mut carry);
                            c.extend_from_slice(&data);
                            c
                        };

                        let text = String::from_utf8_lossy(&combined);

                        if text.contains("{{KEYCLAW_SECRET_") {
                            log_line(format!("stream chunk has placeholder, resolving..."));
                            match processor.resolve_text(&combined) {
                                Ok(resolved) => {
                                    let resolved_text = String::from_utf8_lossy(&resolved);
                                    // Check for partial placeholder at end that continues next frame
                                    if let Some(partial) = crate::placeholder::find_partial_placeholder_start(&resolved_text) {
                                        carry = resolved[partial..].to_vec();
                                        log_line("stream: carrying partial placeholder to next frame".to_string());
                                        return hudsucker::hyper::body::Frame::data(
                                            hudsucker::hyper::body::Bytes::from(resolved[..partial].to_vec())
                                        );
                                    }
                                    log_line("response: resolved placeholders in stream chunk".to_string());
                                    return hudsucker::hyper::body::Frame::data(
                                        hudsucker::hyper::body::Bytes::from(resolved)
                                    );
                                }
                                Err(e) => {
                                    log_line(format!("resolve_text error: {}", e));
                                }
                            }
                        } else if let Some(partial) = crate::placeholder::find_partial_placeholder_start(&text) {
                            // No complete marker but might have a partial one starting
                            carry = combined[partial..].to_vec();
                            return hudsucker::hyper::body::Frame::data(
                                hudsucker::hyper::body::Bytes::from(combined[..partial].to_vec())
                            );
                        }

                        hudsucker::hyper::body::Frame::data(
                            hudsucker::hyper::body::Bytes::from(combined)
                        )
                    }
                    Err(frame) => frame,
                }
            }).boxed();
            return Response::from_parts(parts, new_body.into());
        }

        // Non-streaming: collect, resolve placeholders, forward
        let (parts, body) = res.into_parts();
        let collected = match body.collect().await {
            Ok(c) => c,
            Err(_) => return Response::from_parts(parts, Body::empty()),
        };
        let mut body_bytes = collected.to_bytes().to_vec();

        let text = String::from_utf8_lossy(&body_bytes);
        if text.contains("{{KEYCLAW_SECRET_") {
            let processor = Arc::clone(&self.processor);
            let payload = body_bytes.clone();
            if let Ok(Ok(resolved)) = tokio::task::spawn_blocking(move || processor.resolve_text(&payload)).await {
                if resolved != body_bytes {
                    log_line("response: resolved placeholders back to secrets".to_string());
                    body_bytes = resolved;
                }
            }
        }

        let mut resp = Response::from_parts(parts, body_from_vec(body_bytes.clone()));
        if let Ok(v) = body_bytes.len().to_string().parse() {
            resp.headers_mut().insert(CONTENT_LENGTH, v);
        }
        resp
    }


    async fn should_intercept(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        request_host(req)
            .map(|host| allowed(&self.allowed_hosts, &host))
            .unwrap_or(false)
    }
}

impl WebSocketHandler for KeyclawHttpHandler {
    async fn handle_message(&mut self, ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        // Server -> Client: resolve any placeholders in responses
        if !matches!(ctx, WebSocketContext::ClientToServer { .. }) {
            match &msg {
                Message::Text(text) => {
                    let s = text.as_str();
                    if s.contains("{{KEYCLAW_SECRET_") {
                        if let Ok(resolved) = self.processor.resolve_text(s.as_bytes()) {
                            if let Ok(value) = String::from_utf8(resolved) {
                                log_line("ws response: resolved placeholders".to_string());
                                return Some(Message::Text(value.into()));
                            }
                        }
                    }
                }
                _ => {}
            }
            return Some(msg);
        }

        // Client -> Server: redact secrets in WS messages
        match &msg {
            Message::Text(text) => {
                let s = text.as_str();
                let processor = self.processor.clone();
                let payload = s.as_bytes().to_vec();
                match processor.rewrite_and_evaluate(&payload) {
                    Ok(result) if !result.replacements.is_empty() => {
                        log_line(format!(
                            "ws request: redacted {} secret(s)",
                            result.replacements.len()
                        ));
                        if let Ok(value) = String::from_utf8(result.body) {
                            return Some(Message::Text(value.into()));
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        Some(msg)
    }
}

fn build_ca_authority(cert_pem: &str, key_pem: &str) -> Result<RcgenAuthority, KeyclawError> {
    let key_pair = KeyPair::from_pem(key_pem)
        .map_err(|e| KeyclawError::uncoded(format!("parse CA private key failed: {e}")))?;
    let issuer = Issuer::from_ca_cert_pem(cert_pem, key_pair)
        .map_err(|e| KeyclawError::uncoded(format!("parse CA certificate failed: {e}")))?;

    Ok(RcgenAuthority::new(
        issuer,
        1_000,
        aws_lc_rs::default_provider(),
    ))
}

fn body_from_vec(bytes: Vec<u8>) -> Body {
    Full::new(hudsucker::hyper::body::Bytes::from(bytes)).into()
}

fn request_host(req: &Request<Body>) -> Option<String> {
    if let Some(authority) = req.uri().authority() {
        return Some(normalize_host(authority.as_str()));
    }

    header_value(req, HOST.as_str()).map(|v| normalize_host(&v))
}

fn header_value(req: &Request<Body>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

fn normalize_hosts(hosts: &[String]) -> Vec<String> {
    hosts
        .iter()
        .map(|h| normalize_host(h))
        .filter(|h| !h.is_empty())
        .collect()
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim().trim_matches('.').to_lowercase();
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return addr.ip().to_string();
    }

    if let Some((base, _)) = trimmed.rsplit_once(':') {
        if base.contains('.')
            || base.contains('[')
            || base == "localhost"
            || base.parse::<std::net::IpAddr>().is_ok()
        {
            return base.trim_matches('[').trim_matches(']').to_string();
        }
    }

    trimmed.trim_matches('[').trim_matches(']').to_string()
}

fn allowed(allowed_hosts: &[String], host: &str) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }
    let host = normalize_host(host);
    allowed_hosts
        .iter()
        .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
}

fn is_json(content_type: &str) -> bool {
    let c = content_type.trim().to_lowercase();
    c.is_empty() || c.contains("application/json") || c.contains("+json")
}

fn is_json_payload(payload: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(payload).is_ok()
}

fn json_error_response(status: StatusCode, code: &str, msg: &str) -> Response<Body> {
    let payload = serde_json::json!({"error": {"code": code, "message": msg}});
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());

    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(body_from_vec(body))
        .expect("failed to build proxy error response")
}

fn log_replacements(host: &str, original: &[u8], replacements: &[crate::placeholder::Replacement]) {
    if !unsafe_log_enabled() || replacements.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(original);
    eprintln!("keyclaw [UNSAFE] INTERCEPTIONS for {host} ({} found):", replacements.len());
    for r in replacements {
        if let Some(pos) = text.find(&r.secret) {
            let ctx_start = if pos > 100 { pos - 100 } else { 0 };
            let secret_end = pos + r.secret.len();
            let before = truncate_utf8(&text[ctx_start..pos], 100);
            let after_end = std::cmp::min(secret_end + 100, text.len());
            let after = truncate_utf8(&text[secret_end..after_end], 100);
            eprintln!(
                "  ...{}[SECRET:{} -> {}]{}...",
                before,
                &r.secret[..std::cmp::min(8, r.secret.len())],
                r.placeholder,
                after
            );
        } else {
            eprintln!("  {} -> {}", &r.secret[..std::cmp::min(8, r.secret.len())], r.placeholder);
        }
    }
    eprintln!("---");
}

fn log_line(line: String) {
    eprintln!("keyclaw: {}", logscrub::scrub(&line));
}
