use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use futures::{SinkExt, Stream, StreamExt};
use http_body_util::{BodyExt, Full};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{
        header::{CONTENT_LENGTH, CONTENT_TYPE, HOST},
        Method, Request, Response, StatusCode,
    },
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
    tokio_tungstenite::tungstenite::{self, Message},
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use serde_json::Value;

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

static LOG_FILE: std::sync::Mutex<Option<File>> = std::sync::Mutex::new(None);

pub fn set_log_file(path: &std::path::Path) -> std::io::Result<()> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    if let Ok(mut guard) = LOG_FILE.lock() {
        *guard = Some(file);
    }
    Ok(())
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

#[derive(Clone)]
struct BufferedInputJsonDeltaEvent {
    other_lines: Vec<String>,
    payload: Value,
    fragment: String,
}

impl BufferedInputJsonDeltaEvent {
    fn parse(event: &str) -> Option<Self> {
        let mut other_lines = Vec::new();
        let mut data_lines = Vec::new();

        for line in event.lines() {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if let Some(rest) = line.strip_prefix("data: ") {
                data_lines.push(rest.to_string());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.to_string());
            } else if !line.is_empty() {
                other_lines.push(line.to_string());
            }
        }

        if data_lines.is_empty() {
            return None;
        }

        let payload_text = data_lines.join("\n");
        let payload: Value = serde_json::from_str(&payload_text).ok()?;
        let delta = payload.get("delta")?;
        if delta.get("type")?.as_str()? != "input_json_delta" {
            return None;
        }

        Some(Self {
            other_lines,
            fragment: delta.get("partial_json")?.as_str()?.to_string(),
            payload,
        })
    }

    fn budget(&self) -> usize {
        self.fragment.len()
    }

    fn with_fragment(mut self, fragment: String) -> Self {
        self.fragment = fragment;
        self
    }

    fn render_with_fragment(&self, fragment: &str) -> Vec<u8> {
        let mut payload = self.payload.clone();
        if let Some(delta) = payload.get_mut("delta").and_then(Value::as_object_mut) {
            delta.insert(
                "partial_json".to_string(),
                Value::String(fragment.to_string()),
            );
        }

        let mut out = String::new();
        for line in &self.other_lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("data: ");
        out.push_str(&payload.to_string());
        out.push_str("\n\n");
        out.into_bytes()
    }
}

struct SseStreamResolver {
    processor: Arc<Processor>,
    frame_carry: Vec<u8>,
    pending_events: Vec<BufferedInputJsonDeltaEvent>,
    pending_text: String,
}

impl SseStreamResolver {
    fn new(processor: Arc<Processor>) -> Self {
        Self {
            processor,
            frame_carry: Vec::new(),
            pending_events: Vec::new(),
            pending_text: String::new(),
        }
    }

    fn process_frame(&mut self, data: &[u8]) -> Vec<u8> {
        self.frame_carry.extend_from_slice(data);
        let mut out = Vec::new();

        for event in drain_complete_sse_events(&mut self.frame_carry) {
            let event_text = String::from_utf8_lossy(&event).into_owned();
            if let Some(parsed) = BufferedInputJsonDeltaEvent::parse(&event_text) {
                self.pending_text.push_str(&parsed.fragment);
                self.pending_events.push(parsed);
                self.flush_pending(&mut out, false);
            } else {
                self.flush_pending(&mut out, true);
                out.extend_from_slice(&event);
            }
        }

        out
    }

    fn flush_pending(&mut self, out: &mut Vec<u8>, force: bool) {
        if self.pending_events.is_empty() {
            return;
        }

        let (resolved_ready, unresolved_tail) = self.resolve_pending_text(force);
        let keep_last_buffered = !force && !unresolved_tail.is_empty();
        if keep_last_buffered && self.pending_events.len() == 1 {
            let deferred = format!("{resolved_ready}{unresolved_tail}");
            self.pending_text = deferred.clone();
            if let Some(last) = self.pending_events.last_mut() {
                *last = last.clone().with_fragment(deferred);
            }
            return;
        }

        let emit_count = if keep_last_buffered {
            self.pending_events.len().saturating_sub(1)
        } else {
            self.pending_events.len()
        };

        let mut remaining = resolved_ready;
        let mut drained = std::mem::take(&mut self.pending_events);
        let deferred_event = if keep_last_buffered {
            drained.pop()
        } else {
            None
        };
        let last_emitted = emit_count.saturating_sub(1);

        for (idx, event) in drained.into_iter().enumerate() {
            let fragment = if idx == last_emitted && !keep_last_buffered {
                std::mem::take(&mut remaining)
            } else {
                take_prefix(&mut remaining, event.budget())
            };
            out.extend(event.render_with_fragment(&fragment));
        }

        if let Some(event) = deferred_event {
            let deferred = format!("{remaining}{unresolved_tail}");
            self.pending_text = deferred.clone();
            self.pending_events.push(event.with_fragment(deferred));
        } else {
            self.pending_text.clear();
        }
    }

    fn resolve_pending_text(&self, force: bool) -> (String, String) {
        let resolved = match self.processor.resolve_text(self.pending_text.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(err) => {
                log_line(format!("sse resolve_text error: {err}"));
                self.pending_text.clone()
            }
        };

        if force {
            return (resolved, String::new());
        }

        if let Some(partial_start) = crate::placeholder::find_partial_placeholder_start(&resolved) {
            (
                resolved[..partial_start].to_string(),
                resolved[partial_start..].to_string(),
            )
        } else {
            (resolved, String::new())
        }
    }
}

fn take_prefix(text: &mut String, max_bytes: usize) -> String {
    if text.is_empty() || max_bytes == 0 {
        return String::new();
    }

    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let remainder = text.split_off(end);
    std::mem::replace(text, remainder)
}

fn drain_complete_sse_events(buffer: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut events = Vec::new();
    let mut start = 0usize;
    let mut idx = 0usize;

    while idx < buffer.len() {
        let delimiter_len =
            if idx + 1 < buffer.len() && buffer[idx] == b'\n' && buffer[idx + 1] == b'\n' {
                Some(2)
            } else if idx + 3 < buffer.len()
                && buffer[idx] == b'\r'
                && buffer[idx + 1] == b'\n'
                && buffer[idx + 2] == b'\r'
                && buffer[idx + 3] == b'\n'
            {
                Some(4)
            } else {
                None
            };

        if let Some(len) = delimiter_len {
            let end = idx + len;
            events.push(buffer[start..end].to_vec());
            start = end;
            idx = end;
        } else {
            idx += 1;
        }
    }

    if start > 0 {
        buffer.drain(..start);
    }

    events
}

fn is_expected_websocket_close_error(err: &tungstenite::Error) -> bool {
    match err {
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => true,
        tungstenite::Error::Protocol(
            tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
        ) => true,
        tungstenite::Error::Io(io_err) => {
            io_err.kind() == std::io::ErrorKind::UnexpectedEof
                && io_err.to_string().contains("close_notify")
        }
        _ => false,
    }
}

fn uses_input_only_ws_rewrite_path(path: &str) -> bool {
    path.starts_with("/backend-api/codex/responses")
}

fn uses_input_only_ws_rewrite(ctx: &WebSocketContext) -> bool {
    matches!(
        ctx,
        WebSocketContext::ClientToServer { dst, .. }
            if uses_input_only_ws_rewrite_path(dst.path())
    )
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
    pub fn new(
        listen_addr: String,
        allowed_hosts: Vec<String>,
        processor: Arc<Processor>,
        ca_cert_pem: String,
        ca_key_pem: String,
    ) -> Self {
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

                let ca =
                    build_ca_authority(&ca_cert_pem, &ca_key_pem).map_err(|e| e.to_string())?;

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
        log_line(format!(
            "intercept {} {} (host={})",
            req.method(),
            req.uri().path(),
            host
        ));

        if req.method() == Method::CONNECT {
            return req.into();
        }

        // WebSocket upgrade: strip compression extensions so the server
        // doesn't negotiate permessage-deflate (tungstenite can't handle RSV1 bits)
        if req
            .headers()
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        {
            let (mut parts, body) = req.into_parts();
            parts.headers.remove("sec-websocket-extensions");
            log_line(
                "ws upgrade: stripped sec-websocket-extensions to disable compression".to_string(),
            );
            return Request::from_parts(parts, body).into();
        }

        let content_type = header_value(&req, CONTENT_TYPE.as_str()).unwrap_or_default();
        let content_type_is_json = is_json(&content_type);

        if self.max_body_bytes > 0 {
            if let Some(content_len) =
                header_value(&req, CONTENT_LENGTH.as_str()).and_then(|v| v.parse::<i64>().ok())
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

        if original_payload.is_empty()
            || (!content_type_is_json && !is_json_payload(&original_payload))
        {
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
                log_line(format!(
                    "request processing failed: {err} — passing through"
                ));
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

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        // SSE/streaming: pass through without buffering
        let is_streaming = res
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("text/event-stream") || ct.contains("stream"))
            .unwrap_or(false)
            || res
                .headers()
                .get("transfer-encoding")
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
            let mut sse_resolver = SseStreamResolver::new(processor);
            let new_body = body
                .map_frame(move |frame| match frame.into_data() {
                    Ok(data) => {
                        let rewritten = sse_resolver.process_frame(&data);
                        hudsucker::hyper::body::Frame::data(hudsucker::hyper::body::Bytes::from(
                            rewritten,
                        ))
                    }
                    Err(frame) => frame,
                })
                .boxed();
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
            if let Ok(Ok(resolved)) =
                tokio::task::spawn_blocking(move || processor.resolve_text(&payload)).await
            {
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
    async fn handle_websocket(
        mut self,
        ctx: WebSocketContext,
        mut stream: impl Stream<Item = Result<Message, tungstenite::Error>> + Unpin + Send + 'static,
        mut sink: impl futures::Sink<Message, Error = tungstenite::Error> + Unpin + Send + 'static,
    ) {
        while let Some(message) = stream.next().await {
            match message {
                Ok(message) => {
                    let Some(message) = self.handle_message(&ctx, message).await else {
                        continue;
                    };

                    match sink.send(message).await {
                        Err(tungstenite::Error::ConnectionClosed) => {}
                        Err(err) => log_line(format!("ws send error: {err}")),
                        Ok(()) => {}
                    }
                }
                Err(err) => {
                    if !is_expected_websocket_close_error(&err) {
                        log_line(format!("ws message error: {err}"));
                        match sink.send(Message::Close(None)).await {
                            Err(tungstenite::Error::ConnectionClosed) => {}
                            Err(close_err) => {
                                log_line(format!("ws close error: {close_err}"));
                            }
                            Ok(()) => {}
                        }
                    }

                    break;
                }
            }
        }
    }

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
                let rewrite = if uses_input_only_ws_rewrite(ctx) {
                    processor.rewrite_and_evaluate_codex_ws(&payload)
                } else {
                    processor.rewrite_and_evaluate(&payload)
                };
                match rewrite {
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
    let use_file = LOG_FILE.lock().ok().as_ref().map_or(false, |g| g.is_some());
    macro_rules! log_out {
        ($($arg:tt)*) => {
            if use_file {
                if let Ok(mut guard) = LOG_FILE.lock() {
                    if let Some(ref mut f) = *guard {
                        let _ = writeln!(f, $($arg)*);
                    }
                }
            } else {
                eprintln!($($arg)*);
            }
        }
    }
    let text = String::from_utf8_lossy(original);
    log_out!(
        "keyclaw [UNSAFE] INTERCEPTIONS for {host} ({} found):",
        replacements.len()
    );
    for r in replacements {
        if let Some(pos) = text.find(&r.secret) {
            let ctx_start = if pos > 100 { pos - 100 } else { 0 };
            let secret_end = pos + r.secret.len();
            let before = truncate_utf8(&text[ctx_start..pos], 100);
            let after_end = std::cmp::min(secret_end + 100, text.len());
            let after = truncate_utf8(&text[secret_end..after_end], 100);
            log_out!(
                "  ...{}[SECRET:{} -> {}]{}...",
                before,
                &r.secret[..std::cmp::min(8, r.secret.len())],
                r.placeholder,
                after
            );
        } else {
            log_out!(
                "  {} -> {}",
                &r.secret[..std::cmp::min(8, r.secret.len())],
                r.placeholder
            );
        }
    }
    log_out!("---");
}

fn log_line(line: String) {
    let msg = format!("keyclaw: {}", logscrub::scrub(&line));
    if let Ok(mut guard) = LOG_FILE.lock() {
        if let Some(ref mut f) = *guard {
            let _ = writeln!(f, "{}", msg);
            return;
        }
    }
    eprintln!("{}", msg);
}

#[cfg(test)]
mod tests {
    use super::{is_expected_websocket_close_error, uses_input_only_ws_rewrite_path};
    use hudsucker::tokio_tungstenite::tungstenite::{self, error::ProtocolError};

    #[test]
    fn tls_unexpected_eof_is_treated_as_expected_ws_close() {
        let err = tungstenite::Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer closed connection without sending TLS close_notify",
        ));

        assert!(is_expected_websocket_close_error(&err));
    }

    #[test]
    fn reset_without_closing_handshake_is_treated_as_expected_ws_close() {
        let err = tungstenite::Error::Protocol(ProtocolError::ResetWithoutClosingHandshake);

        assert!(is_expected_websocket_close_error(&err));
    }

    #[test]
    fn unrelated_io_errors_are_not_treated_as_expected_ws_close() {
        let err = tungstenite::Error::Io(std::io::Error::other("socket exploded"));

        assert!(!is_expected_websocket_close_error(&err));
    }

    #[test]
    fn codex_responses_ws_uses_input_only_scope() {
        assert!(uses_input_only_ws_rewrite_path(
            "/backend-api/codex/responses"
        ));
    }

    #[test]
    fn non_codex_ws_keeps_full_scope() {
        assert!(!uses_input_only_ws_rewrite_path("/backend-api/other"));
    }
}
