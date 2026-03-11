use std::sync::Arc;
use std::sync::atomic::Ordering;

use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse,
    hyper::{
        Method, Request, Response, StatusCode,
        header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, TRANSFER_ENCODING},
    },
};

use crate::errors::{
    CODE_BODY_TOO_LARGE, CODE_HOOK_BLOCKED, CODE_INVALID_JSON, CODE_REQUEST_TIMEOUT, code_of,
};

use super::KeyclawHttpHandler;
use super::common::{
    allowed, body_from_vec, header_value, is_json, is_json_payload, json_error_response, log_debug,
    log_replacements, log_warn, request_host, response_is_sse,
};
use super::streaming::SseStreamResolver;

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
            return req.into();
        }
        self.intercepted.fetch_add(1, Ordering::SeqCst);
        log_debug(format!(
            "intercept {} {} (host={})",
            req.method(),
            req.uri().path(),
            host
        ));

        if req.method() == Method::CONNECT {
            return req.into();
        }

        if req
            .headers()
            .get("upgrade")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
        {
            let (mut parts, body) = req.into_parts();
            parts.headers.remove("sec-websocket-extensions");
            log_debug(
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
                log_warn(format!(
                    "body read timeout after {} ms for host {host}; raise KEYCLAW_DETECTOR_TIMEOUT if large requests are expected",
                    self.body_timeout.as_millis()
                ));
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
                log_warn(format!("rewrite error ({code}): {err}"));
                if self.processor.strict_mode || code == CODE_HOOK_BLOCKED {
                    return request_rewrite_error_response(&err).into();
                }
                return Request::from_parts(parts, body_from_vec(original_payload)).into();
            }
            Ok(Err(err)) => {
                log_warn(format!("request processing failed: {err}"));
                if self.processor.strict_mode {
                    return json_error_response(
                        StatusCode::BAD_GATEWAY,
                        "rewrite_failed",
                        "request processing failed before forwarding upstream",
                    )
                    .into();
                }
                return Request::from_parts(parts, body_from_vec(original_payload)).into();
            }
            Err(_) => {
                log_warn(rewrite_timeout_message(
                    &host,
                    original_payload.len(),
                    self.body_timeout,
                ));
                if self.processor.strict_mode {
                    return json_error_response(
                        StatusCode::REQUEST_TIMEOUT,
                        CODE_REQUEST_TIMEOUT,
                        "request rewrite timed out",
                    )
                    .into();
                }
                return Request::from_parts(parts, body_from_vec(original_payload)).into();
            }
        };

        let request_had_secrets = !rewritten.replacements.is_empty();
        if request_had_secrets {
            if let Err(err) = self
                .processor
                .run_secret_detected_hooks(&host, &rewritten.replacements)
            {
                return request_rewrite_error_response(&err).into();
            }
            if !self.processor.dry_run {
                if let Err(err) = self
                    .processor
                    .run_request_redacted_hooks(&host, &rewritten.replacements)
                {
                    return request_rewrite_error_response(&err).into();
                }
            }
            log_debug(format!(
                "request rewritten for host {host}: {}",
                self.processor.replacement_summary(&rewritten.replacements)
            ));
            log_replacements(&host, &original_payload, &rewritten.replacements);
            if !self.processor.dry_run {
                if let Err(err) = crate::audit::append_redactions(
                    self.audit_log_path.as_deref(),
                    &host,
                    &rewritten.replacements,
                ) {
                    log_warn(format!("audit log write failed: {err}"));
                }
            }
        }

        let rewritten_len = rewritten.body.len();
        let mut rewritten_req = Request::from_parts(parts, body_from_vec(rewritten.body));
        set_fixed_body_headers(rewritten_req.headers_mut(), rewritten_len);
        if !self.processor.dry_run && !rewritten.replacements.is_empty() {
            if let Ok(value) = crate::placeholder::CONTRACT_MARKER_VALUE.parse() {
                rewritten_req
                    .headers_mut()
                    .insert(crate::placeholder::CONTRACT_MARKER_KEY, value);
            }
        }
        rewritten_req.headers_mut().remove("accept-encoding");

        rewritten_req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let is_sse = response_is_sse(&res);

        if res.status() == StatusCode::SWITCHING_PROTOCOLS || res.status().is_informational() {
            return res;
        }

        if is_sse {
            let processor = Arc::clone(&self.processor);
            let (mut parts, body) = res.into_parts();
            let mut sse_resolver = SseStreamResolver::new(processor);
            parts.headers.remove(CONTENT_LENGTH);
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

        let (mut parts, body) = res.into_parts();
        let collected = match body.collect().await {
            Ok(collected) => collected,
            Err(_) => return Response::from_parts(parts, Body::empty()),
        };
        let mut body_bytes = collected.to_bytes().to_vec();

        let text = String::from_utf8_lossy(&body_bytes);
        if crate::placeholder::contains_placeholder_prefix(&text) {
            let processor = Arc::clone(&self.processor);
            let payload = body_bytes.clone();
            if let Ok(Ok(resolved)) =
                tokio::task::spawn_blocking(move || processor.resolve_text(&payload)).await
            {
                if resolved != body_bytes {
                    log_debug("response: resolved placeholders back to secrets".to_string());
                    body_bytes = resolved;
                }
            }
        }

        parts.headers.remove(TRANSFER_ENCODING);
        let body_len = body_bytes.len();
        let mut resp = Response::from_parts(parts, body_from_vec(body_bytes));
        set_fixed_body_headers(resp.headers_mut(), body_len);
        resp
    }

    async fn should_intercept(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        request_host(req)
            .map(|host| allowed(&self.allowed_hosts, &host))
            .unwrap_or(false)
    }
}

fn request_rewrite_error_response(err: &crate::errors::KeyclawError) -> Response<Body> {
    let code = code_of(err).unwrap_or("rewrite_failed");
    let message = err.display_without_code();

    let status = match code {
        CODE_BODY_TOO_LARGE => StatusCode::PAYLOAD_TOO_LARGE,
        CODE_REQUEST_TIMEOUT => StatusCode::REQUEST_TIMEOUT,
        CODE_HOOK_BLOCKED => StatusCode::FORBIDDEN,
        CODE_INVALID_JSON => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_GATEWAY,
    };

    json_error_response(status, code, &message)
}

fn set_fixed_body_headers(headers: &mut HeaderMap, len: usize) {
    headers.remove(TRANSFER_ENCODING);
    if let Ok(value) = len.to_string().parse() {
        headers.insert(CONTENT_LENGTH, value);
    }
}

fn rewrite_timeout_message(host: &str, body_len: usize, timeout: std::time::Duration) -> String {
    format!(
        "rewrite timeout after {}s for host {host} on {body_len}-byte JSON body; increase KEYCLAW_DETECTOR_TIMEOUT if this payload shape is expected",
        timeout.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hudsucker::hyper::header::{CONTENT_LENGTH, HeaderMap, HeaderValue, TRANSFER_ENCODING};

    use super::{rewrite_timeout_message, set_fixed_body_headers};

    #[test]
    fn set_fixed_body_headers_removes_transfer_encoding_and_sets_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));

        set_fixed_body_headers(&mut headers, 42);

        assert!(!headers.contains_key(TRANSFER_ENCODING));
        assert_eq!(
            headers
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("42")
        );
    }

    #[test]
    fn rewrite_timeout_message_mentions_host_body_size_and_knob() {
        let message =
            rewrite_timeout_message("api.anthropic.com", 1_048_576, Duration::from_secs(20));

        assert!(message.contains("api.anthropic.com"), "message={message}");
        assert!(message.contains("1048576-byte"), "message={message}");
        assert!(message.contains("20s"), "message={message}");
        assert!(
            message.contains("KEYCLAW_DETECTOR_TIMEOUT"),
            "message={message}"
        );
    }
}
