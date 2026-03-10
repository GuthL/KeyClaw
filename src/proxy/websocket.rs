use futures::{SinkExt, Stream, StreamExt};
use hudsucker::{
    WebSocketContext, WebSocketHandler,
    tokio_tungstenite::tungstenite::{self, Message},
};

use crate::errors::{CODE_INVALID_JSON, KeyclawError, code_of};

use super::KeyclawHttpHandler;
use super::common::{log_debug, log_warn, normalize_host_value};

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

enum WsRequestRewrite {
    Unchanged,
    Rewritten(String, Vec<crate::placeholder::Replacement>),
    Blocked(KeyclawError),
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
                    let should_close = matches!(message, Message::Close(_));

                    match sink.send(message).await {
                        Err(tungstenite::Error::ConnectionClosed) => {}
                        Err(err) => log_warn(format!("ws send error: {err}")),
                        Ok(()) => {}
                    }
                    if should_close {
                        break;
                    }
                }
                Err(err) => {
                    if !is_expected_websocket_close_error(&err) {
                        log_warn(format!("ws message error: {err}"));
                        match sink.send(Message::Close(None)).await {
                            Err(tungstenite::Error::ConnectionClosed) => {}
                            Err(close_err) => {
                                log_warn(format!("ws close error: {close_err}"));
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
        if !matches!(ctx, WebSocketContext::ClientToServer { .. }) {
            if let Message::Text(text) = &msg {
                if let Some(value) = self.resolve_ws_response_text(text.as_str()) {
                    log_debug("ws response: resolved placeholders".to_string());
                    return Some(Message::Text(value.into()));
                }
            }
            return Some(msg);
        }

        if let Message::Text(text) = &msg {
            match self.rewrite_ws_request_text(text.as_str(), uses_input_only_ws_rewrite(ctx)) {
                WsRequestRewrite::Rewritten(value, replacements) => {
                    if let Some(host) = websocket_request_host(ctx) {
                        if !self.processor.dry_run {
                            if let Err(err) = crate::audit::append_redactions(
                                self.audit_log_path.as_deref(),
                                &host,
                                &replacements,
                            ) {
                                log_warn(format!("audit log write failed: {err}"));
                            }
                        }
                    }
                    log_debug(format!(
                        "ws request: redacted {} secret(s)",
                        replacements.len()
                    ));
                    return Some(Message::Text(value.into()));
                }
                WsRequestRewrite::Blocked(err) => {
                    let code = code_of(&err).unwrap_or("unknown");
                    log_warn(format!("ws rewrite error ({code}): {err}"));
                    return Some(Message::Close(None));
                }
                WsRequestRewrite::Unchanged => {}
            }
        }
        Some(msg)
    }
}

impl KeyclawHttpHandler {
    fn rewrite_ws_request_text(&self, text: &str, input_only: bool) -> WsRequestRewrite {
        let payload = text.as_bytes().to_vec();
        let rewrite = if input_only {
            self.processor.rewrite_and_evaluate_codex_ws(&payload)
        } else {
            self.processor.rewrite_and_evaluate(&payload)
        };
        match rewrite {
            Ok(result) if result.replacements.is_empty() => WsRequestRewrite::Unchanged,
            Ok(result) => match String::from_utf8(result.body) {
                Ok(value) => WsRequestRewrite::Rewritten(value, result.replacements),
                Err(err) => self.ws_rewrite_failure(KeyclawError::coded_with_source(
                    CODE_INVALID_JSON,
                    "rewrite produced non-utf8 websocket payload",
                    err,
                )),
            },
            Err(err) => self.ws_rewrite_failure(err),
        }
    }

    fn ws_rewrite_failure(&self, err: KeyclawError) -> WsRequestRewrite {
        if self.processor.strict_mode {
            WsRequestRewrite::Blocked(err)
        } else {
            let code = code_of(&err).unwrap_or("unknown");
            log_warn(format!("ws rewrite error ({code}): {err}"));
            WsRequestRewrite::Unchanged
        }
    }

    fn resolve_ws_response_text(&self, text: &str) -> Option<String> {
        if !crate::placeholder::contains_placeholder_prefix(text) {
            return None;
        }

        self.processor
            .resolve_text(text.as_bytes())
            .ok()
            .and_then(|resolved| String::from_utf8(resolved).ok())
    }
}

fn websocket_request_host(ctx: &WebSocketContext) -> Option<String> {
    match ctx {
        WebSocketContext::ClientToServer { dst, .. } => dst
            .authority()
            .map(|authority| normalize_host_value(authority.as_str())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicI64;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use hudsucker::tokio_tungstenite::tungstenite::{self, error::ProtocolError};

    use super::super::KeyclawHttpHandler;
    use super::{
        WsRequestRewrite, is_expected_websocket_close_error, uses_input_only_ws_rewrite_path,
    };
    use crate::errors::{CODE_INVALID_JSON, code_of};
    use crate::gitleaks_rules::RuleSet;
    use crate::pipeline::Processor;
    use crate::placeholder;
    use crate::vault::Store;

    fn empty_ruleset() -> Arc<RuleSet> {
        Arc::new(RuleSet::from_toml("rules = []").expect("empty ruleset"))
    }

    fn sample_secret_ruleset() -> Arc<RuleSet> {
        let mut rules = RuleSet::from_toml(
            r#"
[[rules]]
id = "generic-api-key"
regex = 'api_key = ([A-Za-z0-9]{30,})'
secretGroup = 1
entropy = 1
keywords = ["api_key"]
"#,
        )
        .expect("sample ruleset");
        rules.entropy_config.enabled = false;
        Arc::new(rules)
    }

    fn test_handler(strict_mode: bool, ruleset: Arc<RuleSet>) -> KeyclawHttpHandler {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let vault = Arc::new(Store::new(
            std::env::temp_dir().join(format!("keyclaw-ws-{unique}.enc")),
            "test-passphrase".to_string(),
        ));
        let processor = Arc::new(Processor {
            vault: Some(vault),
            ruleset,
            second_pass_scanner: None,
            max_body_size: 1 << 20,
            strict_mode,
            notice_mode: crate::redaction::NoticeMode::Verbose,
            dry_run: false,
        });

        KeyclawHttpHandler {
            allowed_hosts: vec!["api.openai.com".to_string()],
            processor,
            max_body_bytes: 1 << 20,
            body_timeout: Duration::from_secs(1),
            audit_log_path: None,
            intercepted: Arc::new(AtomicI64::new(0)),
        }
    }

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

    #[test]
    fn ws_request_text_messages_are_redacted() {
        let handler = test_handler(true, sample_secret_ruleset());
        let secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
        let rewrite = handler.rewrite_ws_request_text(
            &format!(r#"{{"messages":[{{"content":"api_key = {}"}}]}}"#, secret),
            false,
        );
        let WsRequestRewrite::Rewritten(text, _) = rewrite else {
            panic!("expected rewritten websocket message");
        };

        assert!(!text.contains(secret), "text={text}");
        assert!(
            placeholder::contains_complete_placeholder(&text),
            "text={text}"
        );
    }

    #[test]
    fn ws_request_rewrite_errors_block_in_strict_mode() {
        let handler = test_handler(true, empty_ruleset());

        let rewrite = handler.rewrite_ws_request_text(r#"{"messages":[{"content":"oops"}"#, false);

        let WsRequestRewrite::Blocked(err) = rewrite else {
            panic!("strict mode should block malformed websocket payloads");
        };
        assert_eq!(code_of(&err), Some(CODE_INVALID_JSON));
    }

    #[test]
    fn ws_request_rewrite_errors_pass_through_when_fail_closed_disabled() {
        let handler = test_handler(false, empty_ruleset());

        let rewrite = handler.rewrite_ws_request_text(r#"{"messages":[{"content":"oops"}"#, false);

        assert!(
            matches!(rewrite, WsRequestRewrite::Unchanged),
            "non-strict mode should preserve pass-through behavior"
        );
    }

    #[test]
    fn ws_response_text_messages_are_resolved() {
        let temp = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(Store::new(
            temp.path().join("vault.enc"),
            "test-passphrase".to_string(),
        ));
        let processor = Arc::new(Processor {
            vault: Some(Arc::clone(&vault)),
            ruleset: empty_ruleset(),
            second_pass_scanner: None,
            max_body_size: 1 << 20,
            strict_mode: true,
            notice_mode: crate::redaction::NoticeMode::Verbose,
            dry_run: false,
        });
        let handler = KeyclawHttpHandler {
            allowed_hosts: vec!["api.openai.com".to_string()],
            processor,
            max_body_bytes: 1 << 20,
            body_timeout: Duration::from_secs(1),
            audit_log_path: None,
            intercepted: Arc::new(AtomicI64::new(0)),
        };
        let request_secret = "api_key = aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
        let id = vault.store_secret(request_secret).expect("store secret");
        let placeholder = placeholder::make(&id);
        let text = handler
            .resolve_ws_response_text(&format!(r#"{{"content":"{}"}}"#, placeholder))
            .expect("resolved message");

        assert!(text.contains(request_secret), "text={text}");
        assert!(!text.contains(&placeholder), "text={text}");
    }
}
