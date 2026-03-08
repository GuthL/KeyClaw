use std::sync::Arc;

use serde_json::Value;

use crate::pipeline::Processor;

use super::common::log_warn;

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

pub(super) struct SseStreamResolver {
    processor: Arc<Processor>,
    frame_carry: Vec<u8>,
    pending_events: Vec<BufferedInputJsonDeltaEvent>,
    pending_text: String,
}

impl SseStreamResolver {
    pub(super) fn new(processor: Arc<Processor>) -> Self {
        Self {
            processor,
            frame_carry: Vec::new(),
            pending_events: Vec::new(),
            pending_text: String::new(),
        }
    }

    pub(super) fn process_frame(&mut self, data: &[u8]) -> Vec<u8> {
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
                log_warn(format!("sse resolve_text error: {err}"));
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{drain_complete_sse_events, BufferedInputJsonDeltaEvent, SseStreamResolver};
    use crate::gitleaks_rules::RuleSet;
    use crate::pipeline::Processor;
    use crate::placeholder;
    use crate::vault::Store;

    #[test]
    fn buffered_input_json_delta_event_parses_fragment_and_metadata_lines() {
        let event = format!(
            "event: content_block_delta\nid: 7\ndata: {}\n\n",
            serde_json::json!({
                "type": "content_block_delta",
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": "{\"alpha\":\"beta"
                }
            })
        );

        let parsed = BufferedInputJsonDeltaEvent::parse(&event).expect("parse input_json_delta");

        assert_eq!(
            parsed.other_lines,
            vec![
                "event: content_block_delta".to_string(),
                "id: 7".to_string()
            ]
        );
        assert_eq!(parsed.fragment, "{\"alpha\":\"beta");
    }

    #[test]
    fn drain_complete_sse_events_leaves_partial_tail_buffered() {
        let mut buffer = format!(
            "{}event: ping\ndata: [DONE]\n\ndata: partial",
            input_json_delta_event("prefix")
        )
        .into_bytes();

        let events = drain_complete_sse_events(&mut buffer);

        assert_eq!(events.len(), 2);
        assert_eq!(
            String::from_utf8(events[1].clone()).expect("utf8"),
            "event: ping\ndata: [DONE]\n\n"
        );
        assert_eq!(buffer, b"data: partial");
    }

    #[test]
    fn sse_resolver_passes_through_non_json_events() {
        let mut resolver = SseStreamResolver::new(test_processor());
        let event = b"event: ping\ndata: [DONE]\n\n";

        assert_eq!(resolver.process_frame(event), event);
    }

    #[test]
    fn sse_resolver_resolves_split_placeholder_without_breaking_utf8_boundaries() {
        let temp = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(Store::new(
            temp.path().join("vault.enc"),
            "test-passphrase".to_string(),
        ));
        let secret = "é漢";
        let id = vault.store_secret(secret).expect("store secret");
        let placeholder = placeholder::make(&id);
        let mut resolver = SseStreamResolver::new(test_processor_with_vault(Arc::clone(&vault)));

        let out1 = resolver.process_frame(input_json_delta_event(&placeholder[..1]).as_bytes());
        let out2 = resolver.process_frame(input_json_delta_event(&placeholder[1..4]).as_bytes());
        let out3 = resolver.process_frame(input_json_delta_event(&placeholder[4..]).as_bytes());

        assert!(out1.is_empty());
        assert_eq!(output_fragments(&out2), vec!["".to_string()]);

        let fragments = [output_fragments(&out2), output_fragments(&out3)].concat();
        assert_eq!(
            fragments,
            vec!["".to_string(), "é".to_string(), "漢".to_string()]
        );
        assert_eq!(fragments.concat(), secret);
        assert!(!String::from_utf8(out2)
            .expect("utf8")
            .contains(&placeholder));
        assert!(!String::from_utf8(out3)
            .expect("utf8")
            .contains(&placeholder));
    }

    fn input_json_delta_event(fragment: &str) -> String {
        format!(
            "event: content_block_delta\ndata: {}\n\n",
            serde_json::json!({
                "type": "content_block_delta",
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": fragment,
                }
            })
        )
    }

    fn output_fragments(output: &[u8]) -> Vec<String> {
        String::from_utf8(output.to_vec())
            .expect("utf8")
            .split("\n\n")
            .filter(|event| !event.is_empty())
            .map(|event| {
                let mut text = event.to_string();
                text.push_str("\n\n");
                BufferedInputJsonDeltaEvent::parse(&text)
                    .expect("parse output event")
                    .fragment
            })
            .collect()
    }

    fn test_processor() -> Arc<Processor> {
        Arc::new(Processor {
            vault: None,
            ruleset: Arc::new(RuleSet::bundled().expect("bundled rules")),
            max_body_size: 1 << 20,
            strict_mode: true,
            notice_mode: crate::redaction::NoticeMode::Verbose,
        })
    }

    fn test_processor_with_vault(vault: Arc<Store>) -> Arc<Processor> {
        Arc::new(Processor {
            vault: Some(vault),
            ruleset: Arc::new(RuleSet::bundled().expect("bundled rules")),
            max_body_size: 1 << 20,
            strict_mode: true,
            notice_mode: crate::redaction::NoticeMode::Verbose,
        })
    }
}
