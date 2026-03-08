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
