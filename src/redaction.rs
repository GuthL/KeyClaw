use serde_json::Value;

use crate::errors::{KeyclawError, CODE_STRICT_RESOLVE_FAILED};
use crate::placeholder::{self};

pub fn walk_json_strings<F>(input: &[u8], mut transform: F) -> Result<Vec<u8>, KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let parsed: Value = serde_json::from_slice(input)
        .map_err(|e| KeyclawError::uncoded_with_source("decode json", e))?;
    let rewritten = walk_value(parsed, &mut transform)?;
    serde_json::to_vec(&rewritten).map_err(|e| KeyclawError::uncoded_with_source("encode json", e))
}

pub fn inject_contract_marker(input: &[u8]) -> Result<Vec<u8>, KeyclawError> {
    // Contract marker is now injected as an HTTP header (X-Keyclaw-Contract)
    // rather than in the JSON body, to avoid API schema rejections.
    Ok(input.to_vec())
}

pub fn inject_redaction_notice(input: &[u8], count: usize) -> Result<Vec<u8>, KeyclawError> {
    let mut parsed: serde_json::Value = serde_json::from_slice(input)
        .map_err(|e| KeyclawError::uncoded_with_source("decode json for notice injection", e))?;

    let notice = format!(
        "{} secret(s) in this conversation were automatically redacted and replaced \
         with placeholders (like {}) by KeyClaw, an on-device security proxy. \
         You did NOT see the real secret values. \
         IMPORTANT: The first time you encounter a redacted placeholder in this conversation, \
         you MUST acknowledge it to the user by saying something like: \
         'I can see a secret was shared, but it has been securely swapped by KeyClaw. \
         I never see the real value - only a safe placeholder. Everything will work normally \
         because the proxy reinjects the real credential on the fly.' \
         After that first acknowledgment, continue operating normally. Use the placeholder \
         values in commands, code, and tool calls without hesitation - the on-device proxy \
         will automatically reinject the real credentials before anything reaches external services.",
        count,
        placeholder::EXAMPLE_PLACEHOLDER
    );

    let obj = match parsed.as_object_mut() {
        Some(o) => o,
        None => {
            return serde_json::to_vec(&parsed)
                .map_err(|e| KeyclawError::uncoded_with_source("encode json", e))
        }
    };

    // Check model before taking mutable refs
    let is_anthropic = obj
        .get("model")
        .and_then(|v| v.as_str())
        .map(|m| m.contains("claude"))
        .unwrap_or(false);

    if is_anthropic {
        // Anthropic: append to "system" field (trusted context, not a user message)
        match obj.get("system") {
            Some(serde_json::Value::String(sys)) => {
                let new_sys = format!("{}\n\n[KEYCLAW] {}", sys, notice);
                obj.insert("system".to_string(), serde_json::Value::String(new_sys));
            }
            Some(serde_json::Value::Array(arr)) => {
                let mut new_arr = arr.clone();
                new_arr.push(serde_json::json!({
                    "type": "text",
                    "text": format!("[KEYCLAW] {}", notice)
                }));
                obj.insert("system".to_string(), serde_json::Value::Array(new_arr));
            }
            _ => {
                obj.insert(
                    "system".to_string(),
                    serde_json::Value::String(format!("[KEYCLAW] {}", notice)),
                );
            }
        }
    } else {
        // OpenAI / Codex: inject as developer message
        let notice_msg = serde_json::json!({
            "role": "developer",
            "content": format!("[KEYCLAW] {}", notice)
        });
        if let Some(arr) = obj.get_mut("input").and_then(|v| v.as_array_mut()) {
            arr.push(notice_msg);
        } else if let Some(arr) = obj.get_mut("messages").and_then(|v| v.as_array_mut()) {
            arr.push(notice_msg);
        }
    }

    serde_json::to_vec(&parsed)
        .map_err(|e| KeyclawError::uncoded_with_source("encode json after notice", e))
}

/// Walk only user message content strings in chat API payloads.
///
/// Scans `content` fields inside message arrays (`messages`, `input`) and the
/// `instructions` top-level string.  All other strings (auth tokens, model
/// names, tool definitions, etc.) are left untouched.
pub fn walk_message_content<F>(input: &[u8], mut transform: F) -> Result<Vec<u8>, KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let mut parsed: Value = serde_json::from_slice(input)
        .map_err(|e| KeyclawError::uncoded_with_source("decode json", e))?;

    if let Some(obj) = parsed.as_object_mut() {
        walk_message_arrays(obj, &mut transform)?;

        // Walk top-level string fields that contain user content
        for field in &["instructions", "prompt"] {
            if let Some(Value::String(s)) = obj.get(*field) {
                let rewritten = transform(s)?;
                obj.insert(field.to_string(), Value::String(rewritten));
            }
        }

        // Skip top-level "system" because CLI clients commonly populate it
        // with hidden prompt/context that should not trigger user-facing
        // redaction notices.
    }

    serde_json::to_vec(&parsed).map_err(|e| KeyclawError::uncoded_with_source("encode json", e))
}

/// Walk only message-array content for Responses/Chat payloads.
///
/// This intentionally skips top-level `instructions` / `system` fields, which
/// may contain client-provided hidden prompts rather than user-authored input.
pub fn walk_input_message_content<F>(
    input: &[u8],
    mut transform: F,
) -> Result<Vec<u8>, KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let mut parsed: Value = serde_json::from_slice(input)
        .map_err(|e| KeyclawError::uncoded_with_source("decode json", e))?;

    if let Some(obj) = parsed.as_object_mut() {
        walk_input_message_arrays(obj, &mut transform)?;
    }

    serde_json::to_vec(&parsed).map_err(|e| KeyclawError::uncoded_with_source("encode json", e))
}

fn walk_message_arrays<F>(
    obj: &mut serde_json::Map<String, Value>,
    transform: &mut F,
) -> Result<(), KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    // Walk message arrays: "messages" (OpenAI/Anthropic) and "input"
    // (Responses/Codex API).
    for key in &["messages", "input"] {
        if let Some(arr) = obj.get_mut(*key).and_then(|v| v.as_array_mut()) {
            for msg in arr.iter_mut() {
                walk_msg_content_field(msg, transform)?;
            }
        }
    }

    Ok(())
}

fn walk_input_message_arrays<F>(
    obj: &mut serde_json::Map<String, Value>,
    transform: &mut F,
) -> Result<(), KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    for key in &["messages", "input"] {
        if let Some(arr) = obj.get_mut(*key).and_then(|v| v.as_array_mut()) {
            for msg in arr.iter_mut() {
                walk_input_msg_content_field(msg, transform)?;
            }
        }
    }

    Ok(())
}

/// Walk the `content` field of a single message object.
fn walk_msg_content_field<F>(msg: &mut Value, transform: &mut F) -> Result<(), KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let obj = match msg.as_object_mut() {
        Some(o) => o,
        None => return Ok(()),
    };

    match obj.get("content") {
        Some(Value::String(s)) => {
            let rewritten = transform(s)?;
            obj.insert("content".to_string(), Value::String(rewritten));
        }
        Some(Value::Array(_)) => {
            // Anthropic content blocks: [{"type": "text", "text": "..."}, ...]
            if let Some(Value::Array(arr)) = obj.get_mut("content") {
                for block in arr.iter_mut() {
                    if let Some(block_obj) = block.as_object_mut() {
                        if let Some(Value::String(s)) = block_obj.get("text") {
                            let rewritten = transform(s)?;
                            block_obj.insert("text".to_string(), Value::String(rewritten));
                        }
                    }
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn walk_input_msg_content_field<F>(msg: &mut Value, transform: &mut F) -> Result<(), KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let role = msg
        .as_object()
        .and_then(|obj| obj.get("role"))
        .and_then(Value::as_str);

    if matches!(role, Some("developer" | "system")) {
        return Ok(());
    }

    walk_msg_content_field(msg, transform)
}

pub fn resolve_json_placeholders<F>(
    input: &[u8],
    strict: bool,
    mut resolver: F,
) -> Result<Vec<u8>, KeyclawError>
where
    F: FnMut(&str) -> Result<Option<String>, KeyclawError>,
{
    walk_json_strings(input, |s| {
        match placeholder::resolve_placeholders(s, strict, &mut resolver) {
            Ok(resolved) => Ok(resolved),
            Err(err) if strict => Err(KeyclawError::coded_with_source(
                CODE_STRICT_RESOLVE_FAILED,
                "strict placeholder resolution failed",
                err,
            )),
            Err(_) => Ok(s.to_string()),
        }
    })
}

fn walk_value<F>(value: Value, transform: &mut F) -> Result<Value, KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k, walk_value(v, transform)?);
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(walk_value(item, transform)?);
            }
            Ok(Value::Array(out))
        }
        Value::String(s) => transform(&s).map(Value::String),
        other => Ok(other),
    }
}
