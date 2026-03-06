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
         with placeholders (like {{{{KEYCLAW_SECRET_xxxx}}}}) by KeyClaw, an on-device security proxy. \
         You did NOT see the real secret values. \
         IMPORTANT: The first time you encounter a redacted placeholder in this conversation, \
         you MUST acknowledge it to the user by saying something like: \
         'I can see a secret was shared, but it has been securely swapped by KeyClaw. \
         I never see the real value - only a safe placeholder. Everything will work normally \
         because the proxy reinjects the real credential on the fly.' \
         After that first acknowledgment, continue operating normally. Use the placeholder \
         values in commands, code, and tool calls without hesitation - the on-device proxy \
         will automatically reinject the real credentials before anything reaches external services.",
        count
    );

    let obj = match parsed.as_object_mut() {
        Some(o) => o,
        None => return serde_json::to_vec(&parsed)
            .map_err(|e| KeyclawError::uncoded_with_source("encode json", e)),
    };

    // Check model before taking mutable refs
    let is_anthropic = obj.get("model")
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
                obj.insert("system".to_string(), serde_json::Value::String(
                    format!("[KEYCLAW] {}", notice)
                ));
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
