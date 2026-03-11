//! Request rewrite and placeholder-resolution pipeline shared by the proxy and
//! CLI helpers.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::errors::{
    CODE_BODY_TOO_LARGE, CODE_INVALID_JSON, CODE_STRICT_RESOLVE_FAILED, KeyclawError,
};
use crate::placeholder::{self, Replacement};
use crate::redaction;
use crate::sensitive::{DetectionEngine, SensitiveKind, SessionStore};

const MAX_DECODE_DEPTH: u8 = 2;
const MAX_DECODE_INPUT_BYTES: usize = 64 * 1024;
const LARGE_HIDDEN_PROMPT_BYTES: usize = 8 * 1024;
const LARGE_PROMPT_SECRET_HINTS: &[&str] = &[
    "api key",
    "api-key",
    "api_key",
    "x-api-key",
    "access token",
    "access-token",
    "access_token",
    "auth token",
    "auth-token",
    "auth_token",
    "bearer ",
    "authorization",
    "client secret",
    "client-secret",
    "client_secret",
    "private key",
    "private-key",
    "private_key",
    "secret key",
    "secret-key",
    "secret_key",
    "password",
    "passwd",
    "credential",
    "-----begin",
    "sk-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "akia",
    "asia",
    "xoxa-",
    "xoxb-",
    "xoxp-",
    "xoxs-",
    "aiza",
    "npm_",
    "sq0atp-",
    "sq0csp-",
    "rk_",
    "pk_",
    "hf_",
    "glpat-",
];

static BASE64_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9_-]{24,})").expect("valid base64 token regex")
});

#[derive(Clone)]
pub struct Processor {
    /// Shared detection engine used across request rewrites.
    pub engine: Arc<DetectionEngine>,
    /// Session-scoped storage used for reversible PII/password placeholders.
    pub session_store: Arc<SessionStore>,
    /// Maximum request body size accepted for rewriting.
    pub max_body_size: i64,
    /// Whether placeholder-resolution failures should be treated as errors.
    pub strict_mode: bool,
    /// Notice mode injected after a successful rewrite.
    pub notice_mode: redaction::NoticeMode,
    /// Whether rewrites should report matches without mutating traffic.
    pub dry_run: bool,
    /// Optional hook runner for request-side events.
    pub hooks: Option<Arc<crate::hooks::HookRunner>>,
}

#[derive(Debug, Clone)]
pub struct RewriteResult {
    /// Rewritten request body.
    pub body: Vec<u8>,
    /// Metadata about each replaced secret.
    pub replacements: Vec<Replacement>,
}

impl Processor {
    pub fn new(
        engine: Arc<DetectionEngine>,
        session_store: Arc<SessionStore>,
        max_body_size: i64,
        strict_mode: bool,
        notice_mode: redaction::NoticeMode,
        dry_run: bool,
        hooks: Option<Arc<crate::hooks::HookRunner>>,
    ) -> Self {
        Self {
            engine,
            session_store,
            max_body_size,
            strict_mode,
            notice_mode,
            dry_run,
            hooks,
        }
    }

    /// Warm up any expensive state before serving live traffic.
    pub fn warm_up(&self) -> Result<(), KeyclawError> {
        Ok(())
    }

    /// Rewrite user-authored content in a standard chat-style payload.
    pub fn rewrite_and_evaluate(&self, body: &[u8]) -> Result<RewriteResult, KeyclawError> {
        if should_use_input_only_rewrite(body) {
            return self.rewrite_and_evaluate_input_only(body);
        }

        self.rewrite_json_messages(body, |body, rewrite| {
            redaction::walk_message_content(body, |text| rewrite(text))
        })
    }

    /// Rewrite only message-array content and skip top-level hidden prompt fields.
    pub fn rewrite_and_evaluate_input_only(
        &self,
        body: &[u8],
    ) -> Result<RewriteResult, KeyclawError> {
        self.rewrite_json_messages(body, |body, rewrite| {
            redaction::walk_input_message_content(body, |text| rewrite(text))
        })
    }

    /// Rewrite a Codex WebSocket payload while preserving the expected schema.
    pub fn rewrite_and_evaluate_codex_ws(
        &self,
        body: &[u8],
    ) -> Result<RewriteResult, KeyclawError> {
        self.ensure_body_within_limit(body.len())?;

        let ctx = self.rewrite_context();
        let mut parsed: Value = serde_json::from_slice(body)
            .map_err(|e| KeyclawError::coded_with_source(CODE_INVALID_JSON, "rewrite failed", e))?;
        let mut replacements = Vec::new();
        let mut notice_replacements = 0usize;

        if let Some(obj) = parsed.as_object_mut() {
            for key in ["input", "messages"] {
                if let Some(arr) = obj.get_mut(key).and_then(Value::as_array_mut) {
                    let last_user_index = arr.iter().rposition(is_user_message);
                    for (idx, item) in arr.iter_mut().enumerate() {
                        let before = replacements.len();
                        redaction::rewrite_message_content_fields(item, &mut |s| {
                            let (rewritten, reps) = rewrite_string(s, &ctx)?;
                            replacements.extend(reps);
                            Ok(rewritten)
                        })?;
                        if Some(idx) == last_user_index {
                            notice_replacements += replacements.len() - before;
                        }
                    }
                }
            }
        }

        let rewritten = serde_json::to_vec(&parsed)
            .map_err(|e| KeyclawError::coded_with_source(CODE_INVALID_JSON, "rewrite failed", e))?;
        let rewritten = if self.dry_run {
            body.to_vec()
        } else {
            rewritten
        };

        self.finalize_rewrite_with_notice_count(rewritten, replacements, notice_replacements)
    }

    fn finalize_rewrite(
        &self,
        rewritten: Vec<u8>,
        replacements: Vec<Replacement>,
    ) -> Result<RewriteResult, KeyclawError> {
        let notice_count = replacements.len();
        self.finalize_rewrite_with_notice_count(rewritten, replacements, notice_count)
    }

    fn finalize_rewrite_with_notice_count(
        &self,
        rewritten: Vec<u8>,
        replacements: Vec<Replacement>,
        notice_count: usize,
    ) -> Result<RewriteResult, KeyclawError> {
        if self.dry_run {
            return Ok(RewriteResult {
                body: rewritten,
                replacements,
            });
        }

        let rewritten = redaction::inject_contract_marker(&rewritten).map_err(|e| {
            KeyclawError::coded_with_source(
                CODE_INVALID_JSON,
                "contract marker injection failed",
                e,
            )
        })?;

        // Inject a notice telling the LLM that secrets were redacted
        let rewritten =
            if notice_count > 0 && !matches!(self.notice_mode, redaction::NoticeMode::Off) {
                redaction::inject_redaction_notice_with_mode_and_replacements(
                    &rewritten,
                    notice_count,
                    self.notice_mode,
                    &replacements,
                )
                .unwrap_or(rewritten)
            } else {
                rewritten
            };

        Ok(RewriteResult {
            body: rewritten,
            replacements,
        })
    }

    /// Resolve placeholders inside a JSON payload using the session-scoped store.
    pub fn resolve_json(&self, body: &[u8]) -> Result<Vec<u8>, KeyclawError> {
        let resolved = redaction::walk_json_strings(body, |text| {
            resolve_string_recursive(text, self.strict_mode, &mut |kind, id| {
                self.resolve_placeholder(kind, id)
            })
        });

        match resolved {
            Ok(value) => Ok(value),
            Err(e) if self.strict_mode => Err(e),
            Err(_) => Ok(body.to_vec()),
        }
    }

    /// Resolve placeholders inside a plain-text payload.
    pub fn resolve_text(&self, body: &[u8]) -> Result<Vec<u8>, KeyclawError> {
        let text = String::from_utf8_lossy(body);
        if !crate::placeholder::contains_placeholder_prefix(&text) {
            let resolved = resolve_string_recursive(&text, self.strict_mode, &mut |kind, id| {
                self.resolve_placeholder(kind, id)
            });
            return match resolved {
                Ok(resolved) if resolved != text => Ok(resolved.into_bytes()),
                Ok(_) => Ok(body.to_vec()),
                Err(err) if self.strict_mode => Err(KeyclawError::coded_with_source(
                    CODE_STRICT_RESOLVE_FAILED,
                    "strict text placeholder resolution failed",
                    err,
                )),
                Err(_) => Ok(body.to_vec()),
            };
        }

        match resolve_string_recursive(&text, self.strict_mode, &mut |kind, id| {
            self.resolve_placeholder(kind, id)
        }) {
            Ok(resolved) => Ok(resolved.into_bytes()),
            Err(err) if self.strict_mode => Err(KeyclawError::coded_with_source(
                CODE_STRICT_RESOLVE_FAILED,
                "strict text placeholder resolution failed",
                err,
            )),
            Err(_) => Ok(body.to_vec()),
        }
    }

    /// Render a short operator-facing summary of the rewrite result.
    pub fn replacement_summary(&self, replacements: &[Replacement]) -> String {
        if replacements.is_empty() {
            "no replacements".to_string()
        } else if self.dry_run {
            format!("would replace {} sensitive value(s)", replacements.len())
        } else {
            format!("replaced {} sensitive value(s)", replacements.len())
        }
    }

    pub fn run_secret_detected_hooks(
        &self,
        request_host: &str,
        replacements: &[Replacement],
    ) -> Result<(), KeyclawError> {
        let Some(hooks) = &self.hooks else {
            return Ok(());
        };
        hooks.on_secret_detected(request_host, replacements)
    }

    pub fn run_secret_detected_hooks_blocking(
        &self,
        request_host: &str,
        replacements: &[Replacement],
    ) -> Result<(), KeyclawError> {
        let Some(hooks) = &self.hooks else {
            return Ok(());
        };
        hooks.on_secret_detected_blocking(request_host, replacements)
    }

    pub fn run_request_redacted_hooks(
        &self,
        request_host: &str,
        replacements: &[Replacement],
    ) -> Result<(), KeyclawError> {
        let Some(hooks) = &self.hooks else {
            return Ok(());
        };
        hooks.on_request_redacted(request_host, replacements)
    }

    pub fn run_request_redacted_hooks_blocking(
        &self,
        request_host: &str,
        replacements: &[Replacement],
    ) -> Result<(), KeyclawError> {
        let Some(hooks) = &self.hooks else {
            return Ok(());
        };
        hooks.on_request_redacted_blocking(request_host, replacements)
    }

    fn rewrite_json_messages<F>(&self, body: &[u8], walk: F) -> Result<RewriteResult, KeyclawError>
    where
        F: for<'a> FnOnce(
            &[u8],
            &'a mut dyn FnMut(&str) -> Result<String, KeyclawError>,
        ) -> Result<Vec<u8>, KeyclawError>,
    {
        self.ensure_body_within_limit(body.len())?;

        let mut replacements: Vec<Replacement> = Vec::new();
        let ctx = self.rewrite_context();
        let mut rewrite = |input: &str| {
            let (rewritten, reps) = rewrite_string(input, &ctx)?;
            replacements.extend(reps);
            Ok(rewritten)
        };
        let rewritten = walk(body, &mut rewrite)
            .map_err(|e| KeyclawError::coded_with_source(CODE_INVALID_JSON, "rewrite failed", e))?;
        let rewritten = if self.dry_run {
            body.to_vec()
        } else {
            rewritten
        };

        self.finalize_rewrite(rewritten, replacements)
    }

    fn ensure_body_within_limit(&self, body_len: usize) -> Result<(), KeyclawError> {
        if self.max_body_size > 0 && (body_len as i64) > self.max_body_size {
            Err(KeyclawError::coded(
                CODE_BODY_TOO_LARGE,
                "request body exceeds max body size",
            ))
        } else {
            Ok(())
        }
    }

    fn resolve_placeholder(
        &self,
        kind: SensitiveKind,
        id: &str,
    ) -> Result<Option<String>, KeyclawError> {
        self.session_store.resolve(kind, id)
    }
}

fn is_user_message(item: &Value) -> bool {
    item.as_object()
        .and_then(|obj| obj.get("role"))
        .and_then(Value::as_str)
        == Some("user")
}

struct RewriteContext<'a> {
    engine: &'a DetectionEngine,
    session_store: &'a SessionStore,
    dry_run: bool,
}

impl Processor {
    fn rewrite_context(&self) -> RewriteContext<'_> {
        RewriteContext {
            engine: self.engine.as_ref(),
            session_store: self.session_store.as_ref(),
            dry_run: self.dry_run,
        }
    }
}

fn rewrite_string(
    input: &str,
    ctx: &RewriteContext<'_>,
) -> Result<(String, Vec<Replacement>), KeyclawError> {
    rewrite_string_recursive(input, ctx, 0)
}

fn rewrite_string_recursive(
    input: &str,
    ctx: &RewriteContext<'_>,
    decoded_depth: u8,
) -> Result<(String, Vec<Replacement>), KeyclawError> {
    let mut rewritten = input.to_string();
    let mut replacements = Vec::new();

    if decoded_depth < MAX_DECODE_DEPTH && rewritten.len() <= MAX_DECODE_INPUT_BYTES {
        if let Some((json_rewritten, json_replacements)) =
            rewrite_json_stringified(&rewritten, ctx, decoded_depth)?
        {
            rewritten = json_rewritten;
            replacements.extend(json_replacements);
        }

        let (base64_rewritten, base64_replacements) =
            rewrite_base64_tokens(&rewritten, ctx, decoded_depth)?;
        if !base64_replacements.is_empty() {
            rewritten = base64_rewritten;
            replacements.extend(base64_replacements);
        }
    }

    let (typed_rewritten, typed_replacements) = rewrite_sensitive_values(
        &rewritten,
        ctx.engine,
        ctx.session_store,
        ctx.dry_run,
        decoded_depth,
    )?;
    rewritten = typed_rewritten;
    replacements.extend(typed_replacements);

    Ok((rewritten, replacements))
}

fn rewrite_json_stringified(
    input: &str,
    ctx: &RewriteContext<'_>,
    decoded_depth: u8,
) -> Result<Option<(String, Vec<Replacement>)>, KeyclawError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !matches!(trimmed.as_bytes()[0], b'{' | b'[' | b'"') {
        return Ok(None);
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(value @ Value::Object(_))
        | Ok(value @ Value::Array(_))
        | Ok(value @ Value::String(_)) => value,
        Ok(_) | Err(_) => return Ok(None),
    };

    let (rewritten_value, replacements) = rewrite_json_value(parsed, ctx, decoded_depth + 1)?;
    if replacements.is_empty() {
        return Ok(None);
    }

    let rendered = serde_json::to_string(&rewritten_value)
        .map_err(|e| KeyclawError::uncoded_with_source("encode nested json", e))?;

    Ok(Some((
        replace_trimmed_segment(input, trimmed, &rendered),
        replacements,
    )))
}

fn resolve_string_recursive<F>(
    input: &str,
    strict: bool,
    resolver: &mut F,
) -> Result<String, KeyclawError>
where
    F: FnMut(SensitiveKind, &str) -> Result<Option<String>, KeyclawError>,
{
    resolve_string_recursive_with_depth(input, strict, resolver, 0)
}

fn resolve_string_recursive_with_depth<F>(
    input: &str,
    strict: bool,
    resolver: &mut F,
    decoded_depth: u8,
) -> Result<String, KeyclawError>
where
    F: FnMut(SensitiveKind, &str) -> Result<Option<String>, KeyclawError>,
{
    let mut resolved = input.to_string();

    if decoded_depth < MAX_DECODE_DEPTH && resolved.len() <= MAX_DECODE_INPUT_BYTES {
        if let Some(nested_json) =
            resolve_json_stringified(&resolved, strict, resolver, decoded_depth)?
        {
            resolved = nested_json;
        }

        resolved = resolve_base64_tokens(&resolved, strict, resolver, decoded_depth)?;
    }

    crate::placeholder::resolve_placeholders_typed(&resolved, strict, resolver)
}

fn resolve_json_stringified<F>(
    input: &str,
    strict: bool,
    resolver: &mut F,
    decoded_depth: u8,
) -> Result<Option<String>, KeyclawError>
where
    F: FnMut(SensitiveKind, &str) -> Result<Option<String>, KeyclawError>,
{
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !matches!(trimmed.as_bytes()[0], b'{' | b'[' | b'"') {
        return Ok(None);
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(value @ Value::Object(_))
        | Ok(value @ Value::Array(_))
        | Ok(value @ Value::String(_)) => value,
        Ok(_) | Err(_) => return Ok(None),
    };

    let resolved_value = resolve_json_value(parsed, strict, resolver, decoded_depth + 1)?;
    let rendered = serde_json::to_string(&resolved_value)
        .map_err(|e| KeyclawError::uncoded_with_source("encode nested json", e))?;

    if rendered == trimmed {
        return Ok(None);
    }

    Ok(Some(replace_trimmed_segment(input, trimmed, &rendered)))
}

fn resolve_json_value<F>(
    value: Value,
    strict: bool,
    resolver: &mut F,
    decoded_depth: u8,
) -> Result<Value, KeyclawError>
where
    F: FnMut(SensitiveKind, &str) -> Result<Option<String>, KeyclawError>,
{
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, value) in map {
                out.insert(
                    key,
                    resolve_json_value(value, strict, resolver, decoded_depth)?,
                );
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(resolve_json_value(item, strict, resolver, decoded_depth)?);
            }
            Ok(Value::Array(out))
        }
        Value::String(text) => Ok(Value::String(resolve_string_recursive_with_depth(
            &text,
            strict,
            resolver,
            decoded_depth,
        )?)),
        other => Ok(other),
    }
}

fn resolve_base64_tokens<F>(
    input: &str,
    strict: bool,
    resolver: &mut F,
    decoded_depth: u8,
) -> Result<String, KeyclawError>
where
    F: FnMut(SensitiveKind, &str) -> Result<Option<String>, KeyclawError>,
{
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut changed = false;

    for candidate in BASE64_TOKEN_RE.find_iter(input) {
        let token = candidate.as_str();
        let Some((decoded, variant)) = decode_base64_candidate(token) else {
            continue;
        };

        let resolved_decoded =
            resolve_string_recursive_with_depth(&decoded, strict, resolver, decoded_depth + 1)?;
        if resolved_decoded == decoded {
            continue;
        }

        out.push_str(&input[last..candidate.start()]);
        out.push_str(&variant.encode(&resolved_decoded));
        last = candidate.end();
        changed = true;
    }

    if !changed {
        return Ok(input.to_string());
    }

    out.push_str(&input[last..]);
    Ok(out)
}

fn rewrite_json_value(
    value: Value,
    ctx: &RewriteContext<'_>,
    decoded_depth: u8,
) -> Result<(Value, Vec<Replacement>), KeyclawError> {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            let mut replacements = Vec::new();
            for (key, value) in map {
                let (rewritten, reps) = rewrite_json_value(value, ctx, decoded_depth)?;
                out.insert(key, rewritten);
                replacements.extend(reps);
            }
            Ok((Value::Object(out), replacements))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            let mut replacements = Vec::new();
            for item in items {
                let (rewritten, reps) = rewrite_json_value(item, ctx, decoded_depth)?;
                out.push(rewritten);
                replacements.extend(reps);
            }
            Ok((Value::Array(out), replacements))
        }
        Value::String(text) => {
            let (rewritten, replacements) = rewrite_string_recursive(&text, ctx, decoded_depth)?;
            Ok((Value::String(rewritten), replacements))
        }
        other => Ok((other, Vec::new())),
    }
}

fn rewrite_base64_tokens(
    input: &str,
    ctx: &RewriteContext<'_>,
    decoded_depth: u8,
) -> Result<(String, Vec<Replacement>), KeyclawError> {
    let mut out = String::with_capacity(input.len());
    let mut replacements = Vec::new();
    let mut last = 0usize;

    for candidate in BASE64_TOKEN_RE.find_iter(input) {
        let token = candidate.as_str();
        let Some((decoded, variant)) = decode_base64_candidate(token) else {
            continue;
        };

        let (rewritten_decoded, mut nested_replacements) =
            rewrite_string_recursive(&decoded, ctx, decoded_depth + 1)?;
        if nested_replacements.is_empty() {
            continue;
        }

        out.push_str(&input[last..candidate.start()]);
        out.push_str(&variant.encode(&rewritten_decoded));
        last = candidate.end();
        replacements.append(&mut nested_replacements);
    }

    if replacements.is_empty() {
        return Ok((input.to_string(), replacements));
    }

    out.push_str(&input[last..]);
    Ok((out, replacements))
}

fn rewrite_sensitive_values(
    input: &str,
    engine: &DetectionEngine,
    session_store: &SessionStore,
    dry_run: bool,
    decoded_depth: u8,
) -> Result<(String, Vec<Replacement>), KeyclawError> {
    let matches = engine.detect(input)?;
    if matches.is_empty() {
        return Ok((input.to_string(), Vec::new()));
    }

    let mut out = String::with_capacity(input.len());
    let mut replacements = Vec::with_capacity(matches.len());
    let mut last = 0usize;

    for matched in matches {
        let id = if dry_run {
            dry_run_sensitive_id(matched.kind, matched.secret)
        } else {
            session_store.store(matched.kind, matched.secret)?
        };
        let placeholder = placeholder::make_typed(matched.kind, &id);
        out.push_str(&input[last..matched.start]);
        out.push_str(&placeholder);
        last = matched.end;

        replacements.push(Replacement {
            rule_id: matched.rule_id,
            kind: matched.kind,
            subtype: matched.subtype,
            policy: matched.policy,
            id,
            placeholder,
            secret: matched.secret.to_string(),
            source: matched.source,
            confidence: matched.confidence,
            confidence_score: matched.confidence_score,
            entropy: matched.entropy,
            decoded_depth,
        });
    }

    out.push_str(&input[last..]);
    Ok((out, replacements))
}

fn dry_run_sensitive_id(kind: SensitiveKind, secret: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(kind.as_str().as_bytes());
    digest.update(secret.as_bytes());
    hex::encode(&digest.finalize()[..8])
}

fn decode_base64_candidate(token: &str) -> Option<(String, Base64Variant)> {
    if !looks_like_base64_candidate(token) {
        return None;
    }

    let variants = if token.contains('-') || token.contains('_') {
        [Base64Variant::UrlSafeNoPad, Base64Variant::UrlSafe]
    } else if token.ends_with('=') {
        [Base64Variant::Standard, Base64Variant::StandardNoPad]
    } else {
        [Base64Variant::StandardNoPad, Base64Variant::UrlSafeNoPad]
    };

    for variant in variants {
        let decoded = match variant.decode(token) {
            Some(decoded) => decoded,
            None => continue,
        };
        if !decoded_is_reasonable_text(&decoded) {
            continue;
        }
        if let Ok(text) = String::from_utf8(decoded) {
            return Some((text, variant));
        }
    }

    None
}

fn looks_like_base64_candidate(token: &str) -> bool {
    if token.len() < 24 || crate::placeholder::contains_placeholder_prefix(token) {
        return false;
    }

    let has_upper = token.bytes().any(|byte| byte.is_ascii_uppercase());
    let has_lower = token.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_digit = token.bytes().any(|byte| byte.is_ascii_digit());
    let has_base64_punct = token
        .bytes()
        .any(|byte| matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_'));

    has_base64_punct || (has_upper && has_lower && has_digit)
}

fn decoded_is_reasonable_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    let acceptable = bytes
        .iter()
        .filter(|byte| {
            matches!(byte, b'\n' | b'\r' | b'\t')
                || byte.is_ascii_graphic()
                || **byte == b' '
                || **byte >= 0x80
        })
        .count();

    acceptable * 10 >= bytes.len() * 9
}

fn replace_trimmed_segment(input: &str, trimmed: &str, rewritten: &str) -> String {
    let prefix_len = input.find(trimmed).unwrap_or(0);
    let suffix_start = prefix_len + trimmed.len();
    format!(
        "{}{}{}",
        &input[..prefix_len],
        rewritten,
        &input[suffix_start..]
    )
}

#[derive(Clone, Copy)]
enum Base64Variant {
    Standard,
    StandardNoPad,
    UrlSafe,
    UrlSafeNoPad,
}

impl Base64Variant {
    fn decode(self, token: &str) -> Option<Vec<u8>> {
        match self {
            Self::Standard => STANDARD.decode(token).ok(),
            Self::StandardNoPad => STANDARD_NO_PAD.decode(token).ok(),
            Self::UrlSafe => URL_SAFE.decode(token).ok(),
            Self::UrlSafeNoPad => URL_SAFE_NO_PAD.decode(token).ok(),
        }
    }

    fn encode(self, text: &str) -> String {
        match self {
            Self::Standard => STANDARD.encode(text),
            Self::StandardNoPad => STANDARD_NO_PAD.encode(text),
            Self::UrlSafe => URL_SAFE.encode(text),
            Self::UrlSafeNoPad => URL_SAFE_NO_PAD.encode(text),
        }
    }
}

fn should_use_input_only_rewrite(body: &[u8]) -> bool {
    let Ok(parsed) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let Some(obj) = parsed.as_object() else {
        return false;
    };

    ["prompt", "instructions"].iter().any(|field| {
        obj.get(*field)
            .and_then(Value::as_str)
            .map(is_large_hidden_prompt_field)
            .unwrap_or(false)
    })
}

fn is_large_hidden_prompt_field(text: &str) -> bool {
    text.len() >= LARGE_HIDDEN_PROMPT_BYTES && !contains_prompt_secret_hint(text)
}

fn contains_prompt_secret_hint(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    LARGE_PROMPT_SECRET_HINTS
        .iter()
        .any(|hint| lower.contains(hint))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::Processor;
    use crate::allowlist::Allowlist;
    use crate::entropy::EntropyConfig;
    use crate::errors::{CODE_BODY_TOO_LARGE, code_of};
    use crate::sensitive::{DetectionEngine, SensitiveDataConfig, SessionStore};

    fn processor_with_limit(max_body_size: i64) -> Processor {
        Processor::new(
            Arc::new(DetectionEngine::new(
                SensitiveDataConfig::default(),
                EntropyConfig::default(),
                Allowlist::default(),
                None,
            )),
            Arc::new(SessionStore::new(Duration::from_secs(60))),
            max_body_size,
            true,
            crate::redaction::NoticeMode::Verbose,
            false,
            None,
        )
    }

    #[test]
    fn ensure_body_within_limit_uses_shared_body_too_large_error() {
        let processor = processor_with_limit(4);

        let err = processor
            .ensure_body_within_limit(5)
            .expect_err("limit should reject oversized bodies");

        assert_eq!(code_of(&err), Some(CODE_BODY_TOO_LARGE));
    }
}
