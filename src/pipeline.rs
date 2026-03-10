//! Request rewrite and placeholder-resolution pipeline shared by the proxy and
//! CLI helpers.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

use crate::errors::{
    CODE_BODY_TOO_LARGE, CODE_INVALID_JSON, CODE_STRICT_RESOLVE_FAILED, KeyclawError,
};
use crate::gitleaks_rules::RuleSet;
use crate::kingfisher::SecondPassScanner;
use crate::placeholder::{self, Replacement};
use crate::redaction;
use crate::vault::Store;

const MAX_DECODE_DEPTH: u8 = 2;
const MAX_DECODE_INPUT_BYTES: usize = 64 * 1024;

static BASE64_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9_-]{24,})").expect("valid base64 token regex")
});

#[derive(Clone)]
pub struct Processor {
    /// Vault used to store and resolve placeholder mappings.
    pub vault: Option<Arc<Store>>,
    /// Compiled bundled or custom gitleaks rules.
    pub ruleset: Arc<RuleSet>,
    /// Provider-specific second-pass scanner used when the first pass misses.
    pub second_pass_scanner: Option<Arc<SecondPassScanner>>,
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
    /// Warm up any expensive state, such as vault initialization, before
    /// serving live traffic.
    pub fn warm_up(&self) -> Result<(), KeyclawError> {
        if let Some(vault) = &self.vault {
            vault.warm_up()?;
        }
        Ok(())
    }

    /// Rewrite user-authored content in a standard chat-style payload.
    pub fn rewrite_and_evaluate(&self, body: &[u8]) -> Result<RewriteResult, KeyclawError> {
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

        let ruleset = &self.ruleset;
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
                            let (rewritten, reps) = rewrite_string(
                                s,
                                ruleset,
                                self.second_pass_scanner.as_ref(),
                                self.vault.as_ref(),
                                self.dry_run,
                            )?;
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
        let rewritten = if notice_count > 0
            && !matches!(self.notice_mode, redaction::NoticeMode::Off)
        {
            redaction::inject_redaction_notice_with_mode(&rewritten, notice_count, self.notice_mode)
                .unwrap_or(rewritten)
        } else {
            rewritten
        };

        Ok(RewriteResult {
            body: rewritten,
            replacements,
        })
    }

    /// Resolve placeholders inside a JSON payload using the configured vault.
    pub fn resolve_json(&self, body: &[u8]) -> Result<Vec<u8>, KeyclawError> {
        let Some(vault) = &self.vault else {
            return Ok(body.to_vec());
        };

        let resolved =
            redaction::resolve_json_placeholders(body, self.strict_mode, |id| vault.resolve(id));

        match resolved {
            Ok(value) => Ok(value),
            Err(e) if self.strict_mode => Err(e),
            Err(_) => Ok(body.to_vec()),
        }
    }

    /// Resolve placeholders inside a plain-text payload.
    pub fn resolve_text(&self, body: &[u8]) -> Result<Vec<u8>, KeyclawError> {
        let Some(vault) = &self.vault else {
            return Ok(body.to_vec());
        };

        let text = String::from_utf8_lossy(body);
        if !crate::placeholder::contains_placeholder_prefix(&text) {
            return Ok(body.to_vec());
        }

        match crate::placeholder::resolve_placeholders(&text, self.strict_mode, |id| {
            vault.resolve(id)
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
            format!("would replace {} secrets", replacements.len())
        } else {
            format!("replaced {} secrets", replacements.len())
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

    fn rewrite_json_messages<F>(&self, body: &[u8], walk: F) -> Result<RewriteResult, KeyclawError>
    where
        F: for<'a> FnOnce(
            &[u8],
            &'a mut dyn FnMut(&str) -> Result<String, KeyclawError>,
        ) -> Result<Vec<u8>, KeyclawError>,
    {
        self.ensure_body_within_limit(body.len())?;

        let mut replacements: Vec<Replacement> = Vec::new();
        let mut rewrite = |input: &str| {
            let (rewritten, reps) = rewrite_string(
                input,
                &self.ruleset,
                self.second_pass_scanner.as_ref(),
                self.vault.as_ref(),
                self.dry_run,
            )?;
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
}

fn is_user_message(item: &Value) -> bool {
    item.as_object()
        .and_then(|obj| obj.get("role"))
        .and_then(Value::as_str)
        == Some("user")
}

fn rewrite_string(
    input: &str,
    ruleset: &RuleSet,
    second_pass_scanner: Option<&Arc<SecondPassScanner>>,
    vault: Option<&Arc<Store>>,
    dry_run: bool,
) -> Result<(String, Vec<Replacement>), KeyclawError> {
    rewrite_string_recursive(input, ruleset, second_pass_scanner, vault, dry_run, 0)
}

fn rewrite_string_recursive(
    input: &str,
    ruleset: &RuleSet,
    second_pass_scanner: Option<&Arc<SecondPassScanner>>,
    vault: Option<&Arc<Store>>,
    dry_run: bool,
    decoded_depth: u8,
) -> Result<(String, Vec<Replacement>), KeyclawError> {
    let mut rewritten = input.to_string();
    let mut replacements = Vec::new();

    if decoded_depth < MAX_DECODE_DEPTH && rewritten.len() <= MAX_DECODE_INPUT_BYTES {
        if let Some((json_rewritten, json_replacements)) = rewrite_json_stringified(
            &rewritten,
            ruleset,
            second_pass_scanner,
            vault,
            dry_run,
            decoded_depth,
        )? {
            rewritten = json_rewritten;
            replacements.extend(json_replacements);
        }

        let (base64_rewritten, base64_replacements) = rewrite_base64_tokens(
            &rewritten,
            ruleset,
            second_pass_scanner,
            vault,
            dry_run,
            decoded_depth,
        )?;
        if !base64_replacements.is_empty() {
            rewritten = base64_rewritten;
            replacements.extend(base64_replacements);
        }
    }

    let (direct_rewritten, direct_replacements) = placeholder::replace_secrets_with_options(
        &rewritten,
        ruleset,
        decoded_depth,
        replacements.is_empty(),
        |secret| {
            if dry_run {
                Ok(placeholder::make_id(secret))
            } else if let Some(vault) = vault {
                vault.store_secret(secret)
            } else {
                Ok(placeholder::make_id(secret))
            }
        },
    )?;
    rewritten = direct_rewritten;
    replacements.extend(direct_replacements);

    if replacements.is_empty() {
        let (second_pass_rewritten, second_pass_replacements) = rewrite_with_second_pass(
            &rewritten,
            second_pass_scanner,
            vault,
            dry_run,
            decoded_depth,
        )?;
        rewritten = second_pass_rewritten;
        replacements.extend(second_pass_replacements);
    }

    Ok((rewritten, replacements))
}

fn rewrite_json_stringified(
    input: &str,
    ruleset: &RuleSet,
    second_pass_scanner: Option<&Arc<SecondPassScanner>>,
    vault: Option<&Arc<Store>>,
    dry_run: bool,
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

    let (rewritten_value, replacements) = rewrite_json_value(
        parsed,
        ruleset,
        second_pass_scanner,
        vault,
        dry_run,
        decoded_depth + 1,
    )?;
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

fn rewrite_json_value(
    value: Value,
    ruleset: &RuleSet,
    second_pass_scanner: Option<&Arc<SecondPassScanner>>,
    vault: Option<&Arc<Store>>,
    dry_run: bool,
    decoded_depth: u8,
) -> Result<(Value, Vec<Replacement>), KeyclawError> {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            let mut replacements = Vec::new();
            for (key, value) in map {
                let (rewritten, reps) = rewrite_json_value(
                    value,
                    ruleset,
                    second_pass_scanner,
                    vault,
                    dry_run,
                    decoded_depth,
                )?;
                out.insert(key, rewritten);
                replacements.extend(reps);
            }
            Ok((Value::Object(out), replacements))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            let mut replacements = Vec::new();
            for item in items {
                let (rewritten, reps) = rewrite_json_value(
                    item,
                    ruleset,
                    second_pass_scanner,
                    vault,
                    dry_run,
                    decoded_depth,
                )?;
                out.push(rewritten);
                replacements.extend(reps);
            }
            Ok((Value::Array(out), replacements))
        }
        Value::String(text) => {
            let (rewritten, replacements) = rewrite_string_recursive(
                &text,
                ruleset,
                second_pass_scanner,
                vault,
                dry_run,
                decoded_depth,
            )?;
            Ok((Value::String(rewritten), replacements))
        }
        other => Ok((other, Vec::new())),
    }
}

fn rewrite_base64_tokens(
    input: &str,
    ruleset: &RuleSet,
    second_pass_scanner: Option<&Arc<SecondPassScanner>>,
    vault: Option<&Arc<Store>>,
    dry_run: bool,
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

        let (rewritten_decoded, mut nested_replacements) = rewrite_string_recursive(
            &decoded,
            ruleset,
            second_pass_scanner,
            vault,
            dry_run,
            decoded_depth + 1,
        )?;
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

fn rewrite_with_second_pass(
    input: &str,
    second_pass_scanner: Option<&Arc<SecondPassScanner>>,
    vault: Option<&Arc<Store>>,
    dry_run: bool,
    decoded_depth: u8,
) -> Result<(String, Vec<Replacement>), KeyclawError> {
    let Some(scanner) = second_pass_scanner else {
        return Ok((input.to_string(), Vec::new()));
    };

    scanner.replace_secrets(input, decoded_depth, |secret| {
        if dry_run {
            Ok(placeholder::make_id(secret))
        } else if let Some(vault) = vault {
            vault.store_secret(secret)
        } else {
            Ok(placeholder::make_id(secret))
        }
    })
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::Processor;
    use crate::errors::{CODE_BODY_TOO_LARGE, code_of};
    use crate::gitleaks_rules::RuleSet;

    fn processor_with_limit(max_body_size: i64) -> Processor {
        Processor {
            vault: None,
            ruleset: Arc::new(RuleSet::from_toml("rules = []").expect("empty ruleset")),
            second_pass_scanner: None,
            max_body_size,
            strict_mode: true,
            notice_mode: crate::redaction::NoticeMode::Verbose,
            dry_run: false,
            hooks: None,
        }
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
