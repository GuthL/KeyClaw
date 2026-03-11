//! Placeholder generation, parsing, and resolution helpers.

use sha2::{Digest, Sha256};

use crate::errors::KeyclawError;
use crate::sensitive::{MatchConfidence, MatchSource, ProtectionPolicy, SensitiveKind};

/// HTTP header key used to signal the placeholder contract version.
pub const CONTRACT_MARKER_KEY: &str = "x-keyclaw-contract";
/// Current placeholder contract version value.
pub const CONTRACT_MARKER_VALUE: &str = "placeholder:v2";
/// Example placeholder shown in operator and model-facing notices.
pub const EXAMPLE_PLACEHOLDER: &str = "{{KEYCLAW_Aa0a-0000~oxxxx}}";

const PLACEHOLDER_START: &str = "{{KEYCLAW_";
const PLACEHOLDER_KIND_SEPARATOR: char = '~';
const PLACEHOLDER_ID_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub struct Replacement {
    /// Stable detector ID for the matched value.
    pub rule_id: String,
    /// Typed sensitive-data class.
    pub kind: SensitiveKind,
    /// Detector subtype or pattern family.
    pub subtype: String,
    /// Reversibility policy used for this match.
    pub policy: ProtectionPolicy,
    /// Placeholder ID stored in the backing resolver.
    pub id: String,
    /// Fully rendered placeholder token.
    pub placeholder: String,
    /// Original sensitive value.
    pub secret: String,
    /// Detector source for this replacement.
    pub source: MatchSource,
    /// Bucketed confidence for the match.
    pub confidence: MatchConfidence,
    /// Raw confidence score used for prioritization.
    pub confidence_score: u8,
    /// Entropy score when available.
    pub entropy: Option<f64>,
    /// Base64 decode depth at which the match was discovered.
    pub decoded_depth: u8,
}

/// Derive a deterministic opaque placeholder ID from a secret value.
pub fn make_id(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    hex::encode(&digest[..8])
}

/// Render a placeholder token for an opaque token.
pub fn make(secret: &str, id: &str) -> String {
    make_typed(SensitiveKind::OpaqueToken, secret, id)
}

/// Render a placeholder token for the supplied kind and ID.
pub fn make_typed(kind: SensitiveKind, secret: &str, id: &str) -> String {
    let body = format!(
        "{}{PLACEHOLDER_KIND_SEPARATOR}{}{}",
        format_signature(secret),
        kind.placeholder_tag(),
        id
    );
    format!("{PLACEHOLDER_START}{body}{}", "}}")
}

/// Return `true` if the full input string is exactly one complete placeholder.
pub fn is_placeholder(s: &str) -> bool {
    matches!(
        parse_placeholder(s),
        PlaceholderParse::Complete(matched) if matched.full_len == s.len()
    )
}

/// Return `true` if the text contains at least one complete placeholder.
pub fn contains_complete_placeholder(text: &str) -> bool {
    let mut cursor = 0usize;

    while let Some(rel) = text[cursor..].find(PLACEHOLDER_START) {
        let start = cursor + rel;
        if complete_placeholder_len(&text[start..]).is_some() {
            return true;
        }
        cursor = start + PLACEHOLDER_START.len();
    }

    false
}

/// Find the start of a partial (incomplete) placeholder near the end of text.
pub fn find_partial_placeholder_start(text: &str) -> Option<usize> {
    text.char_indices().rev().find_map(|(abs, ch)| {
        if ch != '{' {
            return None;
        }

        matches!(parse_placeholder(&text[abs..]), PlaceholderParse::Partial).then_some(abs)
    })
}

pub(crate) fn contains_placeholder_prefix(text: &str) -> bool {
    text.contains(PLACEHOLDER_START)
}

/// Resolve opaque-token placeholders by consulting the supplied resolver.
pub fn resolve_placeholders<F>(
    input: &str,
    strict: bool,
    mut resolver: F,
) -> Result<String, KeyclawError>
where
    F: FnMut(&str) -> Result<Option<String>, KeyclawError>,
{
    resolve_placeholders_typed(input, strict, |kind, id| match kind {
        SensitiveKind::OpaqueToken => resolver(id),
        _ => Ok(None),
    })
}

/// Resolve all placeholders in `input` by consulting the supplied typed resolver.
pub fn resolve_placeholders_typed<F>(
    input: &str,
    strict: bool,
    mut resolver: F,
) -> Result<String, KeyclawError>
where
    F: FnMut(SensitiveKind, &str) -> Result<Option<String>, KeyclawError>,
{
    if !contains_placeholder_prefix(input) {
        return Ok(input.to_string());
    }

    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while let Some(rel) = input[cursor..].find("{{") {
        let start = cursor + rel;
        out.push_str(&input[cursor..start]);

        match parse_placeholder(&input[start..]) {
            PlaceholderParse::Complete(matched) => {
                let resolved = resolver(matched.kind, matched.id)?;
                match resolved {
                    Some(secret) => out.push_str(&secret),
                    None if strict => {
                        return Err(KeyclawError::uncoded(format!(
                            "missing placeholder secret for {} id {}",
                            matched.kind.as_str(),
                            matched.id
                        )));
                    }
                    None => out.push_str(&input[start..start + matched.full_len]),
                }
                cursor = start + matched.full_len;
            }
            PlaceholderParse::NoMatch | PlaceholderParse::Partial => {
                out.push_str("{{");
                cursor = start + 2;
            }
        }
    }

    out.push_str(&input[cursor..]);
    Ok(out)
}

pub(crate) fn complete_placeholder_len(text: &str) -> Option<usize> {
    match parse_placeholder(text) {
        PlaceholderParse::Complete(matched) => Some(matched.full_len),
        PlaceholderParse::NoMatch | PlaceholderParse::Partial => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlaceholderMatch<'a> {
    pub kind: SensitiveKind,
    pub id: &'a str,
    pub full_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlaceholderParse<'a> {
    NoMatch,
    Partial,
    Complete(PlaceholderMatch<'a>),
}

fn parse_placeholder(text: &str) -> PlaceholderParse<'_> {
    if text.is_empty() {
        return PlaceholderParse::NoMatch;
    }
    if text.len() < PLACEHOLDER_START.len() {
        return if PLACEHOLDER_START.starts_with(text) {
            PlaceholderParse::Partial
        } else {
            PlaceholderParse::NoMatch
        };
    }
    if !text.starts_with(PLACEHOLDER_START) {
        return PlaceholderParse::NoMatch;
    }

    let body_and_tail = &text[PLACEHOLDER_START.len()..];
    let Some(close_rel) = body_and_tail.find("}}") else {
        return parse_placeholder_body(body_and_tail, false);
    };

    let body = &body_and_tail[..close_rel];
    let PlaceholderParse::Complete(PlaceholderMatch { kind, id, .. }) =
        parse_placeholder_body(body, true)
    else {
        return PlaceholderParse::NoMatch;
    };

    let full_len = PLACEHOLDER_START.len() + body.len() + 2;
    PlaceholderParse::Complete(PlaceholderMatch { kind, id, full_len })
}

fn parse_placeholder_body(body: &str, complete: bool) -> PlaceholderParse<'_> {
    let Some((signature, suffix)) = body.split_once(PLACEHOLDER_KIND_SEPARATOR) else {
        return if body.is_empty() || body.chars().all(is_signature_char) {
            PlaceholderParse::Partial
        } else {
            PlaceholderParse::NoMatch
        };
    };

    if signature.is_empty() || !signature.chars().all(is_signature_char) || suffix.contains('~') {
        return PlaceholderParse::NoMatch;
    }

    let mut chars = suffix.chars();
    let Some(kind_tag) = chars.next() else {
        return if complete {
            PlaceholderParse::NoMatch
        } else {
            PlaceholderParse::Partial
        };
    };
    let Some(kind) = SensitiveKind::from_placeholder_tag(kind_tag) else {
        return PlaceholderParse::NoMatch;
    };

    let id = chars.as_str();
    if id.is_empty() {
        return if complete {
            PlaceholderParse::NoMatch
        } else {
            PlaceholderParse::Partial
        };
    }

    if !is_valid_placeholder_id(id) {
        return PlaceholderParse::NoMatch;
    }

    if complete {
        if id.len() != PLACEHOLDER_ID_LEN {
            return PlaceholderParse::NoMatch;
        }
        PlaceholderParse::Complete(PlaceholderMatch {
            kind,
            id,
            full_len: 0,
        })
    } else if id.len() <= PLACEHOLDER_ID_LEN {
        PlaceholderParse::Partial
    } else {
        PlaceholderParse::NoMatch
    }
}

fn is_valid_placeholder_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_signature_char(ch: char) -> bool {
    matches!(
        ch,
        'A' | 'a' | '0' | 'x' | '_' | '@' | '.' | '-' | ':' | '/' | '+' | '=' | '(' | ')' | '#'
    )
}

fn format_signature(secret: &str) -> String {
    let mut out = String::with_capacity(secret.len());
    for ch in secret.chars() {
        out.push(match ch {
            'a'..='z' => 'a',
            'A'..='Z' => 'A',
            '0'..='9' => '0',
            '@' | '.' | '-' | '_' | ':' | '/' | '+' | '=' | '(' | ')' | '#' => ch,
            ch if ch.is_ascii_whitespace() => '_',
            _ => 'x',
        });
    }
    out
}
