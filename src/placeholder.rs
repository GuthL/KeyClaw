//! Placeholder generation, parsing, and resolution helpers.

use sha2::{Digest, Sha256};

use crate::errors::KeyclawError;
use crate::sensitive::{MatchConfidence, MatchSource, ProtectionPolicy, SensitiveKind};

/// HTTP header key used to signal the placeholder contract version.
pub const CONTRACT_MARKER_KEY: &str = "x-keyclaw-contract";
/// Current placeholder contract version value.
pub const CONTRACT_MARKER_VALUE: &str = "placeholder:v2";
/// Example placeholder shown in operator and model-facing notices.
pub const EXAMPLE_PLACEHOLDER: &str = "{{KEYCLAW_OPAQUE_xxxx}}";

const PLACEHOLDER_START: &str = "{{KEYCLAW_";
const MAX_PARTIAL_PLACEHOLDER_LEN: usize = PLACEHOLDER_START.len() + 16 + 1 + 64 + 2;

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
pub fn make(id: &str) -> String {
    make_typed(SensitiveKind::OpaqueToken, id)
}

/// Render a placeholder token for the supplied kind and ID.
pub fn make_typed(kind: SensitiveKind, id: &str) -> String {
    format!(
        "{PLACEHOLDER_START}{}_{}{}",
        kind.placeholder_label(),
        id,
        "}}"
    )
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
    let scan_start = text.len().saturating_sub(MAX_PARTIAL_PLACEHOLDER_LEN);
    let tail = &text[scan_start..];

    tail.char_indices().find_map(|(rel, ch)| {
        if ch != '{' {
            return None;
        }

        let abs = scan_start + rel;
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

    let rest = &text[PLACEHOLDER_START.len()..];
    let Some(label_sep) = rest.find('_') else {
        return if placeholder_label_prefix_matches(rest) {
            PlaceholderParse::Partial
        } else {
            PlaceholderParse::NoMatch
        };
    };

    let label = &rest[..label_sep];
    let Some(kind) = SensitiveKind::from_placeholder_label(label) else {
        return if placeholder_label_prefix_matches(label) {
            PlaceholderParse::Partial
        } else {
            PlaceholderParse::NoMatch
        };
    };

    let id_and_tail = &rest[label_sep + 1..];
    if id_and_tail.is_empty() {
        return PlaceholderParse::Partial;
    }

    let Some(close_rel) = id_and_tail.find("}}") else {
        let partial_id = id_and_tail.strip_suffix('}').unwrap_or(id_and_tail);
        return if partial_id.bytes().all(is_placeholder_id_byte) {
            PlaceholderParse::Partial
        } else {
            PlaceholderParse::NoMatch
        };
    };
    let id = &id_and_tail[..close_rel];
    if !is_valid_placeholder_id(kind, id) {
        return PlaceholderParse::NoMatch;
    }

    let full_len = PLACEHOLDER_START.len() + label.len() + 1 + id.len() + 2;
    PlaceholderParse::Complete(PlaceholderMatch { kind, id, full_len })
}

fn placeholder_label_prefix_matches(candidate: &str) -> bool {
    [
        SensitiveKind::OpaqueToken,
        SensitiveKind::Password,
        SensitiveKind::Email,
        SensitiveKind::Phone,
        SensitiveKind::NationalId,
        SensitiveKind::Passport,
        SensitiveKind::PaymentCard,
        SensitiveKind::Cvv,
    ]
    .iter()
    .any(|kind| kind.placeholder_label().starts_with(candidate))
}

fn is_placeholder_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'_' | b'-' | b'.')
}

fn is_valid_placeholder_id(kind: SensitiveKind, id: &str) -> bool {
    if id.is_empty() || !id.bytes().all(is_placeholder_id_byte) {
        return false;
    }

    matches!(
        kind,
        SensitiveKind::OpaqueToken
            | SensitiveKind::Password
            | SensitiveKind::Email
            | SensitiveKind::Phone
            | SensitiveKind::NationalId
            | SensitiveKind::Passport
            | SensitiveKind::PaymentCard
            | SensitiveKind::Cvv
    ) && id.len() >= 8
        && id.len() <= 64
        && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}
