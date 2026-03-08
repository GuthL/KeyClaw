use sha2::{Digest, Sha256};

use crate::errors::KeyclawError;
use crate::gitleaks_rules::RuleSet;

pub const CONTRACT_MARKER_KEY: &str = "_keyclaw_contract";
pub const CONTRACT_MARKER_VALUE: &str = "placeholder:v1";

const PLACEHOLDER_MARKER: &str = "{{KEYCLAW_SECRET_";
const PREFIX_LEN: usize = 5;
const HASH_LEN: usize = 16;
const MAX_PARTIAL_PLACEHOLDER_LEN: usize = PLACEHOLDER_MARKER.len() + PREFIX_LEN + 1 + HASH_LEN + 1;
pub(crate) const MAX_PLACEHOLDER_LEN: usize =
    PLACEHOLDER_MARKER.len() + PREFIX_LEN + 1 + HASH_LEN + 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    pub id: String,
    pub placeholder: String,
    pub secret: String,
}

pub fn make_id(secret: &str) -> String {
    let prefix: String = secret
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '*' || *c == '_' || *c == '-')
        .take(PREFIX_LEN)
        .collect();
    let prefix = if prefix.is_empty() {
        "*".to_string()
    } else {
        prefix
    };
    let digest = Sha256::digest(secret.as_bytes());
    format!("{}_{}", prefix, hex::encode(&digest[..8]))
}

pub fn make(id: &str) -> String {
    format!("{PLACEHOLDER_MARKER}{id}}}}}")
}

pub fn is_placeholder(s: &str) -> bool {
    matches!(
        parse_placeholder(s),
        PlaceholderParse::Complete(matched) if matched.full_len == s.len()
    )
}

pub fn contains_complete_placeholder(text: &str) -> bool {
    let mut cursor = 0usize;

    while let Some(rel) = text[cursor..].find(PLACEHOLDER_MARKER) {
        let start = cursor + rel;
        if complete_placeholder_len(&text[start..]).is_some() {
            return true;
        }
        cursor = start + PLACEHOLDER_MARKER.len();
    }

    false
}

pub fn replace_secrets<F>(
    input: &str,
    ruleset: &RuleSet,
    mut on_secret: F,
) -> Result<(String, Vec<Replacement>), KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let matches = ruleset.find_secrets(input);
    if matches.is_empty() {
        return Ok((input.to_string(), Vec::new()));
    }

    let mut replacements = Vec::with_capacity(matches.len());
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;

    for m in &matches {
        let id = on_secret(m.secret)?;
        let ph = make(&id);

        replacements.push(Replacement {
            id,
            placeholder: ph.clone(),
            secret: m.secret.to_string(),
        });

        out.push_str(&input[last..m.start]);
        out.push_str(&ph);
        last = m.end;
    }

    out.push_str(&input[last..]);
    Ok((out, replacements))
}

/// Find the start of a partial (incomplete) placeholder near the end of text.
/// Returns `Some(byte_offset)` if text ends with a prefix of `{{KEYCLAW_SECRET_...}}` that
/// could continue in the next chunk.
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
    text.contains(PLACEHOLDER_MARKER)
}

pub fn resolve_placeholders<F>(
    input: &str,
    strict: bool,
    mut resolver: F,
) -> Result<String, KeyclawError>
where
    F: FnMut(&str) -> Result<Option<String>, KeyclawError>,
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
                let resolved = resolver(matched.id)?;
                match resolved {
                    Some(secret) => out.push_str(&secret),
                    None if strict => {
                        return Err(KeyclawError::uncoded(format!(
                            "missing placeholder secret for id {}",
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
struct PlaceholderMatch<'a> {
    id: &'a str,
    full_len: usize,
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
    if text.len() < PLACEHOLDER_MARKER.len() {
        return if PLACEHOLDER_MARKER.starts_with(text) {
            PlaceholderParse::Partial
        } else {
            PlaceholderParse::NoMatch
        };
    }
    if !text.starts_with(PLACEHOLDER_MARKER) {
        return PlaceholderParse::NoMatch;
    }

    let bytes = text.as_bytes();
    let prefix_start = PLACEHOLDER_MARKER.len();
    let mut saw_partial = bytes.len() == prefix_start;

    for prefix_len in 1..=PREFIX_LEN {
        let prefix_end = prefix_start + prefix_len;
        if bytes.len() < prefix_end {
            let candidate = &bytes[prefix_start..];
            if candidate.iter().all(|byte| is_placeholder_id_byte(*byte)) {
                saw_partial = true;
            }
            break;
        }

        let prefix = &bytes[prefix_start..prefix_end];
        if !prefix.iter().all(|byte| is_placeholder_id_byte(*byte)) {
            break;
        }

        if bytes.len() == prefix_end {
            saw_partial = true;
            continue;
        }
        if bytes[prefix_end] != b'_' {
            continue;
        }

        let hash_start = prefix_end + 1;
        let hash_end = hash_start + HASH_LEN;
        if bytes.len() <= hash_start {
            saw_partial = true;
            continue;
        }
        if bytes.len() < hash_end {
            if bytes[hash_start..]
                .iter()
                .all(|byte| byte.is_ascii_hexdigit())
            {
                saw_partial = true;
            }
            continue;
        }
        if !bytes[hash_start..hash_end]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        if bytes.len() == hash_end {
            saw_partial = true;
            continue;
        }
        if bytes[hash_end] != b'}' {
            continue;
        }
        if bytes.len() == hash_end + 1 {
            saw_partial = true;
            continue;
        }
        if bytes[hash_end + 1] != b'}' {
            continue;
        }

        return PlaceholderParse::Complete(PlaceholderMatch {
            id: &text[prefix_start..hash_end],
            full_len: hash_end + 2,
        });
    }

    if saw_partial {
        PlaceholderParse::Partial
    } else {
        PlaceholderParse::NoMatch
    }
}

fn is_placeholder_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'_' | b'-')
}
