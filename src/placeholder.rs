use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::errors::KeyclawError;

pub const CONTRACT_MARKER_KEY: &str = "_keyclaw_contract";
pub const CONTRACT_MARKER_VALUE: &str = "placeholder:v1";

static PLACEHOLDER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\{\{KEYCLAW_SECRET_([a-f0-9]{16})\}\}").expect("valid placeholder regex")
});
static OPENAI_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9_-]{20,}").expect("valid openai regex"));
static ANTHROPIC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").expect("valid anthropic regex"));
static AWS_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid aws key regex"));
static GITHUB_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"gh[ps]_[A-Za-z0-9]{36,}").expect("valid github token regex"));
static GENERIC_API_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\W*[:=]\W*([A-Za-z0-9_-]{20,})").expect("valid generic api key regex"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    pub id: String,
    pub placeholder: String,
    pub secret: String,
}

pub fn make_id(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    hex::encode(&digest[..8])
}

pub fn make(id: &str) -> String {
    format!("{{{{KEYCLAW_SECRET_{}}}}}", id.to_ascii_lowercase())
}

pub fn is_placeholder(s: &str) -> bool {
    PLACEHOLDER_RE.is_match(s)
}

pub fn replace_secrets<F>(
    input: &str,
    mut on_secret: F,
) -> Result<(String, Vec<Replacement>), KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let mut replacements = Vec::<Replacement>::new();

    let out = rewrite_with_regex(&OPENAI_RE, input, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&ANTHROPIC_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&AWS_KEY_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&GITHUB_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_generic_regex(&GENERIC_API_KEY_RE, &out, &mut replacements, &mut on_secret)?;
    Ok((out, replacements))
}

pub fn resolve_placeholders<F>(
    input: &str,
    strict: bool,
    mut resolver: F,
) -> Result<String, KeyclawError>
where
    F: FnMut(&str) -> Result<Option<String>, KeyclawError>,
{
    let mut matches = PLACEHOLDER_RE.captures_iter(input).peekable();
    if matches.peek().is_none() {
        return Ok(input.to_string());
    }

    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;

    for caps in PLACEHOLDER_RE.captures_iter(input) {
        let full = caps.get(0).expect("full match exists");
        let id_match = caps.get(1).expect("capture group exists");
        let id = id_match.as_str();

        let resolved = resolver(id)?;
        match resolved {
            Some(secret) => {
                out.push_str(&input[last..full.start()]);
                out.push_str(&secret);
                last = full.end();
            }
            None if strict => {
                return Err(KeyclawError::uncoded(format!(
                    "missing placeholder secret for id {id}"
                )));
            }
            None => {
                out.push_str(&input[last..full.end()]);
                last = full.end();
            }
        }
    }

    out.push_str(&input[last..]);
    Ok(out)
}

fn rewrite_with_regex<F>(
    re: &Regex,
    input: &str,
    replacements: &mut Vec<Replacement>,
    on_secret: &mut F,
) -> Result<String, KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut has_match = false;

    for m in re.find_iter(input) {
        has_match = true;
        let secret = m.as_str();
        let id = on_secret(secret)?;
        let ph = make(&id);

        replacements.push(Replacement {
            id,
            placeholder: ph.clone(),
            secret: secret.to_string(),
        });

        out.push_str(&input[last..m.start()]);
        out.push_str(&ph);
        last = m.end();
    }

    if !has_match {
        return Ok(input.to_string());
    }

    out.push_str(&input[last..]);
    Ok(out)
}

fn rewrite_with_generic_regex<F>(
    re: &Regex,
    input: &str,
    replacements: &mut Vec<Replacement>,
    on_secret: &mut F,
) -> Result<String, KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut has_match = false;

    for caps in re.captures_iter(input) {
        has_match = true;
        let full = caps.get(0).expect("full match exists");
        let secret_match = caps.get(1).unwrap_or(full);
        let secret = secret_match.as_str();
        let id = on_secret(secret)?;
        let ph = make(&id);

        replacements.push(Replacement {
            id,
            placeholder: ph.clone(),
            secret: secret.to_string(),
        });

        // Replace just the captured secret within the full match
        out.push_str(&input[last..secret_match.start()]);
        out.push_str(&ph);
        last = secret_match.end();
    }

    if !has_match {
        return Ok(input.to_string());
    }

    out.push_str(&input[last..]);
    Ok(out)
}
