use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::errors::KeyclawError;
use crate::gitleaks_rules::RuleSet;

pub const CONTRACT_MARKER_KEY: &str = "_keyclaw_contract";
pub const CONTRACT_MARKER_VALUE: &str = "placeholder:v1";

const PREFIX_LEN: usize = 5;

static PLACEHOLDER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\{\{KEYCLAW_SECRET_([A-Za-z0-9*_-]{1,5})_([a-f0-9]{16})\}\}").expect("valid placeholder regex")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    pub id: String,
    pub placeholder: String,
    pub secret: String,
}

pub fn make_id(secret: &str) -> String {
    let prefix: String = secret.chars().take(PREFIX_LEN).collect();
    let prefix = if prefix.is_empty() { "*".to_string() } else { prefix };
    let digest = Sha256::digest(secret.as_bytes());
    format!("{}_{}", prefix, hex::encode(&digest[..8]))
}

pub fn make(id: &str) -> String {
    format!("{{{{KEYCLAW_SECRET_{}}}}}", id)
}

pub fn is_placeholder(s: &str) -> bool {
    PLACEHOLDER_RE.is_match(s)
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
        let prefix = caps.get(1).expect("prefix group exists").as_str();
        let hash = caps.get(2).expect("hash group exists").as_str();
        let id = format!("{}_{}", prefix, hash);

        let resolved = resolver(&id)?;
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
