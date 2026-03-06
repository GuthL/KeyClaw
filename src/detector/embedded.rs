use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::detector::{Detector, Finding, Severity};
use crate::errors::KeyclawError;

static RE_OPENAI: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9]{20,}").expect("valid OpenAI token regex"));
static RE_ANTHROPIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").expect("valid Anthropic token regex"));
static RE_BEARER_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)bearer\s+([A-Za-z0-9._-]{20,})").expect("valid bearer token regex")
});
static RE_ENTROPY_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9_-]{24,}").expect("valid entropy token regex"));
static SECRET_KEYWORD_MATCHER: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasick::new([
        "api_key",
        "authorization",
        "bearer",
        "secret",
        "token",
        "x-api-key",
        "sk-",
        "sk-ant-",
    ])
    .expect("valid aho-corasick keyword set")
});

#[derive(Debug, Default, Clone)]
pub struct EmbeddedDetector;

impl EmbeddedDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for EmbeddedDetector {
    fn name(&self) -> &'static str {
        "embedded"
    }

    fn detect(&self, payload: &[u8]) -> Result<Vec<Finding>, KeyclawError> {
        let content = String::from_utf8_lossy(payload);
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        let mut add_finding = |rule_id: &str,
                               secret: &str,
                               message: &str,
                               severity: Severity,
                               findings: &mut Vec<Finding>| {
            if secret.is_empty() || secret.contains("KEYCLAW_SECRET_") {
                return;
            }
            if !seen.insert(secret.to_string()) {
                return;
            }
            findings.push(Finding {
                detector: self.name().to_string(),
                rule_id: rule_id.to_string(),
                message: message.to_string(),
                secret: redact_secret(secret),
                severity,
            });
        };

        for token in RE_OPENAI.find_iter(&content).map(|m| m.as_str()) {
            add_finding(
                "embedded_openai",
                token,
                "possible OpenAI secret",
                Severity::High,
                &mut findings,
            );
        }

        for token in RE_ANTHROPIC.find_iter(&content).map(|m| m.as_str()) {
            add_finding(
                "embedded_anthropic",
                token,
                "possible Anthropic secret",
                Severity::High,
                &mut findings,
            );
        }

        for caps in RE_BEARER_TOKEN.captures_iter(&content) {
            if let Some(m) = caps.get(1) {
                let token = m.as_str();
                if !looks_false_positive(token) {
                    add_finding(
                        "embedded_bearer",
                        token,
                        "possible bearer token",
                        Severity::Medium,
                        &mut findings,
                    );
                }
            }
        }

        let lower = content.to_lowercase();
        if SECRET_KEYWORD_MATCHER.is_match(&lower) {
            for token in RE_ENTROPY_TOKEN.find_iter(&content).map(|m| m.as_str()) {
                if looks_false_positive(token)
                    || entropy(token) < 4.15
                    || !has_alpha_and_digit(token)
                {
                    continue;
                }
                add_finding(
                    "embedded_entropy",
                    token,
                    "high entropy token near secret keyword",
                    Severity::Medium,
                    &mut findings,
                );
            }
        }

        Ok(findings)
    }
}

fn redact_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        "[redacted]".to_string()
    } else {
        format!("{}...{}", &secret[..4], &secret[secret.len() - 4..])
    }
}

fn looks_false_positive(token: &str) -> bool {
    let lower = token.to_lowercase();
    if lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("keyclaw_secret")
    {
        return true;
    }
    if token.len() > 64 && token.chars().filter(|c| *c == '_').count() > 4 {
        return true;
    }
    all_same_char(token)
}

fn all_same_char(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return true;
    };
    chars.all(|c| c == first)
}

fn has_alpha_and_digit(token: &str) -> bool {
    let mut has_alpha = false;
    let mut has_digit = false;

    for c in token.chars() {
        if c.is_ascii_alphabetic() {
            has_alpha = true;
        }
        if c.is_ascii_digit() {
            has_digit = true;
        }
        if has_alpha && has_digit {
            return true;
        }
    }

    false
}

fn entropy(token: &str) -> f64 {
    if token.is_empty() {
        return 0.0;
    }

    let mut freq = std::collections::HashMap::<char, usize>::new();
    for ch in token.chars() {
        *freq.entry(ch).or_insert(0) += 1;
    }

    let len = token.chars().count() as f64;
    let mut value = 0.0;
    for count in freq.values() {
        let p = *count as f64 / len;
        value += -p * p.log2();
    }
    value
}
