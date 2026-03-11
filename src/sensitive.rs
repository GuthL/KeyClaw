//! Sensitive-data detection, placeholder metadata, and session-scoped storage.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use once_cell::sync::Lazy;
use rand::RngCore;
use regex::Regex;
use reqwest::blocking::Client;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::allowlist::Allowlist;
use crate::entropy::{EntropyConfig, find_high_entropy_tokens};
use crate::errors::KeyclawError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchSource {
    Regex,
    Entropy,
    Heuristic,
    Classifier,
}

impl MatchSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Entropy => "entropy",
            Self::Heuristic => "heuristic",
            Self::Classifier => "classifier",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchConfidence {
    Low,
    Medium,
    High,
}

impl MatchConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SensitiveKind {
    OpaqueToken,
    Password,
    Email,
    Phone,
    NationalId,
    Passport,
    PaymentCard,
    Cvv,
}

impl SensitiveKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpaqueToken => "opaque_token",
            Self::Password => "password",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::NationalId => "national_id",
            Self::Passport => "passport",
            Self::PaymentCard => "payment_card",
            Self::Cvv => "cvv",
        }
    }

    pub fn display_label(self) -> &'static str {
        match self {
            Self::OpaqueToken => "opaque token",
            Self::Password => "password",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::NationalId => "national ID",
            Self::Passport => "passport",
            Self::PaymentCard => "payment card",
            Self::Cvv => "cvv",
        }
    }

    pub fn placeholder_label(self) -> &'static str {
        match self {
            Self::OpaqueToken => "OPAQUE",
            Self::Password => "PASSWORD",
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::NationalId => "ID",
            Self::Passport => "PASSPORT",
            Self::PaymentCard => "CARD",
            Self::Cvv => "CVV",
        }
    }

    pub fn from_placeholder_label(label: &str) -> Option<Self> {
        match label {
            "OPAQUE" => Some(Self::OpaqueToken),
            "PASSWORD" => Some(Self::Password),
            "EMAIL" => Some(Self::Email),
            "PHONE" => Some(Self::Phone),
            "ID" => Some(Self::NationalId),
            "PASSPORT" => Some(Self::Passport),
            "CARD" => Some(Self::PaymentCard),
            "CVV" => Some(Self::Cvv),
            _ => None,
        }
    }

    pub fn is_session_scoped(self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionPolicy {
    ReversibleSession,
}

impl ProtectionPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReversibleSession => "reversible_session",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SensitiveDataConfig {
    pub passwords_enabled: bool,
    pub emails_enabled: bool,
    pub phones_enabled: bool,
    pub national_ids_enabled: bool,
    pub passports_enabled: bool,
    pub payment_cards_enabled: bool,
    pub cvv_enabled: bool,
    pub session_ttl: Duration,
}

impl Default for SensitiveDataConfig {
    fn default() -> Self {
        Self {
            passwords_enabled: false,
            emails_enabled: false,
            phones_enabled: false,
            national_ids_enabled: false,
            passports_enabled: false,
            payment_cards_enabled: false,
            cvv_enabled: false,
            session_ttl: Duration::from_secs(60 * 60),
        }
    }
}

impl SensitiveDataConfig {
    pub fn any_enabled(&self) -> bool {
        self.passwords_enabled
            || self.emails_enabled
            || self.phones_enabled
            || self.national_ids_enabled
            || self.passports_enabled
            || self.payment_cards_enabled
            || self.cvv_enabled
    }
}

#[derive(Debug, Clone)]
pub struct LocalClassifierConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub model: String,
    pub timeout: Duration,
}

impl Default for LocalClassifierConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            model: String::new(),
            timeout: Duration::from_secs(3),
        }
    }
}

impl LocalClassifierConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled && !self.endpoint.trim().is_empty() && !self.model.trim().is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct DetectionMatch<'a> {
    pub rule_id: String,
    pub kind: SensitiveKind,
    pub subtype: String,
    pub policy: ProtectionPolicy,
    pub source: MatchSource,
    pub confidence: MatchConfidence,
    pub confidence_score: u8,
    pub start: usize,
    pub end: usize,
    pub secret: &'a str,
    pub entropy: Option<f64>,
}

#[derive(Clone, Copy)]
struct DetectionSpec {
    rule_id: &'static str,
    kind: SensitiveKind,
    subtype: &'static str,
    policy: ProtectionPolicy,
    source: MatchSource,
    confidence: MatchConfidence,
    confidence_score: u8,
    validator: Option<fn(&str) -> bool>,
}

impl DetectionSpec {
    fn to_match<'a>(self, start: usize, end: usize, secret: &'a str) -> DetectionMatch<'a> {
        DetectionMatch {
            rule_id: self.rule_id.to_string(),
            kind: self.kind,
            subtype: self.subtype.to_string(),
            policy: self.policy,
            source: self.source,
            confidence: self.confidence,
            confidence_score: self.confidence_score,
            start,
            end,
            secret,
            entropy: None,
        }
    }
}

#[derive(Clone)]
pub struct DetectionEngine {
    typed_config: SensitiveDataConfig,
    entropy_config: EntropyConfig,
    allowlist: Allowlist,
    classifier: Option<Arc<dyn LocalClassifier>>,
}

impl DetectionEngine {
    pub fn new(
        typed_config: SensitiveDataConfig,
        entropy_config: EntropyConfig,
        allowlist: Allowlist,
        classifier: Option<Arc<dyn LocalClassifier>>,
    ) -> Self {
        Self {
            typed_config,
            entropy_config,
            allowlist,
            classifier,
        }
    }

    pub fn detect<'a>(&self, input: &'a str) -> Result<Vec<DetectionMatch<'a>>, KeyclawError> {
        if input.is_empty() {
            return Ok(Vec::new());
        }

        let mut matches = detect_sensitive(input, &self.typed_config, self.classifier.as_deref())?;
        matches.extend(detect_opaque_tokens(input, &self.entropy_config));
        let matches = retain_best_matches(matches);

        Ok(matches
            .into_iter()
            .filter(|matched| !self.allowlist.allows(&matched.rule_id, matched.secret))
            .collect())
    }

    pub fn entropy_config(&self) -> &EntropyConfig {
        &self.entropy_config
    }

    pub fn typed_config(&self) -> &SensitiveDataConfig {
        &self.typed_config
    }
}

#[derive(Debug, Clone)]
pub struct ClassificationCandidate {
    pub kind: SensitiveKind,
    pub subtype: String,
    pub value: String,
    pub context: String,
}

pub trait LocalClassifier: Send + Sync {
    fn accept(&self, candidate: &ClassificationCandidate) -> Result<bool, KeyclawError>;
}

pub struct OpenAiCompatibleLocalClassifier {
    endpoint: String,
    model: String,
    client: Client,
}

impl OpenAiCompatibleLocalClassifier {
    pub fn from_config(cfg: &LocalClassifierConfig) -> Result<Self, KeyclawError> {
        let client = Client::builder()
            .timeout(cfg.timeout)
            .build()
            .map_err(|err| {
                KeyclawError::uncoded_with_source("build classifier HTTP client", err)
            })?;
        Ok(Self {
            endpoint: cfg.endpoint.trim().to_string(),
            model: cfg.model.trim().to_string(),
            client,
        })
    }
}

impl LocalClassifier for OpenAiCompatibleLocalClassifier {
    fn accept(&self, candidate: &ClassificationCandidate) -> Result<bool, KeyclawError> {
        let payload = json!({
            "model": self.model,
            "temperature": 0,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a binary sensitive-data classifier. Reply with ALLOW if the candidate is truly the requested sensitive-data type in context. Reply with DENY otherwise."
                },
                {
                    "role": "user",
                    "content": json!({
                        "kind": candidate.kind.as_str(),
                        "subtype": candidate.subtype,
                        "value": candidate.value,
                        "context": candidate.context,
                    }).to_string()
                }
            ]
        });
        let response = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .body(payload.to_string())
            .send()
            .and_then(|resp| resp.error_for_status())
            .map_err(|err| KeyclawError::uncoded_with_source("run local classifier", err))?;
        let body_text = response.text().map_err(|err| {
            KeyclawError::uncoded_with_source("read local classifier response", err)
        })?;
        let body: serde_json::Value = serde_json::from_str(&body_text).map_err(|err| {
            KeyclawError::uncoded_with_source("decode local classifier response", err)
        })?;
        let content = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .to_ascii_uppercase();
        Ok(content.starts_with("ALLOW"))
    }
}

#[derive(Debug)]
pub struct SensitiveStore {
    ttl: Duration,
    session_salt: [u8; 32],
    entries: Mutex<HashMap<String, SessionEntry>>,
}

#[derive(Debug, Clone)]
struct SessionEntry {
    kind: SensitiveKind,
    secret: String,
    expires_at: Instant,
}

impl SensitiveStore {
    pub fn new(ttl: Duration) -> Self {
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Self::new_with_salt(ttl, salt)
    }

    pub fn new_with_salt(ttl: Duration, session_salt: [u8; 32]) -> Self {
        Self {
            ttl,
            session_salt,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn store(&self, kind: SensitiveKind, secret: &str) -> Result<String, KeyclawError> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| KeyclawError::uncoded("session store mutex poisoned"))?;
        prune_expired(&mut guard);
        let id = self.make_id(kind, secret);
        guard.insert(
            id.clone(),
            SessionEntry {
                kind,
                secret: secret.to_string(),
                expires_at: Instant::now() + self.ttl,
            },
        );
        Ok(id)
    }

    pub fn resolve(&self, kind: SensitiveKind, id: &str) -> Result<Option<String>, KeyclawError> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| KeyclawError::uncoded("session store mutex poisoned"))?;
        prune_expired(&mut guard);
        Ok(guard
            .get(id)
            .filter(|entry| entry.kind == kind)
            .map(|entry| entry.secret.clone()))
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    fn make_id(&self, kind: SensitiveKind, secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.session_salt);
        hasher.update(kind.as_str().as_bytes());
        hasher.update(secret.as_bytes());
        hex::encode(&hasher.finalize()[..8])
    }
}

pub type SessionStore = SensitiveStore;

fn prune_expired(entries: &mut HashMap<String, SessionEntry>) {
    let now = Instant::now();
    entries.retain(|_, entry| entry.expires_at > now);
}

static QUOTED_PASSWORD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:
            password|passwd|passcode|passphrase|pin
        )\b
        \s*(?:=|:|=>)\s*
        ["'`](?P<value>[^"'`\r\n]{4,128})["'`]
    "#,
    )
    .expect("valid password regex")
});
static UNQUOTED_PASSWORD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:
            password|passwd|passcode|passphrase|pin
        )\b
        \s*(?:=|:|=>)\s*
        (?P<value>[^\s,;}\]'"`]{4,128})
    "#,
    )
    .expect("valid password regex")
});
static DSN_PASSWORD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        \b[a-z][a-z0-9+.\-]{1,20}://
        [^/\s:@]{1,64}:
        (?P<value>[^@\s/]{4,128})
        @
    "#,
    )
    .expect("valid DSN password regex")
});
static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?P<value>[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24})\b"#)
        .expect("valid email regex")
});
static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\b(?P<value>\+?\d[\d .()\-/]{7,}\d)\b"#).expect("valid phone regex")
});
static SSN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\b(?P<value>\d{3}-\d{2}-\d{4})\b"#).expect("valid ssn regex"));
static LABELED_ID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:
            ssn|social\ security|national\ id|tax\ id|government\ id|nin
        )\b
        \s*(?:=|:|=>)\s*
        ["'`]?(?P<value>[A-Za-z0-9\-]{6,20})["'`]?
    "#,
    )
    .expect("valid id regex")
});
static PASSPORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        \bpassport(?:\s+(?:number|no|\#))?\b
        \s*(?:=|:|=>)\s*
        ["'`]?(?P<value>[A-Za-z0-9]{6,12})["'`]?
    "#,
    )
    .expect("valid passport regex")
});
static CARD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\b(?P<value>(?:\d[ -]?){13,19})\b"#).expect("valid card regex"));
static CVV_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
        \b(?:cvv|cvc|cvn|security\ code)\b
        \s*(?:=|:|=>)\s*
        ["'`]?(?P<value>\d{3,4})["'`]?
    "#,
    )
    .expect("valid cvv regex")
});

const CARD_CONTEXT_HINTS: &[&str] = &[
    "card",
    "visa",
    "mastercard",
    "amex",
    "american express",
    "payment",
    "billing",
    "checkout",
];

pub fn detect_sensitive<'a>(
    input: &'a str,
    cfg: &SensitiveDataConfig,
    classifier: Option<&dyn LocalClassifier>,
) -> Result<Vec<DetectionMatch<'a>>, KeyclawError> {
    if input.is_empty() || !cfg.any_enabled() {
        return Ok(Vec::new());
    }

    let card_context = input.to_ascii_lowercase();
    let mut matches = Vec::new();

    if cfg.passwords_enabled {
        let labeled_password = DetectionSpec {
            rule_id: "typed.password.labeled",
            kind: SensitiveKind::Password,
            subtype: "labeled",
            policy: ProtectionPolicy::ReversibleSession,
            source: MatchSource::Heuristic,
            confidence: MatchConfidence::High,
            confidence_score: 92,
            validator: Some(validate_password_candidate),
        };
        detect_matches(input, &QUOTED_PASSWORD_RE, &labeled_password, &mut matches);
        detect_matches(
            input,
            &UNQUOTED_PASSWORD_RE,
            &DetectionSpec {
                confidence_score: 90,
                ..labeled_password
            },
            &mut matches,
        );
        detect_matches(
            input,
            &DSN_PASSWORD_RE,
            &DetectionSpec {
                rule_id: "typed.password.dsn",
                subtype: "dsn_userinfo",
                confidence_score: 95,
                ..labeled_password
            },
            &mut matches,
        );
    }

    if cfg.emails_enabled {
        detect_matches(
            input,
            &EMAIL_RE,
            &DetectionSpec {
                rule_id: "typed.email",
                kind: SensitiveKind::Email,
                subtype: "email_address",
                policy: ProtectionPolicy::ReversibleSession,
                source: MatchSource::Heuristic,
                confidence: MatchConfidence::High,
                confidence_score: 90,
                validator: Some(validate_email_candidate),
            },
            &mut matches,
        );
    }

    if cfg.phones_enabled {
        detect_matches(
            input,
            &PHONE_RE,
            &DetectionSpec {
                rule_id: "typed.phone",
                kind: SensitiveKind::Phone,
                subtype: "phone_number",
                policy: ProtectionPolicy::ReversibleSession,
                source: MatchSource::Heuristic,
                confidence: MatchConfidence::Low,
                confidence_score: 55,
                validator: Some(validate_phone_candidate),
            },
            &mut matches,
        );
    }

    if cfg.national_ids_enabled {
        detect_matches(
            input,
            &SSN_RE,
            &DetectionSpec {
                rule_id: "typed.id.ssn",
                kind: SensitiveKind::NationalId,
                subtype: "us_ssn",
                policy: ProtectionPolicy::ReversibleSession,
                source: MatchSource::Heuristic,
                confidence: MatchConfidence::High,
                confidence_score: 94,
                validator: Some(validate_ssn_candidate),
            },
            &mut matches,
        );
        detect_matches(
            input,
            &LABELED_ID_RE,
            &DetectionSpec {
                rule_id: "typed.id.labeled",
                kind: SensitiveKind::NationalId,
                subtype: "labeled_id",
                policy: ProtectionPolicy::ReversibleSession,
                source: MatchSource::Heuristic,
                confidence: MatchConfidence::Low,
                confidence_score: 58,
                validator: Some(validate_id_candidate),
            },
            &mut matches,
        );
    }

    if cfg.passports_enabled {
        detect_matches(
            input,
            &PASSPORT_RE,
            &DetectionSpec {
                rule_id: "typed.passport",
                kind: SensitiveKind::Passport,
                subtype: "passport_number",
                policy: ProtectionPolicy::ReversibleSession,
                source: MatchSource::Heuristic,
                confidence: MatchConfidence::Low,
                confidence_score: 58,
                validator: Some(validate_passport_candidate),
            },
            &mut matches,
        );
    }

    let mut saw_card = false;
    if cfg.payment_cards_enabled {
        for caps in CARD_RE.captures_iter(input) {
            let Some(value_match) = caps.name("value") else {
                continue;
            };
            let candidate = value_match.as_str();
            let Some(normalized) = normalize_card_candidate(candidate) else {
                continue;
            };
            let issuer = card_issuer(&normalized);
            matches.push(
                DetectionSpec {
                    rule_id: "typed.card.pan",
                    kind: SensitiveKind::PaymentCard,
                    subtype: issuer,
                    policy: ProtectionPolicy::ReversibleSession,
                    source: MatchSource::Heuristic,
                    confidence: MatchConfidence::High,
                    confidence_score: 96,
                    validator: None,
                }
                .to_match(value_match.start(), value_match.end(), candidate),
            );
            saw_card = true;
        }
    }

    if cfg.cvv_enabled
        && (saw_card
            || CARD_CONTEXT_HINTS
                .iter()
                .any(|hint| card_context.contains(hint)))
    {
        detect_matches(
            input,
            &CVV_RE,
            &DetectionSpec {
                rule_id: "typed.card.cvv",
                kind: SensitiveKind::Cvv,
                subtype: "card_cvv",
                policy: ProtectionPolicy::ReversibleSession,
                source: MatchSource::Heuristic,
                confidence: MatchConfidence::Low,
                confidence_score: 56,
                validator: Some(validate_cvv_candidate),
            },
            &mut matches,
        );
    }

    let mut matches = retain_best_matches(matches);
    if let Some(classifier) = classifier {
        matches = filter_ambiguous_matches(input, matches, classifier)?;
    }
    Ok(matches)
}

fn detect_opaque_tokens<'a>(input: &'a str, cfg: &EntropyConfig) -> Vec<DetectionMatch<'a>> {
    if !cfg.enabled {
        return Vec::new();
    }

    find_high_entropy_tokens(input, cfg.min_len, cfg.threshold)
        .into_iter()
        .filter(|matched| !should_skip_opaque_candidate(matched.token))
        .map(|matched| {
            let confidence_score = if matched.entropy >= cfg.threshold + 1.0 {
                92
            } else if matched.entropy >= cfg.threshold + 0.5 {
                84
            } else {
                72
            };
            DetectionMatch {
                rule_id: "opaque.high_entropy".to_string(),
                kind: SensitiveKind::OpaqueToken,
                subtype: "high_entropy".to_string(),
                policy: ProtectionPolicy::ReversibleSession,
                source: MatchSource::Entropy,
                confidence: match confidence_score {
                    80..=u8::MAX => MatchConfidence::High,
                    60..=79 => MatchConfidence::Medium,
                    _ => MatchConfidence::Low,
                },
                confidence_score,
                start: matched.start,
                end: matched.end,
                secret: matched.token,
                entropy: Some(matched.entropy),
            }
        })
        .collect()
}

fn should_skip_opaque_candidate(token: &str) -> bool {
    if token.contains("KEYCLAW_") || crate::placeholder::contains_placeholder_prefix(token) {
        return true;
    }

    if token.len() < 24 {
        return false;
    }

    for decoded in [
        STANDARD.decode(token),
        STANDARD_NO_PAD.decode(token),
        URL_SAFE.decode(token),
        URL_SAFE_NO_PAD.decode(token),
    ] {
        let Ok(decoded) = decoded else {
            continue;
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            continue;
        };
        if crate::placeholder::contains_placeholder_prefix(&decoded) {
            return true;
        }
    }

    false
}

fn detect_matches<'a>(
    input: &'a str,
    regex: &Regex,
    spec: &DetectionSpec,
    out: &mut Vec<DetectionMatch<'a>>,
) {
    for caps in regex.captures_iter(input) {
        let Some(value_match) = caps.name("value") else {
            continue;
        };
        let candidate = value_match.as_str();
        if spec.validator.is_some_and(|check| !check(candidate)) {
            continue;
        }
        out.push(spec.to_match(value_match.start(), value_match.end(), candidate));
    }
}

fn retain_best_matches<'a>(mut matches: Vec<DetectionMatch<'a>>) -> Vec<DetectionMatch<'a>> {
    matches.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.confidence_score.cmp(&left.confidence_score))
            .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });

    let mut retained: Vec<DetectionMatch<'a>> = Vec::new();
    for candidate in matches {
        if let Some(last) = retained.last_mut() {
            let overlaps = candidate.start < last.end && candidate.end > last.start;
            if overlaps {
                if candidate.confidence_score > last.confidence_score
                    || (candidate.confidence_score == last.confidence_score
                        && (candidate.end - candidate.start) > (last.end - last.start))
                {
                    *last = candidate;
                }
                continue;
            }
        }
        retained.push(candidate);
    }
    retained
}

fn filter_ambiguous_matches<'a>(
    input: &'a str,
    matches: Vec<DetectionMatch<'a>>,
    classifier: &dyn LocalClassifier,
) -> Result<Vec<DetectionMatch<'a>>, KeyclawError> {
    let mut filtered = Vec::with_capacity(matches.len());
    for candidate in matches {
        if candidate.confidence_score >= 70 {
            filtered.push(candidate);
            continue;
        }

        let context = surrounding_context(input, candidate.start, candidate.end, 96);
        let classifier_candidate = ClassificationCandidate {
            kind: candidate.kind,
            subtype: candidate.subtype.clone(),
            value: candidate.secret.to_string(),
            context,
        };

        let accepted = classifier.accept(&classifier_candidate).unwrap_or(true);
        if accepted {
            let mut upgraded = candidate;
            upgraded.source = MatchSource::Classifier;
            upgraded.confidence = MatchConfidence::Medium;
            upgraded.confidence_score = upgraded.confidence_score.max(72);
            filtered.push(upgraded);
        }
    }
    Ok(filtered)
}

fn surrounding_context(input: &str, start: usize, end: usize, radius: usize) -> String {
    let context_start = start.saturating_sub(radius);
    let context_end = (end + radius).min(input.len());
    input[context_start..context_end].to_string()
}

fn validate_password_candidate(candidate: &str) -> bool {
    let trimmed = candidate.trim();
    trimmed.len() >= 4
        && trimmed.len() <= 128
        && !trimmed.eq_ignore_ascii_case("password")
        && !trimmed.eq_ignore_ascii_case("passwd")
        && !trimmed.eq_ignore_ascii_case("hunter2")
}

fn validate_email_candidate(candidate: &str) -> bool {
    let lower = candidate.to_ascii_lowercase();
    !lower.ends_with(".png")
        && !lower.ends_with(".jpg")
        && !lower.ends_with(".svg")
        && !lower.contains("example.com")
        && !lower.contains("email@example")
}

fn validate_phone_candidate(candidate: &str) -> bool {
    let digits: String = candidate.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if !(10..=15).contains(&digits.len()) {
        return false;
    }
    if digits.chars().all(|ch| ch == digits.as_bytes()[0] as char) {
        return false;
    }
    candidate.contains(' ')
        || candidate.contains('-')
        || candidate.contains('(')
        || candidate.starts_with('+')
}

fn validate_ssn_candidate(candidate: &str) -> bool {
    candidate != "000-00-0000" && candidate != "123-45-6789"
}

fn validate_id_candidate(candidate: &str) -> bool {
    let trimmed = candidate.trim_matches(|ch| ch == '"' || ch == '\'');
    trimmed.len() >= 6 && trimmed.len() <= 20 && trimmed.chars().any(|ch| ch.is_ascii_digit())
}

fn validate_passport_candidate(candidate: &str) -> bool {
    let trimmed = candidate.trim();
    trimmed.len() >= 6 && trimmed.len() <= 12 && trimmed.chars().any(|ch| ch.is_ascii_digit())
}

fn validate_cvv_candidate(candidate: &str) -> bool {
    matches!(candidate.len(), 3 | 4) && !candidate.chars().all(|ch| ch == '0')
}

fn normalize_card_candidate(candidate: &str) -> Option<String> {
    let digits: String = candidate.chars().filter(|ch| ch.is_ascii_digit()).collect();
    if !(13..=19).contains(&digits.len()) {
        return None;
    }
    if digits.chars().all(|ch| ch == digits.as_bytes()[0] as char) {
        return None;
    }
    luhn_valid(&digits).then_some(digits)
}

fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        let mut value = match ch.to_digit(10) {
            Some(value) => value,
            None => return false,
        };
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum % 10 == 0
}

fn card_issuer(digits: &str) -> &'static str {
    if digits.starts_with('4') {
        "visa"
    } else if digits.starts_with("34") || digits.starts_with("37") {
        "amex"
    } else if digits.starts_with("6011")
        || digits.starts_with("65")
        || (digits.len() >= 3 && matches!(digits[..3].parse::<u16>(), Ok(644..=649)))
    {
        "discover"
    } else if (digits.len() >= 2 && matches!(digits[..2].parse::<u8>(), Ok(51..=55)))
        || (digits.len() >= 4 && matches!(digits[..4].parse::<u16>(), Ok(2221..=2720)))
    {
        "mastercard"
    } else {
        "pan"
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LocalClassifier, LocalClassifierConfig, OpenAiCompatibleLocalClassifier, ProtectionPolicy,
        SensitiveDataConfig, SensitiveKind, SessionStore, card_issuer, detect_sensitive,
        luhn_valid, normalize_card_candidate,
    };
    use crate::errors::KeyclawError;

    #[test]
    fn session_store_is_stable_within_a_process() {
        let store = SessionStore::new(std::time::Duration::from_secs(60));
        let first = store
            .store(SensitiveKind::Email, "alice@example.org")
            .expect("store");
        let second = store
            .store(SensitiveKind::Email, "alice@example.org")
            .expect("store");
        assert_eq!(first, second);
        assert_eq!(
            store
                .resolve(SensitiveKind::Email, &first)
                .expect("resolve")
                .as_deref(),
            Some("alice@example.org")
        );
    }

    #[test]
    fn session_store_differs_across_sessions() {
        let first = SessionStore::new(std::time::Duration::from_secs(60))
            .store(SensitiveKind::Phone, "+1 (415) 555-0123")
            .expect("store");
        let second = SessionStore::new(std::time::Duration::from_secs(60))
            .store(SensitiveKind::Phone, "+1 (415) 555-0123")
            .expect("store");
        assert_ne!(first, second);
    }

    #[test]
    fn luhn_validation_accepts_a_known_card() {
        assert!(luhn_valid("4111111111111111"));
        assert_eq!(card_issuer("4111111111111111"), "visa");
        assert!(normalize_card_candidate("4111 1111 1111 1111").is_some());
    }

    #[test]
    fn detect_sensitive_finds_typed_candidates() {
        let cfg = SensitiveDataConfig {
            passwords_enabled: true,
            emails_enabled: true,
            phones_enabled: true,
            national_ids_enabled: true,
            passports_enabled: true,
            payment_cards_enabled: true,
            cvv_enabled: true,
            session_ttl: std::time::Duration::from_secs(60),
        };
        let matches = detect_sensitive(
            "password=\"S3cret!\"\nemail=alice@company.dev\nphone=+1 (415) 555-0123\nssn=123-45-6788\npassport: X1234567\ncard=4111 1111 1111 1111\ncvv=123",
            &cfg,
            None,
        )
        .expect("detect");

        assert!(matches.iter().any(|m| m.kind == SensitiveKind::Password));
        assert!(matches.iter().any(|m| m.kind == SensitiveKind::Email));
        assert!(matches.iter().any(|m| m.kind == SensitiveKind::Phone));
        assert!(matches.iter().any(|m| m.kind == SensitiveKind::NationalId));
        assert!(matches.iter().any(|m| m.kind == SensitiveKind::Passport));
        assert!(matches.iter().any(|m| m.kind == SensitiveKind::PaymentCard));
        assert!(matches.iter().any(|m| m.kind == SensitiveKind::Cvv));
        assert!(
            matches
                .iter()
                .all(|m| m.policy == ProtectionPolicy::ReversibleSession)
        );
    }

    struct DenyClassifier;

    impl LocalClassifier for DenyClassifier {
        fn accept(
            &self,
            _candidate: &super::ClassificationCandidate,
        ) -> Result<bool, KeyclawError> {
            Ok(false)
        }
    }

    #[test]
    fn classifier_can_filter_ambiguous_matches() {
        let cfg = SensitiveDataConfig {
            phones_enabled: true,
            ..SensitiveDataConfig::default()
        };
        let matches = detect_sensitive("Call me at +1 (415) 555-0123", &cfg, Some(&DenyClassifier))
            .expect("detect");
        assert!(matches.is_empty(), "{matches:?}");
    }

    #[test]
    fn local_classifier_config_requires_model_and_endpoint() {
        let cfg = LocalClassifierConfig::default();
        assert!(!cfg.is_enabled());
        let cfg = LocalClassifierConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:8000/v1/chat/completions".to_string(),
            model: "Qwen3.5-0.8B".to_string(),
            timeout: std::time::Duration::from_secs(3),
        };
        assert!(cfg.is_enabled());
        let _ = OpenAiCompatibleLocalClassifier::from_config(&cfg).expect("classifier");
    }
}
