use std::collections::HashSet;
use std::path::Path;

use regex::{Regex, RegexBuilder};
use serde::Deserialize;

use crate::allowlist::Allowlist;
use crate::entropy::EntropyConfig;
use crate::errors::KeyclawError;

const ENTROPY_RULE_ID: &str = "entropy";

/// A single compiled gitleaks rule ready for matching.
pub struct Rule {
    pub id: String,
    pub regex: Regex,
    pub keywords: Vec<String>,
    /// Which capture group holds the secret (0 = full match).
    pub secret_group: usize,
    /// Minimum Shannon entropy for the matched secret. If set,
    /// matches below this threshold are discarded as likely false positives.
    pub min_entropy: Option<f64>,
    allowlists: Vec<CompiledAllowlist>,
    stopwords: HashSet<String>,
    specificity: RuleSpecificity,
}

/// All compiled gitleaks rules.
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub skipped_rules: usize,
    pub entropy_config: EntropyConfig,
    pub allowlist: Allowlist,
    global_allowlists: Vec<CompiledAllowlist>,
    global_stopwords: HashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchSource {
    Regex,
    Entropy,
}

impl MatchSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Entropy => "entropy",
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
    fn from_score(score: u8) -> Self {
        match score {
            80..=u8::MAX => Self::High,
            60..=79 => Self::Medium,
            _ => Self::Low,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleSpecificity {
    Generic,
    Specific,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllowlistRegexTarget {
    Secret,
    Match,
}

#[derive(Debug)]
struct CompiledAllowlist {
    regexes: Vec<Regex>,
    target: AllowlistRegexTarget,
    stopwords: HashSet<String>,
}

// ── TOML deserialization shapes ──────────────────────────────

#[derive(Default, Deserialize)]
struct TomlConfig {
    #[serde(default)]
    rules: Vec<TomlRule>,
    #[serde(default)]
    allowlist: TomlAllowlist,
}

#[derive(Deserialize)]
struct TomlRule {
    id: String,
    #[serde(default)]
    regex: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default, rename = "secretGroup")]
    secret_group: Option<usize>,
    #[serde(default)]
    entropy: Option<f64>,
    #[serde(default)]
    allowlists: Vec<TomlAllowlist>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(default)]
    path: String,
}

#[derive(Default, Deserialize)]
struct TomlAllowlist {
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(default, rename = "regexTarget")]
    regex_target: Option<String>,
}

// ── Loading ──────────────────────────────────────────────────

impl RuleSet {
    /// Load and compile rules from a gitleaks.toml file.
    pub fn from_file(path: &Path) -> Result<Self, KeyclawError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| KeyclawError::uncoded(format!("read {}: {e}", path.display())))?;
        Self::from_toml(&content)
    }

    /// Load and compile rules from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, KeyclawError> {
        let config: TomlConfig = toml::from_str(toml_str)
            .map_err(|e| KeyclawError::uncoded(format!("parse gitleaks.toml: {e}")))?;

        let mut rules = Vec::with_capacity(config.rules.len());
        let mut skipped = 0usize;
        let global_allowlists =
            compile_allowlists(&config.allowlist).map_err(KeyclawError::uncoded)?;
        let global_stopwords = normalize_stopwords(&config.allowlist.stopwords);

        for r in config.rules {
            if r.regex.is_empty() || !r.path.trim().is_empty() {
                skipped += 1;
                continue;
            }
            match RegexBuilder::new(&r.regex)
                .size_limit(50 * 1024 * 1024)
                .build()
            {
                Ok(compiled) => {
                    let allowlists = match compile_rule_allowlists(&r.allowlists) {
                        Ok(allowlists) => allowlists,
                        Err(_) => {
                            skipped += 1;
                            continue;
                        }
                    };
                    rules.push(Rule {
                        specificity: rule_specificity(&r.id),
                        id: r.id,
                        regex: compiled,
                        keywords: r.keywords.iter().map(|k| k.to_lowercase()).collect(),
                        secret_group: r.secret_group.unwrap_or(0),
                        min_entropy: r.entropy,
                        allowlists,
                        stopwords: normalize_stopwords(&r.stopwords),
                    });
                }
                Err(_) => {
                    skipped += 1;
                }
            }
        }

        Ok(RuleSet {
            rules,
            skipped_rules: skipped,
            entropy_config: EntropyConfig::default(),
            allowlist: Allowlist::default(),
            global_allowlists,
            global_stopwords,
        })
    }

    /// Return the bundled default rules (compiled into the binary).
    pub fn bundled() -> Result<Self, KeyclawError> {
        Self::from_toml(include_str!("../gitleaks.toml"))
    }

    /// Find all secret matches in `input`, returning (rule_id, start, end, secret).
    /// Matches inside existing placeholders are skipped.
    pub fn find_secrets<'a>(&'a self, input: &'a str) -> Vec<SecretMatch<'a>> {
        self.find_secrets_with_options(input, true)
    }

    pub fn find_secrets_with_options<'a>(
        &'a self,
        input: &'a str,
        include_entropy: bool,
    ) -> Vec<SecretMatch<'a>> {
        let mut candidates: Vec<SecretMatch<'a>> = Vec::new();
        let mut input_lower: Option<String> = None;

        for rule in &self.rules {
            // Fast keyword pre-filter: skip rule if none of its keywords appear
            if !rule.keywords.is_empty() {
                let input_lower = input_lower.get_or_insert_with(|| input.to_ascii_lowercase());
                if !rule.keywords.iter().any(|kw| input_lower.contains(kw)) {
                    continue;
                }
            }

            for caps in rule.regex.captures_iter(input) {
                let full_match = caps.get(0).unwrap();
                let secret_match = if rule.secret_group > 0 {
                    caps.get(rule.secret_group)
                        .unwrap_or_else(|| caps.get(0).unwrap())
                } else {
                    caps.get(0).unwrap()
                };

                let start = secret_match.start();
                let end = secret_match.end();
                let secret = secret_match.as_str();

                // Skip very short matches
                if secret.len() < 8 {
                    continue;
                }

                // Skip if matched secret's entropy is below the rule's threshold
                let entropy = rule
                    .min_entropy
                    .map(|_| crate::entropy::shannon_entropy(secret));
                if let Some(min_entropy) = rule.min_entropy {
                    if entropy.unwrap_or_default() < min_entropy {
                        continue;
                    }
                }

                if self.should_allow_match(rule, secret, full_match.as_str()) {
                    continue;
                }

                // Skip if inside an existing placeholder
                if inside_placeholder(input, start, end) {
                    continue;
                }

                let confidence_score = score_regex_match(rule, secret, entropy);
                candidates.push(SecretMatch {
                    rule_id: &rule.id,
                    start,
                    end,
                    secret,
                    source: MatchSource::Regex,
                    confidence: MatchConfidence::from_score(confidence_score),
                    confidence_score,
                    entropy,
                });
            }
        }

        // Entropy-based detection pass
        if include_entropy && self.entropy_config.enabled {
            for em in crate::entropy::find_high_entropy_tokens(
                input,
                self.entropy_config.min_len,
                self.entropy_config.threshold,
            ) {
                // Skip if inside an existing placeholder
                if inside_placeholder(input, em.start, em.end) {
                    continue;
                }
                if self
                    .global_stopwords
                    .contains(&normalize_secret_key(em.token))
                {
                    continue;
                }
                if self.allowlist.allows(ENTROPY_RULE_ID, em.token) {
                    continue;
                }
                let confidence_score = score_entropy_match(em.token, em.entropy);
                candidates.push(SecretMatch {
                    rule_id: ENTROPY_RULE_ID,
                    start: em.start,
                    end: em.end,
                    secret: em.token,
                    source: MatchSource::Entropy,
                    confidence: MatchConfidence::from_score(confidence_score),
                    confidence_score,
                    entropy: Some(em.entropy),
                });
            }
        }

        select_best_matches(candidates)
    }

    fn should_allow_match(&self, rule: &Rule, secret: &str, matched: &str) -> bool {
        self.allowlist.allows(&rule.id, secret)
            || self
                .global_stopwords
                .contains(&normalize_secret_key(secret))
            || rule.stopwords.contains(&normalize_secret_key(secret))
            || matches_allowlists(&self.global_allowlists, secret, matched)
            || matches_allowlists(&rule.allowlists, secret, matched)
    }
}

#[derive(Debug)]
pub struct SecretMatch<'a> {
    pub rule_id: &'a str,
    pub start: usize,
    pub end: usize,
    pub secret: &'a str,
    pub source: MatchSource,
    pub confidence: MatchConfidence,
    pub confidence_score: u8,
    pub entropy: Option<f64>,
}

impl SecretMatch<'_> {
    fn priority(&self) -> (u8, u8, usize) {
        let source_rank = match self.source {
            MatchSource::Regex => 2,
            MatchSource::Entropy => 1,
        };
        (self.confidence_score, source_rank, self.len())
    }

    fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
}

/// Check if a position in the input falls inside an existing placeholder.
fn inside_placeholder(input: &str, start: usize, end: usize) -> bool {
    let search_start = start.saturating_sub(crate::placeholder::MAX_PLACEHOLDER_LEN);
    for (rel, ch) in input[search_start..start].char_indices() {
        if ch != '{' {
            continue;
        }

        let abs_pos = search_start + rel;
        if let Some(len) = crate::placeholder::complete_placeholder_len(&input[abs_pos..]) {
            let placeholder_end = abs_pos + len;
            if abs_pos < end && start < placeholder_end {
                return true;
            }
        }
    }

    false
}

fn compile_rule_allowlists(raw: &[TomlAllowlist]) -> Result<Vec<CompiledAllowlist>, String> {
    raw.iter()
        .map(compile_allowlist)
        .filter_map(|result| match result {
            Ok(Some(allowlist)) => Some(Ok(allowlist)),
            Ok(None) => None,
            Err(_) => None,
        })
        .collect()
}

fn compile_allowlists(raw: &TomlAllowlist) -> Result<Vec<CompiledAllowlist>, String> {
    match compile_allowlist(raw)? {
        Some(allowlist) => Ok(vec![allowlist]),
        None => Ok(Vec::new()),
    }
}

fn compile_allowlist(raw: &TomlAllowlist) -> Result<Option<CompiledAllowlist>, String> {
    if raw.regexes.is_empty() && raw.stopwords.is_empty() {
        return Ok(None);
    }

    let target = match raw
        .regex_target
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("match") => AllowlistRegexTarget::Match,
        _ => AllowlistRegexTarget::Secret,
    };

    let mut regexes = Vec::with_capacity(raw.regexes.len());
    for pattern in &raw.regexes {
        if let Ok(compiled) = RegexBuilder::new(pattern)
            .size_limit(50 * 1024 * 1024)
            .build()
        {
            regexes.push(compiled);
        }
    }

    if regexes.is_empty() && raw.stopwords.is_empty() {
        return Ok(None);
    }

    Ok(Some(CompiledAllowlist {
        regexes,
        target,
        stopwords: normalize_stopwords(&raw.stopwords),
    }))
}

fn matches_allowlists(allowlists: &[CompiledAllowlist], secret: &str, matched: &str) -> bool {
    allowlists.iter().any(|allowlist| {
        if allowlist.stopwords.contains(&normalize_secret_key(secret)) {
            return true;
        }
        let candidate = match allowlist.target {
            AllowlistRegexTarget::Secret => secret,
            AllowlistRegexTarget::Match => matched,
        };
        allowlist
            .regexes
            .iter()
            .any(|regex| regex.is_match(candidate))
    })
}

fn normalize_stopwords(stopwords: &[String]) -> HashSet<String> {
    stopwords
        .iter()
        .map(|word| normalize_secret_key(word))
        .collect()
}

fn normalize_secret_key(secret: &str) -> String {
    secret.trim().to_ascii_lowercase()
}

fn rule_specificity(rule_id: &str) -> RuleSpecificity {
    if rule_id.trim().to_ascii_lowercase().starts_with("generic-") {
        RuleSpecificity::Generic
    } else {
        RuleSpecificity::Specific
    }
}

fn score_regex_match(rule: &Rule, secret: &str, entropy: Option<f64>) -> u8 {
    let mut score = match rule.specificity {
        RuleSpecificity::Specific => 88u8,
        RuleSpecificity::Generic => 66u8,
    };

    if let (Some(min_entropy), Some(entropy)) = (rule.min_entropy, entropy) {
        let bonus = ((entropy - min_entropy).max(0.0) * 8.0).round() as u8;
        score = score.saturating_add(bonus.min(10));
    }

    if secret.len() >= 32 {
        score = score.saturating_add(3);
    }

    score.min(99)
}

fn score_entropy_match(secret: &str, entropy: f64) -> u8 {
    let len_bonus = (secret.len() / 16).min(8) as u8;
    let entropy_bonus = ((entropy - 3.5).max(0.0) * 10.0).round() as u8;
    42u8.saturating_add(len_bonus)
        .saturating_add(entropy_bonus.min(12))
        .min(70)
}

fn select_best_matches<'a>(mut candidates: Vec<SecretMatch<'a>>) -> Vec<SecretMatch<'a>> {
    candidates.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.priority().cmp(&left.priority()))
    });

    let mut selected: Vec<SecretMatch<'a>> = Vec::new();

    'candidate: for candidate in candidates {
        let mut idx = 0usize;
        while idx < selected.len() {
            if selected[idx].start < candidate.end && candidate.start < selected[idx].end {
                if candidate.priority() > selected[idx].priority() {
                    selected.remove(idx);
                    continue;
                }
                continue 'candidate;
            }
            idx += 1;
        }
        selected.push(candidate);
    }

    selected.sort_by_key(|m| m.start);
    selected
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::RuleSet;
    use crate::allowlist::Allowlist;
    use crate::placeholder::make;

    #[test]
    fn find_secrets_skips_real_placeholders_but_not_marker_shaped_invalid_text() {
        let rules = RuleSet::from_toml(
            r#"
[[rules]]
id = "placeholder-hash"
regex = '[a-f0-9]{16}'
"#,
        )
        .expect("ruleset");

        let valid = format!("prefix {}", make("*_0123456789abcdef"));
        let invalid = "prefix {{KEYCLAW_SECRET_prefixx_0123456789abcdef}}";

        assert!(
            rules.find_secrets(&valid).is_empty(),
            "valid placeholder should be ignored"
        );
        assert_eq!(
            rules.find_secrets(invalid).len(),
            1,
            "invalid marker-shaped text should still be scanned"
        );
    }

    #[test]
    fn find_secrets_includes_entropy_matches() {
        use crate::entropy::EntropyConfig;
        let rules = RuleSet {
            rules: Vec::new(),
            skipped_rules: 0,
            entropy_config: EntropyConfig::default(),
            allowlist: Allowlist::default(),
            global_allowlists: Vec::new(),
            global_stopwords: HashSet::new(),
        };
        let input = "token=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
        let matches = rules.find_secrets(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "entropy");
        assert_eq!(matches[0].secret, "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v");
    }

    #[test]
    fn find_secrets_entropy_disabled() {
        use crate::entropy::EntropyConfig;
        let rules = RuleSet {
            rules: Vec::new(),
            skipped_rules: 0,
            entropy_config: EntropyConfig {
                enabled: false,
                ..Default::default()
            },
            allowlist: Allowlist::default(),
            global_allowlists: Vec::new(),
            global_stopwords: HashSet::new(),
        };
        let input = "token=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
        let matches = rules.find_secrets(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn find_secrets_respects_per_rule_entropy_threshold() {
        // Rule requires entropy >= 3.0; a low-entropy match should be skipped
        let rules = RuleSet::from_toml(
            r#"
[[rules]]
id = "high-entropy-only"
regex = '[a-zA-Z0-9]{20,}'
entropy = 3.0
"#,
        )
        .expect("ruleset");

        // Low entropy: repeated pattern
        let low = "abcabcabcabcabcabcabcabc";
        assert!(
            rules.find_secrets(low).is_empty(),
            "low-entropy match should be filtered by per-rule threshold"
        );

        // High entropy: random-looking
        let high = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
        let matches = rules.find_secrets(high);
        assert_eq!(matches.len(), 1, "high-entropy match should pass threshold");
        assert_eq!(matches[0].rule_id, "high-entropy-only");
    }

    #[test]
    fn find_secrets_no_entropy_threshold_accepts_all_matches() {
        // Rule without entropy field — all matches accepted
        let rules = RuleSet::from_toml(
            r#"
[[rules]]
id = "no-threshold"
regex = '[a-zA-Z]{20,}'
"#,
        )
        .expect("ruleset");

        let input = "abcabcabcabcabcabcabcabc";
        let matches = rules.find_secrets(input);
        assert_eq!(
            matches.len(),
            1,
            "without entropy threshold, all matches pass"
        );
    }

    #[test]
    fn bundled_rules_parse_entropy_field() {
        let rules = RuleSet::bundled().expect("bundled rules");
        let with_entropy = rules
            .rules
            .iter()
            .filter(|r| r.min_entropy.is_some())
            .count();
        assert!(
            with_entropy >= 100,
            "expected at least 100 rules with entropy thresholds, found {with_entropy}"
        );
    }
    #[test]
    fn bundled_rules_report_unsupported_entries_as_skipped() {
        let rules = RuleSet::bundled().expect("bundled rules");
        assert!(
            rules.skipped_rules >= 1,
            "payload scanning should skip unsupported path-scoped entries"
        );
    }
}
