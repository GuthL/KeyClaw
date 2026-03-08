use std::path::Path;

use regex::Regex;
use serde::Deserialize;

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
}

/// All compiled gitleaks rules.
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub skipped_rules: usize,
    pub entropy_config: EntropyConfig,
}

// ── TOML deserialization shapes ──────────────────────────────

#[derive(Deserialize)]
struct TomlConfig {
    #[serde(default)]
    rules: Vec<TomlRule>,
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

        for r in config.rules {
            if r.regex.is_empty() {
                skipped += 1;
                continue;
            }
            match regex::RegexBuilder::new(&r.regex)
                .size_limit(50 * 1024 * 1024)
                .build()
            {
                Ok(compiled) => {
                    rules.push(Rule {
                        id: r.id,
                        regex: compiled,
                        keywords: r.keywords.iter().map(|k| k.to_lowercase()).collect(),
                        secret_group: r.secret_group.unwrap_or(0),
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
        })
    }

    /// Return the bundled default rules (compiled into the binary).
    pub fn bundled() -> Result<Self, KeyclawError> {
        Self::from_toml(include_str!("../gitleaks.toml"))
    }

    /// Find all secret matches in `input`, returning (rule_id, start, end, secret).
    /// Matches inside existing placeholders are skipped.
    pub fn find_secrets<'a>(&'a self, input: &'a str) -> Vec<SecretMatch<'a>> {
        let mut matches: Vec<SecretMatch<'a>> = Vec::new();
        let input_lower = input.to_lowercase();

        for rule in &self.rules {
            // Fast keyword pre-filter: skip rule if none of its keywords appear
            if !rule.keywords.is_empty() && !rule.keywords.iter().any(|kw| input_lower.contains(kw))
            {
                continue;
            }

            for caps in rule.regex.captures_iter(input) {
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

                // Skip if this range overlaps with an already-found match
                if matches.iter().any(|m| m.start < end && start < m.end) {
                    continue;
                }

                // Skip if inside an existing placeholder
                if inside_placeholder(input, start, end) {
                    continue;
                }

                matches.push(SecretMatch {
                    rule_id: &rule.id,
                    start,
                    end,
                    secret,
                });
            }
        }

        // Entropy-based detection pass
        if self.entropy_config.enabled {
            for em in crate::entropy::find_high_entropy_tokens(
                input,
                self.entropy_config.min_len,
                self.entropy_config.threshold,
            ) {
                // Skip if overlaps with an existing regex match
                if matches.iter().any(|m| m.start < em.end && em.start < m.end) {
                    continue;
                }
                // Skip if inside an existing placeholder
                if inside_placeholder(input, em.start, em.end) {
                    continue;
                }
                matches.push(SecretMatch {
                    rule_id: ENTROPY_RULE_ID,
                    start: em.start,
                    end: em.end,
                    secret: em.token,
                });
            }
        }

        // Sort by position for stable replacement order
        matches.sort_by_key(|m| m.start);
        matches
    }
}

pub struct SecretMatch<'a> {
    pub rule_id: &'a str,
    pub start: usize,
    pub end: usize,
    pub secret: &'a str,
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

#[cfg(test)]
mod tests {
    use super::RuleSet;
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
        };
        let input = "token=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
        let matches = rules.find_secrets(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn bundled_rules_load_without_skips() {
        let rules = RuleSet::bundled().expect("bundled rules");
        assert_eq!(
            rules.skipped_rules, 0,
            "bundled rules should not contain invalid or unsupported entries"
        );
    }
}
