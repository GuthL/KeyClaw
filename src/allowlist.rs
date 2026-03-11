use std::collections::HashSet;

use regex::{Regex, RegexBuilder};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    rule_ids: HashSet<String>,
    patterns: Vec<Regex>,
    secret_sha256: HashSet<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllowlistCounts {
    pub rule_ids: usize,
    pub patterns: usize,
    pub secret_sha256: usize,
}

impl Allowlist {
    pub fn from_parts(
        rule_ids: &[String],
        patterns: &[String],
        secret_sha256: &[String],
    ) -> Result<Self, String> {
        let mut out = Self::default();

        for rule_id in rule_ids {
            let normalized = rule_id.trim().to_ascii_lowercase();
            if !normalized.is_empty() {
                out.rule_ids.insert(normalized);
            }
        }

        for (idx, pattern) in patterns.iter().enumerate() {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                continue;
            }
            let compiled = RegexBuilder::new(trimmed)
                .size_limit(1024 * 1024)
                .build()
                .map_err(|err| format!("allowlist.patterns[{idx}] is invalid: {err}"))?;
            out.patterns.push(compiled);
        }

        for (idx, hash) in secret_sha256.iter().enumerate() {
            let normalized = hash.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                continue;
            }
            if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!(
                    "allowlist.secret_sha256[{idx}] must be a 64-character hex sha256 digest"
                ));
            }
            out.secret_sha256.insert(normalized);
        }

        Ok(out)
    }

    pub fn allows(&self, rule_id: &str, secret: &str) -> bool {
        self.rule_ids.contains(&rule_id.trim().to_ascii_lowercase())
            || self.patterns.iter().any(|pattern| pattern.is_match(secret))
            || self
                .secret_sha256
                .contains(&hex::encode(Sha256::digest(secret.as_bytes())))
    }

    pub fn counts(&self) -> AllowlistCounts {
        AllowlistCounts {
            rule_ids: self.rule_ids.len(),
            patterns: self.patterns.len(),
            secret_sha256: self.secret_sha256.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rule_ids.is_empty() && self.patterns.is_empty() && self.secret_sha256.is_empty()
    }
}

impl AllowlistCounts {
    pub fn total(self) -> usize {
        self.rule_ids + self.patterns + self.secret_sha256
    }
}

#[cfg(test)]
mod tests {
    use super::Allowlist;
    use sha2::Digest;

    #[test]
    fn allows_by_rule_id_pattern_and_hash() {
        let allowlist = Allowlist::from_parts(
            &["opaque.high_entropy".to_string()],
            &["^sk-test-".to_string()],
            &[hex::encode(sha2::Sha256::digest(b"exact-secret-value"))],
        )
        .expect("allowlist");

        assert!(allowlist.allows("opaque.high_entropy", "ignored"));
        assert!(allowlist.allows("other-rule", "sk-test-123"));
        assert!(allowlist.allows("other-rule", "exact-secret-value"));
        assert!(!allowlist.allows("other-rule", "real-secret"));
    }

    #[test]
    fn rejects_invalid_secret_hashes() {
        let err = Allowlist::from_parts(&[], &[], &["abc".to_string()]).expect_err("hash error");

        assert!(err.contains("allowlist.secret_sha256[0]"));
    }
}
