use std::sync::Arc;

use serde_json::Value;

use crate::errors::{
    KeyclawError, CODE_BODY_TOO_LARGE, CODE_INVALID_JSON, CODE_STRICT_RESOLVE_FAILED,
};
use crate::gitleaks_rules::RuleSet;
use crate::placeholder::{self, Replacement};
use crate::redaction;
use crate::vault::Store;

#[derive(Clone)]
pub struct Processor {
    pub vault: Option<Arc<Store>>,
    pub ruleset: Arc<RuleSet>,
    pub max_body_size: i64,
    pub strict_mode: bool,
    pub notice_mode: redaction::NoticeMode,
}

#[derive(Debug, Clone)]
pub struct RewriteResult {
    pub body: Vec<u8>,
    pub replacements: Vec<Replacement>,
}

impl Processor {
    pub fn warm_up(&self) -> Result<(), KeyclawError> {
        if let Some(vault) = &self.vault {
            vault.warm_up()?;
        }
        Ok(())
    }

    pub fn rewrite_and_evaluate(&self, body: &[u8]) -> Result<RewriteResult, KeyclawError> {
        self.rewrite_json_messages(body, |body, rewrite| {
            redaction::walk_message_content(body, |text| rewrite(text))
        })
    }

    pub fn rewrite_and_evaluate_input_only(
        &self,
        body: &[u8],
    ) -> Result<RewriteResult, KeyclawError> {
        self.rewrite_json_messages(body, |body, rewrite| {
            redaction::walk_input_message_content(body, |text| rewrite(text))
        })
    }

    pub fn rewrite_and_evaluate_codex_ws(
        &self,
        body: &[u8],
    ) -> Result<RewriteResult, KeyclawError> {
        self.ensure_body_within_limit(body.len())?;

        let ruleset = &self.ruleset;
        let mut parsed: Value = serde_json::from_slice(body)
            .map_err(|e| KeyclawError::coded_with_source(CODE_INVALID_JSON, "rewrite failed", e))?;
        let mut replacements = Vec::new();
        let mut notice_replacements = 0usize;

        if let Some(obj) = parsed.as_object_mut() {
            for key in ["input", "messages"] {
                if let Some(arr) = obj.get_mut(key).and_then(Value::as_array_mut) {
                    let last_user_index = arr.iter().rposition(is_user_message);
                    for (idx, item) in arr.iter_mut().enumerate() {
                        let before = replacements.len();
                        redaction::rewrite_message_content_fields(item, &mut |s| {
                            let (rewritten, reps) =
                                rewrite_string(s, ruleset, self.vault.as_ref())?;
                            replacements.extend(reps);
                            Ok(rewritten)
                        })?;
                        if Some(idx) == last_user_index {
                            notice_replacements += replacements.len() - before;
                        }
                    }
                }
            }
        }

        let rewritten = serde_json::to_vec(&parsed)
            .map_err(|e| KeyclawError::coded_with_source(CODE_INVALID_JSON, "rewrite failed", e))?;

        self.finalize_rewrite_with_notice_count(rewritten, replacements, notice_replacements)
    }

    fn finalize_rewrite(
        &self,
        rewritten: Vec<u8>,
        replacements: Vec<Replacement>,
    ) -> Result<RewriteResult, KeyclawError> {
        let notice_count = replacements.len();
        self.finalize_rewrite_with_notice_count(rewritten, replacements, notice_count)
    }

    fn finalize_rewrite_with_notice_count(
        &self,
        rewritten: Vec<u8>,
        replacements: Vec<Replacement>,
        notice_count: usize,
    ) -> Result<RewriteResult, KeyclawError> {
        let rewritten = redaction::inject_contract_marker(&rewritten).map_err(|e| {
            KeyclawError::coded_with_source(
                CODE_INVALID_JSON,
                "contract marker injection failed",
                e,
            )
        })?;

        // Inject a notice telling the LLM that secrets were redacted
        let rewritten = if notice_count > 0
            && !matches!(self.notice_mode, redaction::NoticeMode::Off)
        {
            redaction::inject_redaction_notice_with_mode(&rewritten, notice_count, self.notice_mode)
                .unwrap_or(rewritten)
        } else {
            rewritten
        };

        Ok(RewriteResult {
            body: rewritten,
            replacements,
        })
    }

    pub fn resolve_json(&self, body: &[u8]) -> Result<Vec<u8>, KeyclawError> {
        let Some(vault) = &self.vault else {
            return Ok(body.to_vec());
        };

        let resolved =
            redaction::resolve_json_placeholders(body, self.strict_mode, |id| vault.resolve(id));

        match resolved {
            Ok(value) => Ok(value),
            Err(e) if self.strict_mode => Err(e),
            Err(_) => Ok(body.to_vec()),
        }
    }

    pub fn resolve_text(&self, body: &[u8]) -> Result<Vec<u8>, KeyclawError> {
        let Some(vault) = &self.vault else {
            return Ok(body.to_vec());
        };

        let text = String::from_utf8_lossy(body);
        if !crate::placeholder::contains_placeholder_prefix(&text) {
            return Ok(body.to_vec());
        }

        match crate::placeholder::resolve_placeholders(&text, self.strict_mode, |id| {
            vault.resolve(id)
        }) {
            Ok(resolved) => Ok(resolved.into_bytes()),
            Err(err) if self.strict_mode => Err(KeyclawError::coded_with_source(
                CODE_STRICT_RESOLVE_FAILED,
                "strict text placeholder resolution failed",
                err,
            )),
            Err(_) => Ok(body.to_vec()),
        }
    }

    pub fn replacement_summary(&self, replacements: &[Replacement]) -> String {
        if replacements.is_empty() {
            "no replacements".to_string()
        } else {
            format!("replaced {} secrets", replacements.len())
        }
    }

    fn rewrite_json_messages<F>(&self, body: &[u8], walk: F) -> Result<RewriteResult, KeyclawError>
    where
        F: for<'a> FnOnce(
            &[u8],
            &'a mut dyn FnMut(&str) -> Result<String, KeyclawError>,
        ) -> Result<Vec<u8>, KeyclawError>,
    {
        self.ensure_body_within_limit(body.len())?;

        let mut replacements: Vec<Replacement> = Vec::new();
        let mut rewrite = |input: &str| {
            let (rewritten, reps) = rewrite_string(input, &self.ruleset, self.vault.as_ref())?;
            replacements.extend(reps);
            Ok(rewritten)
        };
        let rewritten = walk(body, &mut rewrite)
            .map_err(|e| KeyclawError::coded_with_source(CODE_INVALID_JSON, "rewrite failed", e))?;

        self.finalize_rewrite(rewritten, replacements)
    }

    fn ensure_body_within_limit(&self, body_len: usize) -> Result<(), KeyclawError> {
        if self.max_body_size > 0 && (body_len as i64) > self.max_body_size {
            Err(KeyclawError::coded(
                CODE_BODY_TOO_LARGE,
                "request body exceeds max body size",
            ))
        } else {
            Ok(())
        }
    }
}

fn is_user_message(item: &Value) -> bool {
    item.as_object()
        .and_then(|obj| obj.get("role"))
        .and_then(Value::as_str)
        == Some("user")
}

fn rewrite_string(
    input: &str,
    ruleset: &RuleSet,
    vault: Option<&Arc<Store>>,
) -> Result<(String, Vec<Replacement>), KeyclawError> {
    placeholder::replace_secrets(input, ruleset, |secret| {
        if let Some(vault) = vault {
            vault.store_secret(secret)
        } else {
            Ok(placeholder::make_id(secret))
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::Processor;
    use crate::errors::{code_of, CODE_BODY_TOO_LARGE};
    use crate::gitleaks_rules::RuleSet;

    fn processor_with_limit(max_body_size: i64) -> Processor {
        Processor {
            vault: None,
            ruleset: Arc::new(RuleSet {
                rules: Vec::new(),
                skipped_rules: 0,
            }),
            max_body_size,
            strict_mode: true,
            notice_mode: crate::redaction::NoticeMode::Verbose,
        }
    }

    #[test]
    fn ensure_body_within_limit_uses_shared_body_too_large_error() {
        let processor = processor_with_limit(4);

        let err = processor
            .ensure_body_within_limit(5)
            .expect_err("limit should reject oversized bodies");

        assert_eq!(code_of(&err), Some(CODE_BODY_TOO_LARGE));
    }
}
