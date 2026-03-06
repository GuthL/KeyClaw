use std::sync::Arc;

use crate::errors::{
    KeyclawError, CODE_BODY_TOO_LARGE, CODE_INVALID_JSON,
};
use crate::placeholder::{self, Replacement};
use crate::policy::{Action, Decision, Executor};
use crate::redaction;
use crate::vault::Store;

#[derive(Clone)]
pub struct Processor {
    pub vault: Option<Arc<Store>>,
    pub policy: Option<Arc<Executor>>,
    pub max_body_size: i64,
    pub strict_mode: bool,
}

#[derive(Debug, Clone)]
pub struct RewriteResult {
    pub body: Vec<u8>,
    pub replacements: Vec<Replacement>,
    pub decision: Decision,
}

impl Processor {
    pub fn rewrite_and_evaluate(&self, body: &[u8]) -> Result<RewriteResult, KeyclawError> {
        if self.max_body_size > 0 && (body.len() as i64) > self.max_body_size {
            return Err(KeyclawError::coded(
                CODE_BODY_TOO_LARGE,
                "request body exceeds max body size",
            ));
        }

        let mut replacements: Vec<Replacement> = Vec::new();
        let rewritten = redaction::walk_json_strings(body, |s| {
            let (out, reps) = placeholder::replace_secrets(s, |secret| {
                if let Some(vault) = &self.vault {
                    vault.store_secret(secret)
                } else {
                    Ok(placeholder::make_id(secret))
                }
            })?;
            replacements.extend(reps);
            Ok(out)
        })
        .map_err(|e| KeyclawError::coded_with_source(CODE_INVALID_JSON, "rewrite failed", e))?;

        let rewritten = redaction::inject_contract_marker(&rewritten).map_err(|e| {
            KeyclawError::coded_with_source(
                CODE_INVALID_JSON,
                "contract marker injection failed",
                e,
            )
        })?;

        // Inject a notice telling the LLM that secrets were redacted
        let rewritten = if !replacements.is_empty() {
            redaction::inject_redaction_notice(&rewritten, replacements.len()).unwrap_or(rewritten)
        } else {
            rewritten
        };

        let mut decision = Decision::allow();
        if let Some(policy) = &self.policy {
            decision = policy.evaluate(&rewritten);
            if decision.action == Action::Warn && !decision.findings.is_empty() {
                eprintln!(
                    "keyclaw [WARN] policy found {} finding(s) after rewrite (secrets already replaced)",
                    decision.findings.len()
                );
            }
        }

        Ok(RewriteResult {
            body: rewritten,
            replacements,
            decision,
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
        if !text.contains("{{KEYCLAW_SECRET_") {
            return Ok(body.to_vec());
        }

        let resolved = crate::placeholder::resolve_placeholders(&text, false, |id| vault.resolve(id))?;
        Ok(resolved.into_bytes())
    }

    pub fn replacement_summary(&self, replacements: &[Replacement]) -> String {
        if replacements.is_empty() {
            "no replacements".to_string()
        } else {
            format!("replaced {} secrets", replacements.len())
        }
    }
}
