use std::sync::Arc;

use crate::config::Config;
use crate::entropy::EntropyConfig;
use crate::errors::KeyclawError;
use crate::gitleaks_rules::RuleSet;
use crate::pipeline::Processor;
use crate::vault::Store;

pub(crate) fn configure_unsafe_logging(cfg: &Config) {
    crate::proxy::set_unsafe_log(cfg.unsafe_log);
    if cfg.unsafe_log {
        crate::logging::warn("unsafe logging enabled; secrets may appear in logs");
    }
}

pub(crate) fn build_processor(cfg: &Config) -> Result<Arc<Processor>, KeyclawError> {
    let passphrase =
        crate::vault::resolve_vault_passphrase(&cfg.vault_path, cfg.vault_passphrase.as_deref())?;
    let vault = Arc::new(Store::new(cfg.vault_path.clone(), passphrase));

    let mut ruleset = load_runtime_ruleset(cfg)?;
    ruleset.entropy_config = EntropyConfig {
        enabled: cfg.entropy_enabled,
        threshold: cfg.entropy_threshold,
        min_len: cfg.entropy_min_len,
    };
    ruleset.allowlist = cfg.allowlist.clone();

    crate::logging::info(&format!("{} gitleaks rules loaded", ruleset.rules.len()));
    if cfg.dry_run {
        crate::logging::info("dry-run enabled; traffic will be scanned but not rewritten");
    }

    Ok(Arc::new(Processor {
        vault: Some(vault),
        ruleset: Arc::new(ruleset),
        max_body_size: cfg.max_body_bytes,
        strict_mode: cfg.fail_closed,
        notice_mode: cfg.notice_mode,
        dry_run: cfg.dry_run,
    }))
}

pub(super) fn load_runtime_ruleset(cfg: &Config) -> Result<RuleSet, KeyclawError> {
    match cfg.gitleaks_config_path.as_deref() {
        Some(path) => match RuleSet::from_file(path) {
            Ok(ruleset) => {
                if ruleset.skipped_rules > 0 {
                    crate::logging::warn(&format!(
                        "loaded {} custom gitleaks rules from {}, skipped {} invalid rule(s)",
                        ruleset.rules.len(),
                        path.display(),
                        ruleset.skipped_rules
                    ));
                }
                Ok(ruleset)
            }
            Err(err) => {
                crate::logging::warn(&format!(
                    "failed to load custom rules from {}: {err}",
                    path.display()
                ));
                crate::logging::warn("falling back to bundled rules");
                load_bundled_ruleset()
            }
        },
        None => load_bundled_ruleset(),
    }
}

pub(super) fn load_bundled_ruleset() -> Result<RuleSet, KeyclawError> {
    let ruleset = RuleSet::bundled()
        .map_err(|err| KeyclawError::uncoded(format!("load bundled gitleaks rules: {err}")))?;
    if ruleset.skipped_rules > 0 {
        crate::logging::info(&format!(
            "loaded {} bundled gitleaks rules, skipped {} invalid rule(s)",
            ruleset.rules.len(),
            ruleset.skipped_rules
        ));
    }
    Ok(ruleset)
}
