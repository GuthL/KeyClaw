use std::sync::Arc;

use crate::config::Config;
use crate::entropy::EntropyConfig;
use crate::errors::KeyclawError;
use crate::pipeline::Processor;
use crate::sensitive::{DetectionEngine, OpenAiCompatibleLocalClassifier, SessionStore};

pub(crate) fn configure_unsafe_logging(cfg: &Config) {
    crate::proxy::set_unsafe_log(cfg.unsafe_log);
    if cfg.unsafe_log {
        crate::logging::warn("unsafe logging enabled; secrets may appear in logs");
    }
}

pub(crate) fn build_processor(cfg: &Config) -> Result<Arc<Processor>, KeyclawError> {
    let entropy_config = EntropyConfig {
        enabled: cfg.entropy_enabled,
        threshold: cfg.entropy_threshold,
        min_len: cfg.entropy_min_len,
    };

    crate::logging::info("opaque-token detection enabled");
    if cfg.dry_run {
        crate::logging::info("dry-run enabled; traffic will be scanned but not rewritten");
    }
    let hooks = if cfg.hooks.is_empty() {
        None
    } else {
        Some(Arc::new(crate::hooks::HookRunner::new(cfg.hooks.clone())))
    };
    let session_store = Arc::new(SessionStore::new(cfg.sensitive_data.session_ttl));
    let local_classifier = if cfg.local_classifier.is_enabled() {
        Some(Arc::new(OpenAiCompatibleLocalClassifier::from_config(
            &cfg.local_classifier,
        )?) as Arc<dyn crate::sensitive::LocalClassifier>)
    } else {
        None
    };
    let engine = Arc::new(DetectionEngine::new(
        cfg.sensitive_data.clone(),
        entropy_config,
        cfg.allowlist.clone(),
        local_classifier,
    ));

    Ok(Arc::new(Processor::new(
        engine,
        session_store,
        cfg.max_body_bytes,
        cfg.fail_closed,
        cfg.notice_mode,
        cfg.dry_run,
        hooks,
    )))
}

#[cfg(test)]
pub(super) fn test_detection_engine(cfg: &Config) -> DetectionEngine {
    DetectionEngine::new(
        cfg.sensitive_data.clone(),
        EntropyConfig {
            enabled: cfg.entropy_enabled,
            threshold: cfg.entropy_threshold,
            min_len: cfg.entropy_min_len,
        },
        crate::allowlist::Allowlist::default(),
        None,
    )
}
