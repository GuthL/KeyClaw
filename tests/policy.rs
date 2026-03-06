use std::sync::Arc;

use keyclaw::detector::{Detector, Finding, Severity};
use keyclaw::policy::{Action, Executor, Mode};

#[derive(Clone)]
struct StubDetector {
    findings: Vec<Finding>,
    err: Option<keyclaw::errors::KeyclawError>,
}

impl Detector for StubDetector {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn detect(&self, _payload: &[u8]) -> Result<Vec<Finding>, keyclaw::errors::KeyclawError> {
        if let Some(err) = &self.err {
            return Err(err.clone());
        }
        Ok(self.findings.clone())
    }
}

#[test]
fn policy_findings_warn_not_block() {
    let exec = Executor::new(
        Some(Arc::new(StubDetector {
            findings: vec![Finding {
                detector: "primary".to_string(),
                rule_id: "r".to_string(),
                message: "m".to_string(),
                secret: "s".to_string(),
                severity: Severity::High,
            }],
            err: None,
        })),
        None,
        Mode::Warn,
        true,
    );

    // Findings warn but never block — secrets are replaced by the rewrite step
    let decision = exec.evaluate(b"{}");
    assert_eq!(decision.action, Action::Warn);
    assert_eq!(decision.findings.len(), 1);
}

#[test]
fn policy_fallback_on_primary_failure() {
    let primary = Arc::new(StubDetector {
        findings: vec![],
        err: Some(keyclaw::errors::KeyclawError::coded(
            keyclaw::errors::CODE_GITLEAKS_UNAVAILABLE,
            "missing",
        )),
    });

    let fallback = Arc::new(StubDetector {
        findings: vec![Finding {
            detector: "embedded".to_string(),
            rule_id: "rule".to_string(),
            message: "desc".to_string(),
            secret: "abc".to_string(),
            severity: Severity::Medium,
        }],
        err: None,
    });

    let exec = Executor::new(Some(primary), Some(fallback), Mode::Warn, true);
    let decision = exec.evaluate(b"{}");

    assert_eq!(decision.action, Action::Warn);
}

#[test]
fn policy_fail_closed_when_all_detectors_fail() {
    let failing = || {
        Arc::new(StubDetector {
            findings: vec![],
            err: Some(keyclaw::errors::KeyclawError::coded(
                keyclaw::errors::CODE_GITLEAKS_UNAVAILABLE,
                "down",
            )),
        })
    };

    let exec = Executor::new(Some(failing()), Some(failing()), Mode::Warn, true);
    let decision = exec.evaluate(b"{}");

    assert_eq!(decision.action, Action::Block);
    assert_eq!(
        decision.reason_code.as_deref(),
        Some(keyclaw::errors::CODE_BLOCKED_BY_LEAK_POLICY)
    );
}
