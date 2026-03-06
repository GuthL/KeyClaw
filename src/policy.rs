use std::sync::Arc;

use crate::detector::{Detector, Finding};
use crate::errors::{
    code_of, KeyclawError, CODE_BLOCKED_BY_LEAK_POLICY, CODE_GITLEAKS_UNAVAILABLE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Block,
    Warn,
}

impl Default for Mode {
    fn default() -> Self {
        Self::Block
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub findings: Vec<Finding>,
    pub reason_code: Option<String>,
    pub warning_code: Option<String>,
    pub err: Option<KeyclawError>,
}

impl Decision {
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            findings: Vec::new(),
            reason_code: None,
            warning_code: None,
            err: None,
        }
    }
}

#[allow(dead_code)]
pub struct Executor {
    primary: Option<Arc<dyn Detector>>,
    fallback: Option<Arc<dyn Detector>>,
    mode: Mode,
    fail_closed: bool,
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            primary: None,
            fallback: None,
            mode: Mode::Block,
            fail_closed: true,
        }
    }
}

impl Executor {
    pub fn new(
        primary: Option<Arc<dyn Detector>>,
        fallback: Option<Arc<dyn Detector>>,
        mode: Mode,
        fail_closed: bool,
    ) -> Self {
        Self {
            primary,
            fallback,
            mode,
            fail_closed,
        }
    }

    pub fn evaluate(&self, payload: &[u8]) -> Decision {
        if self.primary.is_none() && self.fallback.is_none() {
            if self.fail_closed {
                let err =
                    KeyclawError::coded(CODE_BLOCKED_BY_LEAK_POLICY, "no detectors configured");
                return Decision {
                    action: Action::Block,
                    findings: Vec::new(),
                    reason_code: Some(CODE_BLOCKED_BY_LEAK_POLICY.to_string()),
                    warning_code: None,
                    err: Some(err),
                };
            }
            return Decision::allow();
        }

        let primary_result = self.run_detector(self.primary.as_ref(), payload);
        let findings = match primary_result {
            Ok(findings) => findings,
            Err(primary_error) => {
                let fallback_result = self.run_detector(self.fallback.as_ref(), payload);
                match fallback_result {
                    Ok(fallback_findings) => {
                        let mut decision = self.from_findings(fallback_findings);
                        if decision.action == Action::Allow {
                            decision.warning_code = error_code(&primary_error);
                        }
                        return decision;
                    }
                    Err(_) => {
                        if self.fail_closed {
                            return Decision {
                                action: Action::Block,
                                findings: Vec::new(),
                                reason_code: Some(CODE_BLOCKED_BY_LEAK_POLICY.to_string()),
                                warning_code: error_code(&primary_error),
                                err: Some(KeyclawError::coded(
                                    CODE_BLOCKED_BY_LEAK_POLICY,
                                    "detector chain failed",
                                )),
                            };
                        }
                        return Decision {
                            action: Action::Warn,
                            findings: Vec::new(),
                            reason_code: None,
                            warning_code: error_code(&primary_error),
                            err: Some(primary_error),
                        };
                    }
                }
            }
        };

        self.from_findings(findings)
    }

    fn run_detector(
        &self,
        detector: Option<&Arc<dyn Detector>>,
        payload: &[u8],
    ) -> Result<Vec<Finding>, KeyclawError> {
        match detector {
            Some(detector) => detector.detect(payload),
            None => Err(KeyclawError::coded(
                CODE_GITLEAKS_UNAVAILABLE,
                "detector unavailable",
            )),
        }
    }

    fn from_findings(&self, findings: Vec<Finding>) -> Decision {
        if findings.is_empty() {
            return Decision::allow();
        }

        match self.mode {
            Mode::Block => Decision {
                action: Action::Block,
                findings,
                reason_code: Some(CODE_BLOCKED_BY_LEAK_POLICY.to_string()),
                warning_code: None,
                err: Some(KeyclawError::coded(
                    CODE_BLOCKED_BY_LEAK_POLICY,
                    "secret detected after rewrite",
                )),
            },
            Mode::Warn => Decision {
                action: Action::Warn,
                findings,
                reason_code: None,
                warning_code: Some(CODE_BLOCKED_BY_LEAK_POLICY.to_string()),
                err: None,
            },
        }
    }
}

fn error_code(err: &KeyclawError) -> Option<String> {
    code_of(err as &(dyn std::error::Error + 'static)).map(ToOwned::to_owned)
}
