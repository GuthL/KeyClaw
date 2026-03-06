use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Deserialize;
use wait_timeout::ChildExt;

use crate::detector::{Detector, Finding, Severity};
use crate::errors::{KeyclawError, CODE_GITLEAKS_UNAVAILABLE};

#[derive(Debug, Clone)]
pub struct GitleaksDetector {
    binary: String,
    timeout: Duration,
    args: Vec<String>,
}

impl GitleaksDetector {
    pub fn new(binary: String, timeout: Duration) -> Self {
        let binary = if binary.trim().is_empty() {
            "gitleaks".to_string()
        } else {
            binary
        };
        let timeout = if timeout.is_zero() {
            Duration::from_secs(4)
        } else {
            timeout
        };
        Self {
            binary,
            timeout,
            args: Vec::new(),
        }
    }
}

impl Detector for GitleaksDetector {
    fn name(&self) -> &'static str {
        "gitleaks"
    }

    fn detect(&self, payload: &[u8]) -> Result<Vec<Finding>, KeyclawError> {
        let mut cmd = Command::new(&self.binary);
        cmd.args([
            "stdin",
            "--report-format",
            "json",
            "--redact",
            "--no-banner",
        ]);
        cmd.args(&self.args);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(_) => {
                return Err(KeyclawError::coded(
                    CODE_GITLEAKS_UNAVAILABLE,
                    "gitleaks not installed",
                ))
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            if stdin.write_all(payload).is_err() {
                return Err(KeyclawError::coded(
                    "gitleaks_run_failed",
                    "gitleaks stdin write failed",
                ));
            }
        }

        let status = match child.wait_timeout(self.timeout) {
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(KeyclawError::coded(
                    CODE_GITLEAKS_UNAVAILABLE,
                    "gitleaks timeout",
                ));
            }
            Err(_) => {
                return Err(KeyclawError::coded(
                    CODE_GITLEAKS_UNAVAILABLE,
                    "gitleaks wait failed",
                ));
            }
        };

        let mut stdout = String::new();
        if let Some(mut reader) = child.stdout.take() {
            if reader.read_to_string(&mut stdout).is_err() {
                return Err(KeyclawError::coded(
                    "gitleaks_run_failed",
                    "gitleaks stdout read failed",
                ));
            }
        }

        let mut stderr = String::new();
        if let Some(mut reader) = child.stderr.take() {
            if reader.read_to_string(&mut stderr).is_err() {
                return Err(KeyclawError::coded(
                    "gitleaks_run_failed",
                    "gitleaks stderr read failed",
                ));
            }
        }

        if status.success() {
            if stdout.trim().is_empty() {
                return Ok(Vec::new());
            }
            return parse_gitleaks_report(stdout.as_bytes());
        }

        if let Ok(findings) = parse_gitleaks_report(stdout.as_bytes()) {
            return Ok(findings);
        }

        if stderr.trim().is_empty() {
            return Err(KeyclawError::coded(
                "gitleaks_run_failed",
                "gitleaks failed",
            ));
        }

        Err(KeyclawError::coded(
            "gitleaks_run_failed",
            "gitleaks failed",
        ))
    }
}

#[derive(Debug, Deserialize)]
struct GitleaksFinding {
    #[serde(rename = "RuleID", default)]
    rule_id: String,
    #[serde(rename = "Description", default)]
    description: String,
    #[serde(rename = "Secret", default)]
    secret: String,
    #[serde(rename = "Match", default)]
    matched: String,
}

#[derive(Debug, Deserialize)]
struct GitleaksWrapper {
    #[serde(rename = "findings", alias = "Findings")]
    findings: Option<Vec<GitleaksFinding>>,
}

pub fn parse_gitleaks_report(raw: &[u8]) -> Result<Vec<Finding>, KeyclawError> {
    let trimmed = String::from_utf8_lossy(raw);
    let trimmed = trimmed.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        let items: Vec<GitleaksFinding> = serde_json::from_str(trimmed).map_err(|_| {
            KeyclawError::coded("gitleaks_parse_error", "parse gitleaks array failed")
        })?;
        return Ok(map_findings(items));
    }

    let wrapper: GitleaksWrapper = serde_json::from_str(trimmed)
        .map_err(|_| KeyclawError::coded("gitleaks_parse_error", "parse gitleaks report failed"))?;
    let Some(items) = wrapper.findings else {
        return Err(KeyclawError::coded(
            "gitleaks_parse_error",
            "unknown gitleaks report format",
        ));
    };

    Ok(map_findings(items))
}

fn map_findings(items: Vec<GitleaksFinding>) -> Vec<Finding> {
    let mut findings = Vec::with_capacity(items.len());
    for item in items {
        let mut secret = item.secret.trim().to_string();
        if secret.is_empty() {
            secret = item.matched.trim().to_string();
        }
        if secret.is_empty() {
            secret = "[redacted]".to_string();
        }

        let rule_id = if item.rule_id.trim().is_empty() {
            "gitleaks".to_string()
        } else {
            item.rule_id
        };
        let message = if item.description.trim().is_empty() {
            "gitleaks finding".to_string()
        } else {
            item.description
        };

        findings.push(Finding {
            detector: "gitleaks".to_string(),
            rule_id,
            message,
            secret,
            severity: Severity::High,
        });
    }

    findings
}
