mod embedded;
mod gitleaks;

use crate::errors::KeyclawError;

pub use embedded::EmbeddedDetector;
pub use gitleaks::{parse_gitleaks_report, GitleaksDetector};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub detector: String,
    pub rule_id: String,
    pub message: String,
    pub secret: String,
    pub severity: Severity,
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, payload: &[u8]) -> Result<Vec<Finding>, KeyclawError>;
}
