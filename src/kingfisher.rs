//! Second-pass secret scanning via the external `kingfisher` binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde::Deserialize;

use crate::errors::KeyclawError;
use crate::gitleaks_rules::{MatchConfidence, MatchSource};
use crate::placeholder::{self, Replacement};

const KINGFISHER_SUCCESS_WITH_FINDINGS: i32 = 200;
const KINGFISHER_SUCCESS_WITH_VALIDATED_FINDINGS: i32 = 205;

pub fn default_scanner() -> Option<Arc<SecondPassScanner>> {
    if !command_available("kingfisher") {
        return None;
    }

    Some(Arc::new(SecondPassScanner::new("kingfisher")))
}

pub struct SecondPassScanner {
    binary: PathBuf,
}

impl SecondPassScanner {
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    pub fn from_binary(binary: impl Into<PathBuf>) -> Result<Self, KeyclawError> {
        let binary = binary.into();
        if binary.is_absolute() || binary.components().count() > 1 {
            if fs::metadata(&binary).is_ok() {
                return Ok(Self { binary });
            }
        }

        if command_available(&binary) {
            Ok(Self { binary })
        } else {
            Err(KeyclawError::uncoded(format!(
                "kingfisher binary not found at {}",
                binary.display()
            )))
        }
    }

    pub fn replace_secrets<F>(
        &self,
        input: &str,
        decoded_depth: u8,
        mut on_secret: F,
    ) -> Result<(String, Vec<Replacement>), KeyclawError>
    where
        F: FnMut(&str) -> Result<String, KeyclawError>,
    {
        let findings = self.scan(input)?;
        if findings.is_empty() {
            return Ok((input.to_string(), Vec::new()));
        }

        let mut out = String::with_capacity(input.len());
        let mut replacements = Vec::with_capacity(findings.len());
        let mut last = 0usize;

        for finding in findings {
            if finding.start < last
                || finding.end > input.len()
                || !input.is_char_boundary(finding.start)
                || !input.is_char_boundary(finding.end)
            {
                continue;
            }

            let secret = &input[finding.start..finding.end];
            if placeholder::contains_placeholder_prefix(secret) {
                continue;
            }

            let id = on_secret(secret)?;
            let rendered = placeholder::make(&id);

            out.push_str(&input[last..finding.start]);
            out.push_str(&rendered);
            last = finding.end;

            replacements.push(Replacement {
                rule_id: finding.rule_id,
                id,
                placeholder: rendered,
                secret: secret.to_string(),
                source: MatchSource::Regex,
                confidence: finding.confidence,
                confidence_score: finding.confidence_score,
                entropy: finding.entropy,
                decoded_depth,
            });
        }

        if replacements.is_empty() {
            return Ok((input.to_string(), replacements));
        }

        out.push_str(&input[last..]);
        Ok((out, replacements))
    }

    fn scan(&self, input: &str) -> Result<Vec<SecondPassFinding>, KeyclawError> {
        let temp = tempfile::tempdir()
            .map_err(|err| KeyclawError::uncoded_with_source("create kingfisher tempdir", err))?;
        let input_path = temp.path().join("payload.txt");
        let output_path = temp.path().join("findings.json");

        fs::write(&input_path, input)
            .map_err(|err| KeyclawError::uncoded_with_source("write kingfisher payload", err))?;

        let output = Command::new(&self.binary)
            .arg("scan")
            .arg(&input_path)
            .arg("--format")
            .arg("json")
            .arg("--output")
            .arg(&output_path)
            .arg("--no-validate")
            .arg("--no-base64")
            .arg("--no-dedup")
            .arg("--confidence")
            .arg("medium")
            .output()
            .map_err(|err| KeyclawError::uncoded_with_source("run kingfisher", err))?;

        let exit_code = output.status.code();
        if !matches!(
            exit_code,
            Some(0 | KINGFISHER_SUCCESS_WITH_FINDINGS | KINGFISHER_SUCCESS_WITH_VALIDATED_FINDINGS)
        ) {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let message = if stderr.is_empty() {
                format!("kingfisher exited with status {:?}", output.status.code())
            } else {
                format!(
                    "kingfisher exited with status {:?}: {}",
                    output.status.code(),
                    stderr
                )
            };
            return Err(KeyclawError::uncoded(message));
        }

        let report_bytes = match fs::read(&output_path) {
            Ok(bytes) => bytes,
            Err(err) if exit_code == Some(0) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    return Ok(Vec::new());
                }
                return Err(KeyclawError::uncoded_with_source(
                    "read kingfisher output",
                    err,
                ));
            }
            Err(err) => {
                return Err(KeyclawError::uncoded_with_source(
                    "read kingfisher output",
                    err,
                ));
            }
        };

        if report_bytes.is_empty() {
            return Ok(Vec::new());
        }

        let report: CliReportEnvelope = serde_json::from_slice(&report_bytes)
            .map_err(|err| KeyclawError::uncoded_with_source("parse kingfisher output", err))?;
        let mut findings = Vec::with_capacity(report.findings.len());

        for record in report.findings {
            let Some(start) = byte_offset_for_line_column(
                input,
                record.finding.line,
                record.finding.column_start,
            ) else {
                continue;
            };
            let Some(end) =
                byte_offset_for_line_column(input, record.finding.line, record.finding.column_end)
            else {
                continue;
            };
            if start >= end {
                continue;
            }

            findings.push(SecondPassFinding {
                rule_id: record.rule.id,
                start,
                end,
                confidence: parse_confidence(&record.finding.confidence),
                confidence_score: confidence_score(&record.finding.confidence),
                entropy: record.finding.entropy.parse::<f64>().ok(),
            });
        }

        findings.sort_by(|left, right| {
            left.start
                .cmp(&right.start)
                .then_with(|| (right.end - right.start).cmp(&(left.end - left.start)))
                .then_with(|| left.rule_id.cmp(&right.rule_id))
        });

        Ok(findings)
    }
}

pub fn default_binary_available() -> bool {
    command_available("kingfisher")
}

fn command_available(command: impl AsRef<Path>) -> bool {
    Command::new(command.as_ref())
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn parse_confidence(confidence: &str) -> MatchConfidence {
    match confidence.trim().to_ascii_lowercase().as_str() {
        "high" => MatchConfidence::High,
        "medium" => MatchConfidence::Medium,
        _ => MatchConfidence::Low,
    }
}

fn confidence_score(confidence: &str) -> u8 {
    match confidence.trim().to_ascii_lowercase().as_str() {
        "high" => 90,
        "medium" => 70,
        _ => 40,
    }
}

fn byte_offset_for_line_column(input: &str, line: u32, column: u32) -> Option<usize> {
    if line == 0 {
        return None;
    }

    let mut current_line = 1u32;
    let mut line_start = 0usize;

    for segment in input.split_inclusive('\n') {
        if current_line == line {
            let candidate = line_start + column as usize;
            let line_len = segment.strip_suffix('\n').unwrap_or(segment).len();
            return (column as usize <= line_len).then_some(candidate);
        }
        line_start += segment.len();
        current_line += 1;
    }

    if input.ends_with('\n') && current_line == line {
        let candidate = line_start + column as usize;
        let line_len = input.len().saturating_sub(line_start);
        return (column as usize <= line_len).then_some(candidate);
    }

    None
}

#[derive(Deserialize)]
struct CliReportEnvelope {
    #[serde(default)]
    findings: Vec<CliFindingRecord>,
}

#[derive(Deserialize)]
struct CliFindingRecord {
    rule: CliRuleMetadata,
    finding: CliFindingData,
}

#[derive(Deserialize)]
struct CliRuleMetadata {
    id: String,
}

#[derive(Deserialize)]
struct CliFindingData {
    confidence: String,
    entropy: String,
    line: u32,
    column_start: u32,
    column_end: u32,
}

struct SecondPassFinding {
    rule_id: String,
    start: usize,
    end: usize,
    confidence: MatchConfidence,
    confidence_score: u8,
    entropy: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::byte_offset_for_line_column;

    #[test]
    fn byte_offsets_follow_line_boundaries() {
        let input = "alpha\nbeta\ngamma";

        assert_eq!(byte_offset_for_line_column(input, 1, 5), Some(5));
        assert_eq!(byte_offset_for_line_column(input, 2, 4), Some(10));
        assert_eq!(byte_offset_for_line_column(input, 2, 5), None);
        assert_eq!(byte_offset_for_line_column(input, 4, 0), None);
    }

    #[test]
    fn byte_offsets_allow_trailing_empty_line() {
        let input = "alpha\n";

        assert_eq!(byte_offset_for_line_column(input, 2, 0), Some(6));
        assert_eq!(byte_offset_for_line_column(input, 2, 1), None);
    }

    #[test]
    fn byte_offsets_use_utf8_byte_columns() {
        let input = "first\nésecret";

        assert_eq!(byte_offset_for_line_column(input, 2, 0), Some(6));
        assert_eq!(byte_offset_for_line_column(input, 2, 2), Some(8));
        assert_eq!(&input[8..], "secret");
    }
}
