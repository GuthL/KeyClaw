use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::Deserialize;

use crate::errors::KeyclawError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountEntry {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsSummary {
    pub total_redactions: usize,
    pub latest_event: Option<String>,
    pub top_rules: Vec<CountEntry>,
    pub top_hosts: Vec<CountEntry>,
}

#[derive(Debug, Deserialize)]
struct AuditRecord {
    #[serde(default)]
    ts: String,
    #[serde(default)]
    rule_id: String,
    #[serde(default)]
    request_host: String,
    #[serde(default)]
    action: String,
}

pub fn summarize_audit_log(path: &Path) -> Result<StatsSummary, KeyclawError> {
    if !path.exists() {
        return Ok(StatsSummary::default());
    }

    let file = File::open(path).map_err(|err| {
        KeyclawError::uncoded(format!("open audit log {}: {err}", path.display()))
    })?;
    let reader = BufReader::new(file);

    let mut total_redactions = 0usize;
    let mut latest_event: Option<String> = None;
    let mut rule_counts = HashMap::<String, usize>::new();
    let mut host_counts = HashMap::<String, usize>::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|err| {
            KeyclawError::uncoded(format!(
                "read audit log {} line {}: {err}",
                path.display(),
                idx + 1
            ))
        })?;
        if line.trim().is_empty() {
            continue;
        }

        let record: AuditRecord = serde_json::from_str(&line).map_err(|err| {
            KeyclawError::uncoded_with_source(
                format!("parse audit log {} line {}", path.display(), idx + 1),
                err,
            )
        })?;
        if record.action != "redacted" {
            continue;
        }

        total_redactions += 1;
        if !record.ts.is_empty()
            && latest_event
                .as_ref()
                .map(|current| record.ts.as_str() > current.as_str())
                .unwrap_or(true)
        {
            latest_event = Some(record.ts);
        }
        if !record.rule_id.is_empty() {
            *rule_counts.entry(record.rule_id).or_insert(0) += 1;
        }
        if !record.request_host.is_empty() {
            *host_counts.entry(record.request_host).or_insert(0) += 1;
        }
    }

    Ok(StatsSummary {
        total_redactions,
        latest_event,
        top_rules: sorted_counts(rule_counts),
        top_hosts: sorted_counts(host_counts),
    })
}

pub fn render_stats(path: &Path, summary: &StatsSummary, limit: usize) -> String {
    let mut out = String::new();
    let _ = writeln!(&mut out, "Audit log: {}", path.display());
    let _ = writeln!(&mut out, "Total redactions: {}", summary.total_redactions);
    if let Some(ts) = &summary.latest_event {
        let _ = writeln!(&mut out, "Latest event: {ts}");
    }
    append_top_section(&mut out, "Top rules", &summary.top_rules, limit);
    append_top_section(&mut out, "Top hosts", &summary.top_hosts, limit);
    out
}

fn append_top_section(out: &mut String, title: &str, entries: &[CountEntry], limit: usize) {
    let _ = writeln!(out, "{title}:");
    if entries.is_empty() {
        let _ = writeln!(out, "- none");
        return;
    }

    for entry in entries.iter().take(limit.max(1)) {
        let _ = writeln!(out, "- {}: {}", entry.name, entry.count);
    }
}

fn sorted_counts(counts: HashMap<String, usize>) -> Vec<CountEntry> {
    let mut entries: Vec<_> = counts
        .into_iter()
        .map(|(name, count)| CountEntry { name, count })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    entries
}
