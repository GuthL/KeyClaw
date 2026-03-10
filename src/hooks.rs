use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::errors::{CODE_HOOK_BLOCKED, KeyclawError};
use crate::placeholder::Replacement;

const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileHookConfig {
    pub event: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    pub action: String,
    pub command: Option<String>,
    pub path: Option<PathBuf>,
    pub timeout_ms: Option<u64>,
    pub message: Option<String>,
}

pub type RawHookConfig = FileHookConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    SecretDetected,
    RequestRedacted,
}

impl HookEvent {
    fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "secret_detected" => Some(Self::SecretDetected),
            "request_redacted" => Some(Self::RequestRedacted),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::SecretDetected => "secret_detected",
            Self::RequestRedacted => "request_redacted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookAction {
    Exec { command: String, timeout: Duration },
    Log { path: PathBuf },
    Block { message: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub event: HookEvent,
    pub rule_ids: Vec<String>,
    pub action: HookAction,
}

#[derive(Debug, Clone, Default)]
pub struct HookRunner {
    hooks: Vec<Hook>,
}

#[derive(Debug, Clone, Serialize)]
struct HookRecord {
    ts: u64,
    event: String,
    rule_id: String,
    placeholder: String,
    request_host: String,
}

impl HookRecord {
    fn from_replacement(event: HookEvent, request_host: &str, replacement: &Replacement) -> Self {
        Self {
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            event: event.as_str().to_string(),
            rule_id: replacement.rule_id.clone(),
            placeholder: replacement.placeholder.clone(),
            request_host: request_host.to_string(),
        }
    }
}

impl HookRunner {
    pub fn new(hooks: Vec<Hook>) -> Self {
        Self { hooks }
    }

    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    pub fn on_secret_detected(
        &self,
        request_host: &str,
        replacements: &[Replacement],
    ) -> Result<(), KeyclawError> {
        self.dispatch_event(HookEvent::SecretDetected, request_host, replacements, true)
    }

    pub fn on_request_redacted(
        &self,
        request_host: &str,
        replacements: &[Replacement],
    ) -> Result<(), KeyclawError> {
        self.dispatch_event(
            HookEvent::RequestRedacted,
            request_host,
            replacements,
            false,
        )
    }

    fn dispatch_event(
        &self,
        event: HookEvent,
        request_host: &str,
        replacements: &[Replacement],
        allow_block: bool,
    ) -> Result<(), KeyclawError> {
        if self.hooks.is_empty() || replacements.is_empty() {
            return Ok(());
        }

        for replacement in replacements {
            let record = HookRecord::from_replacement(event, request_host, replacement);
            for hook in self
                .hooks
                .iter()
                .filter(|hook| hook.event == event && hook_matches_rule(hook, &replacement.rule_id))
            {
                match &hook.action {
                    HookAction::Block { message } if allow_block => {
                        let msg = message.clone().unwrap_or_else(|| {
                            format!("request blocked by hook for rule {}", replacement.rule_id)
                        });
                        return Err(KeyclawError::coded(CODE_HOOK_BLOCKED, msg));
                    }
                    HookAction::Block { .. } => {}
                    action => spawn_nonblocking(action.clone(), record.clone()),
                }
            }
        }

        Ok(())
    }
}

pub fn parse_hooks(entries: &[RawHookConfig]) -> Result<Vec<Hook>, String> {
    let mut hooks = Vec::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        hooks.push(parse_hook_entry(entry, idx)?);
    }
    Ok(hooks)
}

fn parse_hook_entry(entry: &RawHookConfig, idx: usize) -> Result<Hook, String> {
    let label = format!("hooks[{idx}]");
    let event = HookEvent::parse(&entry.event)
        .ok_or_else(|| format!("{label} has invalid event `{}`", entry.event.trim()))?;
    let rule_ids = normalize_rule_ids(&entry.rule_ids);
    let action_name = entry.action.trim().to_ascii_lowercase();

    let action = match action_name.as_str() {
        "exec" => {
            let command = entry.command.as_deref().map(str::trim).unwrap_or_default();
            if command.is_empty() {
                return Err(format!("{label} exec action requires command"));
            }
            if entry.path.is_some() {
                return Err(format!("{label} exec action does not accept path"));
            }
            let timeout = entry
                .timeout_ms
                .map(Duration::from_millis)
                .unwrap_or(DEFAULT_EXEC_TIMEOUT);
            HookAction::Exec {
                command: command.to_string(),
                timeout,
            }
        }
        "log" => {
            let path = entry
                .path
                .clone()
                .ok_or_else(|| format!("{label} log action requires path"))?;
            if entry.command.is_some() {
                return Err(format!("{label} log action does not accept command"));
            }
            if entry.timeout_ms.is_some() {
                return Err(format!("{label} log action does not accept timeout_ms"));
            }
            HookAction::Log { path }
        }
        "block" => {
            if event != HookEvent::SecretDetected {
                return Err(format!(
                    "{label} block action is only supported for secret_detected"
                ));
            }
            if entry.command.is_some() || entry.path.is_some() || entry.timeout_ms.is_some() {
                return Err(format!(
                    "{label} block action only accepts the optional message field"
                ));
            }
            HookAction::Block {
                message: entry.message.clone(),
            }
        }
        _ => {
            return Err(format!(
                "{label} has invalid action `{}`",
                entry.action.trim()
            ));
        }
    };

    Ok(Hook {
        event,
        rule_ids,
        action,
    })
}

fn normalize_rule_ids(rule_ids: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = rule_ids
        .iter()
        .map(|rule_id| rule_id.trim().to_ascii_lowercase())
        .filter(|rule_id| !rule_id.is_empty())
        .collect();
    if normalized.is_empty() {
        normalized.push("*".to_string());
    }
    normalized
}

fn hook_matches_rule(hook: &Hook, rule_id: &str) -> bool {
    let rule_id = rule_id.trim().to_ascii_lowercase();
    hook.rule_ids
        .iter()
        .any(|candidate| candidate == "*" || candidate == &rule_id)
}

fn spawn_nonblocking(action: HookAction, record: HookRecord) {
    if let Err(err) = thread::Builder::new()
        .name("keyclaw-hook".to_string())
        .spawn(move || {
            if let Err(err) = run_action(action, record) {
                crate::logging::warn(&format!("hook action failed: {err}"));
            }
        })
    {
        crate::logging::warn(&format!("failed to spawn hook worker: {err}"));
    }
}

fn run_action(action: HookAction, record: HookRecord) -> Result<(), KeyclawError> {
    match action {
        HookAction::Exec { command, timeout } => run_exec_hook(&command, timeout, &record),
        HookAction::Log { path } => append_hook_log(&path, &record),
        HookAction::Block { .. } => Ok(()),
    }
}

fn append_hook_log(path: &Path, record: &HookRecord) -> Result<(), KeyclawError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            KeyclawError::uncoded(format!("create hook log dir {}: {err}", parent.display()))
        })?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| KeyclawError::uncoded(format!("open hook log {}: {err}", path.display())))?;
    let line = serde_json::to_string(record)
        .map_err(|err| KeyclawError::uncoded_with_source("serialize hook log record", err))?;
    writeln!(file, "{line}")
        .map_err(|err| KeyclawError::uncoded(format!("write hook log {}: {err}", path.display())))
}

fn run_exec_hook(
    command: &str,
    timeout: Duration,
    record: &HookRecord,
) -> Result<(), KeyclawError> {
    let mut child = shell_command(command)
        .env("KEYCLAW_HOOK_EVENT", &record.event)
        .env("KEYCLAW_HOOK_RULE_ID", &record.rule_id)
        .env("KEYCLAW_HOOK_PLACEHOLDER", &record.placeholder)
        .env("KEYCLAW_HOOK_REQUEST_HOST", &record.request_host)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| KeyclawError::uncoded(format!("spawn hook command `{command}`: {err}")))?;
    let payload = serde_json::to_vec(record)
        .map_err(|err| KeyclawError::uncoded_with_source("serialize hook payload", err))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&payload).map_err(|err| {
            KeyclawError::uncoded(format!("write hook stdin for `{command}`: {err}"))
        })?;
    }

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(KeyclawError::uncoded(format!(
                    "hook command `{command}` exited with status {status}"
                )));
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(KeyclawError::uncoded(format!(
                    "hook command `{command}` timed out after {}ms",
                    timeout.as_millis()
                )));
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(err) => {
                return Err(KeyclawError::uncoded(format!(
                    "poll hook command `{command}`: {err}"
                )));
            }
        }
    }
}

#[cfg(unix)]
fn shell_command(command: &str) -> Command {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-lc").arg(command);
    cmd
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    let mut cmd = Command::new("cmd");
    cmd.args(["/C", command]);
    cmd
}

#[cfg(test)]
mod tests {
    use super::{HookRunner, RawHookConfig, hook_matches_rule, parse_hooks};
    use crate::gitleaks_rules::{MatchConfidence, MatchSource};
    use crate::placeholder::Replacement;

    fn sample_replacement(rule_id: &str) -> Replacement {
        Replacement {
            rule_id: rule_id.to_string(),
            id: "api_k_deadbeef".to_string(),
            placeholder: "{{KEYCLAW_SECRET_api_k_deadbeef}}".to_string(),
            secret: "sk-live-real-secret".to_string(),
            source: MatchSource::Regex,
            confidence: MatchConfidence::High,
            confidence_score: 100,
            entropy: None,
            decoded_depth: 0,
        }
    }

    #[test]
    fn parse_hooks_defaults_empty_rule_ids_to_wildcard() {
        let hooks = parse_hooks(&[RawHookConfig {
            event: "secret_detected".to_string(),
            rule_ids: Vec::new(),
            action: "log".to_string(),
            command: None,
            path: Some(std::env::temp_dir().join("hooks.log")),
            timeout_ms: None,
            message: None,
        }])
        .expect("parse hooks");

        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn hook_matches_exact_rules_and_wildcards() {
        let hooks = parse_hooks(&[RawHookConfig {
            event: "request_redacted".to_string(),
            rule_ids: vec!["generic-api-key".to_string()],
            action: "log".to_string(),
            command: None,
            path: Some(std::env::temp_dir().join("hooks.log")),
            timeout_ms: None,
            message: None,
        }])
        .expect("parse hooks");

        let hook = &hooks[0];
        assert!(hook_matches_rule(hook, "generic-api-key"));
        assert!(!hook_matches_rule(hook, "aws-access-key"));
    }

    #[test]
    fn block_hooks_return_coded_error_without_secret_material() {
        let hooks = HookRunner::new(
            parse_hooks(&[RawHookConfig {
                event: "secret_detected".to_string(),
                rule_ids: vec!["generic-api-key".to_string()],
                action: "block".to_string(),
                command: None,
                path: None,
                timeout_ms: None,
                message: Some("production key detected".to_string()),
            }])
            .expect("parse hooks"),
        );
        let replacement = sample_replacement("generic-api-key");

        let err = hooks
            .on_secret_detected("stdin", &[replacement])
            .expect_err("block should reject");

        assert_eq!(err.code(), Some("hook_blocked"));
        assert!(err.to_string().contains("production key detected"));
        assert!(!err.to_string().contains("sk-live-real-secret"));
    }
}
