use std::env;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub proxy_listen_addr: String,
    pub proxy_url: String,
    pub ca_cert_path: String,
    pub fail_closed: bool,
    pub max_body_bytes: i64,
    pub detector_timeout: Duration,
    pub known_codex_hosts: Vec<String>,
    pub known_claude_hosts: Vec<String>,
    pub gitleaks_binary: String,
    pub require_mitm_effective: bool,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            proxy_listen_addr: env_or("KEYCLAW_PROXY_ADDR", "127.0.0.1:8877"),
            proxy_url: env_or("KEYCLAW_PROXY_URL", "http://127.0.0.1:8877"),
            ca_cert_path: env_or("KEYCLAW_CA_CERT", ""),
            fail_closed: bool_env("KEYCLAW_FAIL_CLOSED", true),
            max_body_bytes: int64_env("KEYCLAW_MAX_BODY_BYTES", 2 * 1024 * 1024),
            detector_timeout: duration_env("KEYCLAW_DETECTOR_TIMEOUT", Duration::from_secs(4)),
            known_codex_hosts: split_csv(&env_or(
                "KEYCLAW_CODEX_HOSTS",
                "api.openai.com,chat.openai.com,chatgpt.com",
            )),
            known_claude_hosts: split_csv(&env_or(
                "KEYCLAW_CLAUDE_HOSTS",
                "api.anthropic.com,claude.ai",
            )),
            gitleaks_binary: env_or("KEYCLAW_GITLEAKS_BIN", "gitleaks"),
            require_mitm_effective: bool_env("KEYCLAW_REQUIRE_MITM_EFFECTIVE", true),
        }
    }

    pub fn allowed_hosts(tool: &str, cfg: &Config) -> Vec<String> {
        match tool.trim().to_ascii_lowercase().as_str() {
            "codex" => cfg.known_codex_hosts.clone(),
            "claude" => cfg.known_claude_hosts.clone(),
            _ => {
                let mut all = cfg.known_codex_hosts.clone();
                all.extend(cfg.known_claude_hosts.iter().cloned());
                all
            }
        }
    }
}

pub fn allowed_hosts(tool: &str, cfg: &Config) -> Vec<String> {
    Config::allowed_hosts(tool, cfg)
}

fn env_or(key: &str, fallback: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => fallback.to_string(),
    }
}

fn bool_env(key: &str, fallback: bool) -> bool {
    match env::var(key) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "t" | "true" | "y" | "yes" | "on" => true,
            "0" | "f" | "false" | "n" | "no" | "off" => false,
            _ => fallback,
        },
        Err(_) => fallback,
    }
}

fn int64_env(key: &str, fallback: i64) -> i64 {
    match env::var(key) {
        Ok(v) => v.trim().parse::<i64>().unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn duration_env(key: &str, fallback: Duration) -> Duration {
    match env::var(key) {
        Ok(v) => parse_duration(v.trim()).unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn split_csv(input: &str) -> Vec<String> {
    if input.trim().is_empty() {
        return Vec::new();
    }

    input
        .split(',')
        .map(|part| part.trim().to_ascii_lowercase())
        .filter(|part| !part.is_empty())
        .collect()
}

fn parse_duration(input: &str) -> Option<Duration> {
    if input.is_empty() {
        return None;
    }

    let mut rest = input;
    let mut nanos_total = 0f64;

    while !rest.is_empty() {
        let num_end = rest
            .char_indices()
            .take_while(|(_, ch)| ch.is_ascii_digit() || *ch == '.')
            .map(|(idx, ch)| idx + ch.len_utf8())
            .last()?;

        let n: f64 = rest[..num_end].parse().ok()?;
        rest = &rest[num_end..];
        if rest.is_empty() {
            return None;
        }

        let (unit, factor_nanos): (&str, f64) = if rest.starts_with("ns") {
            ("ns", 1.0)
        } else if rest.starts_with("us") {
            ("us", 1_000.0)
        } else if rest.starts_with("µs") {
            ("µs", 1_000.0)
        } else if rest.starts_with("ms") {
            ("ms", 1_000_000.0)
        } else if rest.starts_with('s') {
            ("s", 1_000_000_000.0)
        } else if rest.starts_with('m') {
            ("m", 60.0 * 1_000_000_000.0)
        } else if rest.starts_with('h') {
            ("h", 3600.0 * 1_000_000_000.0)
        } else {
            return None;
        };

        nanos_total += n * factor_nanos;
        rest = &rest[unit.len()..];
    }

    if !nanos_total.is_finite() || nanos_total < 0.0 {
        return None;
    }

    let nanos_total = nanos_total.round() as u128;
    let secs = nanos_total / 1_000_000_000;
    let nanos = (nanos_total % 1_000_000_000) as u32;
    if secs > u64::MAX as u128 {
        return None;
    }
    Some(Duration::new(secs as u64, nanos))
}
