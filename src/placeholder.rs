use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::errors::KeyclawError;

pub const CONTRACT_MARKER_KEY: &str = "_keyclaw_contract";
pub const CONTRACT_MARKER_VALUE: &str = "placeholder:v1";

const PREFIX_LEN: usize = 5;

static PLACEHOLDER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\{\{KEYCLAW_SECRET_([A-Za-z0-9*_-]{1,5})_([a-f0-9]{16})\}\}").expect("valid placeholder regex")
});

// --- Provider-specific patterns (ordered: most specific first) ---

static ANTHROPIC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").expect("valid anthropic regex"));
static OPENAI_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9_-]{20,}").expect("valid openai regex"));
static AWS_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}").expect("valid aws key regex"));
static GITHUB_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:ghp|ghs|ghu|gho|ghr)_[A-Za-z0-9]{36,}").expect("valid github token regex"));
static GITHUB_FINE_GRAINED_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"github_pat_[A-Za-z0-9_]{20,}").expect("valid github fine-grained pat regex"));
static GITLAB_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"glpat-[A-Za-z0-9_-]{20,}").expect("valid gitlab pat regex"));
static SLACK_TOKEN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"xox[bpasroet]-[A-Za-z0-9_-]{10,}").expect("valid slack token regex"));
static SLACK_APP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"xapp-[A-Za-z0-9_-]{10,}").expect("valid slack app token regex"));
static STRIPE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,}").expect("valid stripe regex"));
static SENDGRID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}").expect("valid sendgrid regex"));
static GCP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AIza[A-Za-z0-9_-]{35,}").expect("valid gcp api key regex"));
static TWILIO_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"SK[0-9a-f]{32}").expect("valid twilio api key regex"));
static NPM_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"npm_[A-Za-z0-9]{36,}").expect("valid npm token regex"));
static PYPI_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"pypi-[A-Za-z0-9_-]{50,}").expect("valid pypi token regex"));
static HUGGINGFACE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"hf_[A-Za-z0-9]{20,}").expect("valid huggingface token regex"));
static DATABRICKS_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"dapi[A-Za-z0-9]{32,}").expect("valid databricks token regex"));
static DIGITALOCEAN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"do[opr]_v1_[A-Fa-f0-9]{64}").expect("valid digitalocean token regex"));
static PLANETSCALE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_-]{20,}").expect("valid planetscale token regex"));
static SHOPIFY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"shp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32,}").expect("valid shopify token regex"));
static LINEAR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"lin_api_[A-Za-z0-9]{40,}").expect("valid linear api key regex"));
static VAULT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"hv[bs]\.[A-Za-z0-9_-]{20,}").expect("valid vault token regex"));
static GRAFANA_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"gl(?:c|sa)_[A-Za-z0-9_-]{20,}").expect("valid grafana token regex"));
static NEWRELIC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"NR(?:AK|II|JS)-[A-Za-z0-9_-]{20,}").expect("valid new relic key regex"));
static TELEGRAM_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[0-9]{5,16}:[A-Za-z0-9_-]{34,}").expect("valid telegram bot token regex"));
static MAILGUN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"key-[A-Za-z0-9]{32,}").expect("valid mailgun key regex"));
static POSTMAN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"PMAK-[A-Za-z0-9_-]{40,}").expect("valid postman key regex"));
static CLOUDFLARE_ORIGIN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"v1\.0-[A-Fa-f0-9]{24,}").expect("valid cloudflare origin ca regex"));
static DOPPLER_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"dp\.pt\.[A-Za-z0-9]{20,}").expect("valid doppler token regex"));
static DYNATRACE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"dt0c01\.[A-Za-z0-9_-]{20,}").expect("valid dynatrace token regex"));
static SENTRY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sntr(?:ys|yu)_[A-Za-z0-9_-]{20,}").expect("valid sentry token regex"));
static AGE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AGE-SECRET-KEY-1[A-Za-z0-9]{58}").expect("valid age secret key regex"));
static PRIVATE_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY[- ]{5}").expect("valid private key regex"));
static FLYIO_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"fo1_[A-Za-z0-9_-]{40,}").expect("valid fly.io token regex"));
static NOTION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"ntn_[A-Za-z0-9]{40,}").expect("valid notion token regex"));
static SONAR_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sq[upa]_[A-Za-z0-9]{30,}").expect("valid sonar token regex"));
static PERPLEXITY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"pplx-[A-Za-z0-9]{40,}").expect("valid perplexity key regex"));

static GENERIC_API_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\W*[:=]\W*([A-Za-z0-9_-]{20,})").expect("valid generic api key regex"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    pub id: String,
    pub placeholder: String,
    pub secret: String,
}

pub fn make_id(secret: &str) -> String {
    let prefix: String = secret.chars().take(PREFIX_LEN).collect();
    let prefix = if prefix.is_empty() { "*".to_string() } else { prefix };
    let digest = Sha256::digest(secret.as_bytes());
    format!("{}_{}", prefix, hex::encode(&digest[..8]))
}

pub fn make(id: &str) -> String {
    format!("{{{{KEYCLAW_SECRET_{}}}}}", id)
}

pub fn is_placeholder(s: &str) -> bool {
    PLACEHOLDER_RE.is_match(s)
}

/// Check if a position in the input falls inside an existing placeholder
fn inside_placeholder(input: &str, start: usize, end: usize) -> bool {
    let search_start = if start >= 60 { start - 60 } else { 0 };
    if let Some(pos) = input[search_start..start].rfind("{{KEYCLAW_SECRET_") {
        let abs_pos = search_start + pos;
        if let Some(close) = input[end..].find("}}") {
            let close_abs = end + close + 2;
            let candidate = &input[abs_pos..close_abs];
            if PLACEHOLDER_RE.is_match(candidate) {
                return true;
            }
        }
    }
    false
}

pub fn replace_secrets<F>(
    input: &str,
    mut on_secret: F,
) -> Result<(String, Vec<Replacement>), KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let mut replacements = Vec::<Replacement>::new();

    // Provider-specific patterns (most specific first to avoid double-matching)
    let out = rewrite_with_regex(&ANTHROPIC_RE, input, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&OPENAI_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&AWS_KEY_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&GITHUB_FINE_GRAINED_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&GITHUB_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&GITLAB_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&SLACK_TOKEN_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&SLACK_APP_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&STRIPE_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&SENDGRID_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&GCP_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&TWILIO_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&NPM_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&PYPI_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&HUGGINGFACE_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&DATABRICKS_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&DIGITALOCEAN_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&PLANETSCALE_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&SHOPIFY_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&LINEAR_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&VAULT_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&GRAFANA_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&NEWRELIC_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&TELEGRAM_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&MAILGUN_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&POSTMAN_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&CLOUDFLARE_ORIGIN_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&DOPPLER_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&DYNATRACE_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&SENTRY_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&AGE_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&PRIVATE_KEY_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&FLYIO_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&NOTION_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&SONAR_RE, &out, &mut replacements, &mut on_secret)?;
    let out = rewrite_with_regex(&PERPLEXITY_RE, &out, &mut replacements, &mut on_secret)?;

    // Generic catch-all (last)
    let out = rewrite_with_generic_regex(&GENERIC_API_KEY_RE, &out, &mut replacements, &mut on_secret)?;
    Ok((out, replacements))
}

pub fn resolve_placeholders<F>(
    input: &str,
    strict: bool,
    mut resolver: F,
) -> Result<String, KeyclawError>
where
    F: FnMut(&str) -> Result<Option<String>, KeyclawError>,
{
    let mut matches = PLACEHOLDER_RE.captures_iter(input).peekable();
    if matches.peek().is_none() {
        return Ok(input.to_string());
    }

    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;

    for caps in PLACEHOLDER_RE.captures_iter(input) {
        let full = caps.get(0).expect("full match exists");
        let prefix = caps.get(1).expect("prefix group exists").as_str();
        let hash = caps.get(2).expect("hash group exists").as_str();
        let id = format!("{}_{}", prefix, hash);

        let resolved = resolver(&id)?;
        match resolved {
            Some(secret) => {
                out.push_str(&input[last..full.start()]);
                out.push_str(&secret);
                last = full.end();
            }
            None if strict => {
                return Err(KeyclawError::uncoded(format!(
                    "missing placeholder secret for id {id}"
                )));
            }
            None => {
                out.push_str(&input[last..full.end()]);
                last = full.end();
            }
        }
    }

    out.push_str(&input[last..]);
    Ok(out)
}

fn rewrite_with_regex<F>(
    re: &Regex,
    input: &str,
    replacements: &mut Vec<Replacement>,
    on_secret: &mut F,
) -> Result<String, KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut has_match = false;

    for m in re.find_iter(input) {
        let secret = m.as_str();
        // Skip if the match is inside an existing placeholder
        if inside_placeholder(input, m.start(), m.end()) {
            continue;
        }
        has_match = true;
        let id = on_secret(secret)?;
        let ph = make(&id);

        replacements.push(Replacement {
            id,
            placeholder: ph.clone(),
            secret: secret.to_string(),
        });

        out.push_str(&input[last..m.start()]);
        out.push_str(&ph);
        last = m.end();
    }

    if !has_match {
        return Ok(input.to_string());
    }

    out.push_str(&input[last..]);
    Ok(out)
}

fn rewrite_with_generic_regex<F>(
    re: &Regex,
    input: &str,
    replacements: &mut Vec<Replacement>,
    on_secret: &mut F,
) -> Result<String, KeyclawError>
where
    F: FnMut(&str) -> Result<String, KeyclawError>,
{
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    let mut has_match = false;

    for caps in re.captures_iter(input) {
        let full = caps.get(0).expect("full match exists");
        let secret_match = caps.get(1).unwrap_or(full);
        let secret = secret_match.as_str();
        // Skip if the captured secret value falls inside an existing placeholder.
        // We check the secret capture position (not the full match) because the
        // generic regex can start matching outside the placeholder (e.g. "API_KEY: {{...")
        // while the captured value is inside it.
        if inside_placeholder(input, secret_match.start(), secret_match.end()) {
            continue;
        }
        has_match = true;
        let id = on_secret(secret)?;
        let ph = make(&id);

        replacements.push(Replacement {
            id,
            placeholder: ph.clone(),
            secret: secret.to_string(),
        });

        // Replace just the captured secret within the full match
        out.push_str(&input[last..secret_match.start()]);
        out.push_str(&ph);
        last = secret_match.end();
    }

    if !has_match {
        return Ok(input.to_string());
    }

    out.push_str(&input[last..]);
    Ok(out)
}
