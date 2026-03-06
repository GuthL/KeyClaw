use once_cell::sync::Lazy;
use regex::Regex;

static RE_OPENAI: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9_-]{12,}").expect("valid openai regex"));
static RE_ANTHROPIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{12,}").expect("valid anthropic regex"));
static RE_BEARER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._-]{12,}").expect("valid bearer regex")
});

static RE_AWS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid aws key regex"));
static RE_GITHUB: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"gh[ps]_[A-Za-z0-9]{36,}").expect("valid github token regex"));

pub fn scrub(input: &str) -> String {
    let out = RE_OPENAI.replace_all(input, "[redacted_openai_secret]");
    let out = RE_ANTHROPIC.replace_all(&out, "[redacted_anthropic_secret]");
    let out = RE_AWS.replace_all(&out, "[redacted_aws_key]");
    let out = RE_GITHUB.replace_all(&out, "[redacted_github_token]");
    RE_BEARER
        .replace_all(&out, "Authorization: Bearer [redacted]")
        .into_owned()
}
