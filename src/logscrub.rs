use once_cell::sync::Lazy;
use regex::{Captures, Regex};

static RE_OPENAI: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-[A-Za-z0-9_-]{12,}").expect("valid openai regex"));
static RE_ANTHROPIC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{12,}").expect("valid anthropic regex"));
static RE_BEARER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._-]{12,}").expect("valid bearer regex")
});
static RE_KEY_VALUE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(\b(?:api[_-]?key|x-api-key|secret[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|password|passwd)\b\s*(?:=|:)\s*)("[^"\r\n]+"|'[^'\r\n]+'|[^\s,;]+)"#,
    )
    .expect("valid key-value regex")
});
static RE_JSON_KEY_VALUE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)("(?:api[_-]?key|x-api-key|secret[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|password|passwd)"\s*:\s*)("[^"\r\n]+"|'[^'\r\n]+'|[^\s,}]+)"#,
    )
    .expect("valid json key-value regex")
});

static RE_AWS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid aws key regex"));
static RE_GITHUB: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"gh[ps]_[A-Za-z0-9]{36,}").expect("valid github token regex"));

pub fn scrub(input: &str) -> String {
    let out = redact_placeholders(input);
    let out = RE_BEARER.replace_all(&out, "Authorization: Bearer [redacted]");
    let out = replace_key_values(&out, &RE_JSON_KEY_VALUE);
    let out = replace_key_values(&out, &RE_KEY_VALUE);
    let out = RE_OPENAI.replace_all(&out, "[redacted_openai_secret]");
    let out = RE_ANTHROPIC.replace_all(&out, "[redacted_anthropic_secret]");
    let out = RE_AWS.replace_all(&out, "[redacted_aws_key]");
    let out = RE_GITHUB.replace_all(&out, "[redacted_github_token]");
    out.into_owned()
}

fn replace_key_values(input: &str, regex: &Regex) -> String {
    regex
        .replace_all(input, |caps: &Captures<'_>| {
            let prefix = caps.get(1).expect("prefix capture").as_str();
            let value = caps.get(2).expect("value capture").as_str();
            let redacted = if value.starts_with('"') && value.ends_with('"') {
                "\"[redacted]\""
            } else if value.starts_with('\'') && value.ends_with('\'') {
                "'[redacted]'"
            } else {
                "[redacted]"
            };
            format!("{prefix}{redacted}")
        })
        .into_owned()
}

fn redact_placeholders(input: &str) -> String {
    if !input.contains("{{") {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while let Some(rel) = input[cursor..].find("{{") {
        let start = cursor + rel;
        out.push_str(&input[cursor..start]);

        if let Some(len) = crate::placeholder::complete_placeholder_len(&input[start..]) {
            out.push_str("[redacted_keyclaw_placeholder]");
            cursor = start + len;
        } else {
            out.push_str("{{");
            cursor = start + 2;
        }
    }

    out.push_str(&input[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::scrub;

    #[test]
    fn scrub_redacts_generic_assignments_and_placeholders() {
        let secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
        let placeholder = "{{KEYCLAW_SECRET_sk-AB_0123456789abcdef}}";
        let input = format!("rewrite failed: api_key = {secret}; placeholder={placeholder}");

        let out = scrub(&input);

        assert!(!out.contains(secret), "output={out}");
        assert!(!out.contains(placeholder), "output={out}");
        assert!(out.contains("api_key"), "output={out}");
        assert!(
            out.contains("[redacted_keyclaw_placeholder]"),
            "output={out}"
        );
    }

    #[test]
    fn scrub_leaves_marker_shaped_invalid_text_unredacted() {
        let invalid = "{{KEYCLAW_SECRET_prefixx_0123456789abcdef}}";

        let out = scrub(invalid);

        assert_eq!(out, invalid);
        assert!(
            !out.contains("[redacted_keyclaw_placeholder]"),
            "output={out}"
        );
    }

    #[test]
    fn scrub_redacts_provider_and_header_secrets() {
        let bearer = "mF_9.B5f-4.1JqM123456789";
        let github = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
        let aws = "AKIA1234567890ABCDEF";
        let anthropic = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890";
        let input = format!(
            "Authorization: Bearer {bearer}; github={github}; aws={aws}; anthropic={anthropic}"
        );

        let out = scrub(&input);

        assert!(!out.contains(bearer), "output={out}");
        assert!(!out.contains(github), "output={out}");
        assert!(!out.contains(aws), "output={out}");
        assert!(!out.contains(anthropic), "output={out}");
    }

    #[test]
    fn scrub_keeps_safe_text() {
        let input = "keyclaw info: proxy listening on 127.0.0.1:8877";
        assert_eq!(scrub(input), input);
    }
}
