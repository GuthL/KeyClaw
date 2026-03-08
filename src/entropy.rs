//! Shannon entropy calculation and high-entropy token detection.
//!
//! This module provides a standalone entropy scorer that flags tokens with
//! unusually high information density — a strong heuristic for API keys,
//! passwords, and other machine-generated secrets that regex rules may miss.

/// Compute the Shannon entropy (bits per byte) of `input`.
///
/// Returns 0.0 for empty strings. For a uniform distribution of all 256 byte
/// values the result approaches 8.0.
pub fn shannon_entropy(input: &str) -> f64 {
    let bytes = input.as_bytes();
    let len = bytes.len();
    if len == 0 {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }

    let len_f = len as f64;
    let mut entropy = 0.0f64;
    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len_f;
        entropy -= p * p.log2();
    }

    entropy
}

/// Configuration knobs for entropy-based detection.
#[derive(Debug, Clone)]
pub struct EntropyConfig {
    pub enabled: bool,
    pub threshold: f64,
    pub min_len: usize,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 3.5,
            min_len: 20,
        }
    }
}

/// A single high-entropy token found in the input.
pub struct EntropyMatch<'a> {
    pub start: usize,
    pub end: usize,
    pub token: &'a str,
    pub entropy: f64,
}

/// Returns true if `ch` is a token delimiter.
fn is_delimiter(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '\t'
            | '\n'
            | '\r'
            | '"'
            | '\''
            | '`'
            | '='
            | ':'
            | ','
            | '{'
            | '}'
            | '['
            | ']'
            | '('
            | ')'
            | ';'
            | '<'
            | '>'
            | '|'
            | '\\'
    )
}

/// Returns true if `token` consists entirely of ASCII lowercase letters.
fn is_all_lowercase_alpha(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| b.is_ascii_lowercase())
}

/// Evaluate a single candidate token and push it into `matches` if it qualifies.
fn check_token<'a>(
    input: &'a str,
    start: usize,
    end: usize,
    min_len: usize,
    threshold: f64,
    matches: &mut Vec<EntropyMatch<'a>>,
) {
    let token = &input[start..end];
    if token.len() < min_len {
        return;
    }
    if is_all_lowercase_alpha(token) {
        return;
    }
    let entropy = shannon_entropy(token);
    if entropy >= threshold {
        matches.push(EntropyMatch {
            start,
            end,
            token,
            entropy,
        });
    }
}

/// Find all tokens in `input` whose Shannon entropy meets or exceeds
/// `threshold` and whose length is at least `min_len`.
///
/// Tokens are produced by splitting on common delimiters. Tokens that are
/// all-lowercase ASCII (likely English words) are skipped. Returned matches
/// carry byte offsets into the original `input`.
pub fn find_high_entropy_tokens<'a>(
    input: &'a str,
    min_len: usize,
    threshold: f64,
) -> Vec<EntropyMatch<'a>> {
    let mut matches = Vec::new();
    let mut token_start: Option<usize> = None;

    for (idx, ch) in input.char_indices() {
        if is_delimiter(ch) {
            if let Some(start) = token_start.take() {
                check_token(input, start, idx, min_len, threshold, &mut matches);
            }
        } else if token_start.is_none() {
            token_start = Some(idx);
        }
    }

    // Handle trailing token (no trailing delimiter)
    if let Some(start) = token_start {
        check_token(input, start, input.len(), min_len, threshold, &mut matches);
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_uniform_distribution_near_eight() {
        // Build a string containing all 256 byte values (as a &str we need valid
        // UTF-8, so we use 256 distinct printable ASCII characters repeated).
        // Instead, we test with the 95 printable ASCII chars which gives ~6.57.
        // For a true 256-uniform test we work at the byte level via a helper.
        // shannon_entropy takes &str, so we test with printable ASCII.
        // Each of 62 alphanumeric chars once → log2(62) ≈ 5.954
        let alnum: String = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();
        let e = shannon_entropy(&alnum);
        assert!(
            (e - 62f64.log2()).abs() < 0.01,
            "expected ~5.954, got {e}"
        );
    }

    #[test]
    fn entropy_single_repeated_char() {
        let input = "aaaaaaaaaa";
        assert_eq!(shannon_entropy(input), 0.0);
    }

    #[test]
    fn entropy_empty_string() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn finds_base64_like_api_key() {
        let input = "token=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
        let matches = find_high_entropy_tokens(input, 20, 3.5);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].token, "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v");
    }

    #[test]
    fn skips_english_prose() {
        let input = "this is a perfectly normal sentence with only regular words";
        let matches = find_high_entropy_tokens(input, 5, 3.5);
        assert!(matches.is_empty(), "prose should not trigger entropy detection");
    }

    #[test]
    fn skips_short_tokens() {
        let input = "key=Ab1";
        let matches = find_high_entropy_tokens(input, 20, 3.5);
        assert!(matches.is_empty());
    }

    #[test]
    fn returns_correct_byte_offsets() {
        let key = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
        let input = format!("prefix={key}");
        let matches = find_high_entropy_tokens(&input, 20, 3.5);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].start, 7);
        assert_eq!(matches[0].end, 7 + key.len());
        assert_eq!(&input[matches[0].start..matches[0].end], key);
    }

    #[test]
    fn skips_all_lowercase_alpha_tokens() {
        // A long all-lowercase token that would otherwise exceed the entropy threshold
        let input = "abcdefghijklmnopqrstuvwxyz";
        let matches = find_high_entropy_tokens(input, 5, 2.0);
        assert!(matches.is_empty(), "all-lowercase tokens should be skipped");
    }
}
