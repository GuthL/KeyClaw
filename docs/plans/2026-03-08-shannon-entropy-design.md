# Shannon Entropy Secret Detection — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Shannon entropy analysis as a second detection pass that catches high-entropy tokens the gitleaks regex rules miss.

**Architecture:** New `src/entropy.rs` module computes Shannon entropy per token. `RuleSet::find_secrets()` calls it after regex matching, emitting unified `SecretMatch` entries with `rule_id: "entropy"`. Entropy config (threshold, min length, enabled flag) is stored on `RuleSet` and configured via env vars. No changes to pipeline, placeholder, redaction, or proxy code.

**Tech Stack:** Pure Rust, no new dependencies. Shannon entropy is `H = -Σ p(c) * log2(p(c))` over character frequencies.

---

### Task 1: Create `src/entropy.rs` with core entropy calculation

**Files:**
- Create: `src/entropy.rs`

**Step 1: Write the failing test**

Add to `src/entropy.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_entropy_of_uniform_distribution() {
        // 256 distinct bytes → log2(256) = 8.0
        let input: String = (0..=255u8).map(|b| b as char).collect();
        let e = shannon_entropy(&input);
        assert!((e - 8.0).abs() < 0.01, "entropy={e}");
    }

    #[test]
    fn shannon_entropy_of_single_char() {
        let e = shannon_entropy("aaaaaaaaaa");
        assert!((e - 0.0).abs() < 0.001, "entropy={e}");
    }

    #[test]
    fn shannon_entropy_of_empty_string() {
        let e = shannon_entropy("");
        assert!((e - 0.0).abs() < 0.001, "entropy={e}");
    }
}
```

**Step 2: Write minimal implementation**

```rust
/// Compute Shannon entropy (bits per character) of a string.
pub fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    let mut total = 0u32;

    for byte in input.bytes() {
        counts[byte as usize] += 1;
        total += 1;
    }

    let total_f = total as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total_f;
        entropy -= p * p.log2();
    }

    entropy
}
```

**Step 3: Run tests to verify they pass**

Run: `cargo test entropy -- --nocapture`
Expected: 3 tests PASS

**Step 4: Commit**

```
feat: add Shannon entropy calculation (entropy.rs)
```

---

### Task 2: Add tokenizer and high-entropy token finder

**Files:**
- Modify: `src/entropy.rs`

**Step 1: Write the failing tests**

```rust
#[test]
fn find_high_entropy_catches_base64_api_key() {
    let input = "here is my key: aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v please use it";
    let matches = find_high_entropy_tokens(input, 20, 3.5);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].token, "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v");
    assert!(matches[0].entropy >= 3.5);
}

#[test]
fn find_high_entropy_skips_english_prose() {
    let input = "the quick brown fox jumps over the lazy dog and keeps running";
    let matches = find_high_entropy_tokens(input, 20, 3.5);
    assert!(matches.is_empty(), "matches={matches:?}");
}

#[test]
fn find_high_entropy_skips_short_tokens() {
    let input = "abc123XYZ";
    let matches = find_high_entropy_tokens(input, 20, 3.5);
    assert!(matches.is_empty());
}

#[test]
fn find_high_entropy_returns_correct_byte_offsets() {
    let prefix = "key=";
    let secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
    let input = format!("{prefix}{secret}");
    let matches = find_high_entropy_tokens(&input, 20, 3.5);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].start, prefix.len());
    assert_eq!(matches[0].end, prefix.len() + secret.len());
    assert_eq!(&input[matches[0].start..matches[0].end], secret);
}

#[test]
fn find_high_entropy_skips_all_lowercase_alpha_tokens() {
    // A long all-lowercase token that happens to have decent entropy
    let input = "abcdefghijklmnopqrstuvwxyz";
    let matches = find_high_entropy_tokens(input, 20, 3.0);
    assert!(matches.is_empty(), "all-lowercase-alpha should be skipped");
}
```

**Step 2: Write implementation**

```rust
/// A high-entropy token found in text.
#[derive(Debug, Clone)]
pub struct EntropyMatch<'a> {
    pub start: usize,
    pub end: usize,
    pub token: &'a str,
    pub entropy: f64,
}

/// Characters that delimit tokens for entropy scanning.
fn is_delimiter(c: char) -> bool {
    matches!(
        c,
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

/// Returns true if the token is all ASCII lowercase letters (likely English).
fn is_all_lowercase_alpha(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| b.is_ascii_lowercase())
}

/// Find all high-entropy tokens in `input`.
///
/// A token is a contiguous run of non-delimiter characters.
/// Returns tokens with `len >= min_len` and `shannon_entropy >= threshold`.
pub fn find_high_entropy_tokens(input: &str, min_len: usize, threshold: f64) -> Vec<EntropyMatch<'_>> {
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

    // Handle trailing token
    if let Some(start) = token_start {
        check_token(input, start, input.len(), min_len, threshold, &mut matches);
    }

    matches
}

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
```

**Step 3: Run tests**

Run: `cargo test entropy -- --nocapture`
Expected: All 8 tests PASS

**Step 4: Commit**

```
feat: add high-entropy token finder with tokenizer
```

---

### Task 3: Add entropy config to `RuleSet` and integrate in `find_secrets()`

**Files:**
- Modify: `src/entropy.rs` (add `EntropyConfig`)
- Modify: `src/gitleaks_rules.rs` (store config, call entropy after regex)

**Step 1: Add `EntropyConfig` to `src/entropy.rs`**

```rust
/// Configuration for entropy-based secret detection.
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
```

**Step 2: Write the failing test in `src/gitleaks_rules.rs`**

```rust
#[test]
fn find_secrets_includes_entropy_matches() {
    let rules = RuleSet {
        rules: Vec::new(), // no regex rules
        skipped_rules: 0,
        entropy_config: EntropyConfig::default(),
    };

    // A high-entropy token that no regex rule would catch
    let input = "token=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
    let matches = rules.find_secrets(input);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_id, "entropy");
    assert_eq!(matches[0].secret, "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v");
}

#[test]
fn find_secrets_entropy_skips_ranges_already_caught_by_regex() {
    let rules = RuleSet::from_toml(
        r#"
[[rules]]
id = "generic-api-key"
regex = '[a-zA-Z0-9]{32}'
"#,
    )
    .expect("ruleset");

    let input = "key=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
    let matches = rules.find_secrets(input);

    // Should have exactly 1 match (regex), not 2
    assert_eq!(matches.len(), 1, "matches={matches:?}");
    assert_ne!(matches[0].rule_id, "entropy", "regex should take priority");
}

#[test]
fn find_secrets_entropy_disabled() {
    let rules = RuleSet {
        rules: Vec::new(),
        skipped_rules: 0,
        entropy_config: EntropyConfig {
            enabled: false,
            ..Default::default()
        },
    };

    let input = "token=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v";
    let matches = rules.find_secrets(input);
    assert!(matches.is_empty());
}
```

**Step 3: Update `RuleSet` struct and `find_secrets()`**

In `src/gitleaks_rules.rs`, add `entropy_config: EntropyConfig` to `RuleSet`. Update `from_toml`, `bundled`, and `from_file` to initialize it with `EntropyConfig::default()`. Update `find_secrets()` to call `entropy::find_high_entropy_tokens()` after regex matching, skipping overlapping ranges.

Key changes to `RuleSet`:

```rust
use crate::entropy::EntropyConfig;

pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub skipped_rules: usize,
    pub entropy_config: EntropyConfig,
}
```

In `find_secrets()`, after the regex loop and before the final sort, add:

```rust
if self.entropy_config.enabled {
    let entropy_matches = crate::entropy::find_high_entropy_tokens(
        input,
        self.entropy_config.min_len,
        self.entropy_config.threshold,
    );

    for em in entropy_matches {
        // Skip if overlaps with an existing regex match
        if matches.iter().any(|m| m.start < em.end && em.start < m.end) {
            continue;
        }
        // Skip if inside an existing placeholder
        if inside_placeholder(input, em.start, em.end) {
            continue;
        }
        matches.push(SecretMatch {
            rule_id: ENTROPY_RULE_ID,
            start: em.start,
            end: em.end,
            secret: em.token,
        });
    }
}
```

Add constant: `const ENTROPY_RULE_ID: &str = "entropy";`

**Step 4: Fix all existing `RuleSet` construction sites**

Any place that constructs `RuleSet` directly (tests in `gitleaks_rules.rs`, `pipeline.rs` tests) must now include `entropy_config`. Add `EntropyConfig::default()` to each.

Files to update:
- `src/gitleaks_rules.rs` — `from_toml()` and `bundled()` methods
- `tests/pipeline.rs:239` — `processor_with_limit` test helper
- Any other test that builds `RuleSet { rules: ..., skipped_rules: ... }`

**Step 5: Run tests**

Run: `cargo test -- --nocapture`
Expected: All tests PASS including the 3 new ones

**Step 6: Commit**

```
feat: integrate entropy detection into RuleSet::find_secrets()
```

---

### Task 4: Add env var configuration for entropy settings

**Files:**
- Modify: `src/config.rs` (add 3 entropy env vars)
- Modify: `src/launcher/bootstrap.rs` (pass entropy config to `RuleSet`)

**Step 1: Write the failing test in `src/config.rs`**

```rust
#[test]
fn from_env_reads_entropy_settings() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let keys = [
        "KEYCLAW_ENTROPY_ENABLED",
        "KEYCLAW_ENTROPY_THRESHOLD",
        "KEYCLAW_ENTROPY_MIN_LEN",
    ];
    let saved = capture_env(&keys);

    env::set_var("KEYCLAW_ENTROPY_ENABLED", "false");
    env::set_var("KEYCLAW_ENTROPY_THRESHOLD", "4.0");
    env::set_var("KEYCLAW_ENTROPY_MIN_LEN", "30");

    let cfg = Config::from_env();

    assert!(!cfg.entropy_enabled);
    assert!((cfg.entropy_threshold - 4.0).abs() < 0.001);
    assert_eq!(cfg.entropy_min_len, 30);

    restore_env(saved);
}

#[test]
fn from_env_uses_entropy_defaults() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let keys = [
        "KEYCLAW_ENTROPY_ENABLED",
        "KEYCLAW_ENTROPY_THRESHOLD",
        "KEYCLAW_ENTROPY_MIN_LEN",
    ];
    let saved = capture_env(&keys);

    env::remove_var("KEYCLAW_ENTROPY_ENABLED");
    env::remove_var("KEYCLAW_ENTROPY_THRESHOLD");
    env::remove_var("KEYCLAW_ENTROPY_MIN_LEN");

    let cfg = Config::from_env();

    assert!(cfg.entropy_enabled);
    assert!((cfg.entropy_threshold - 3.5).abs() < 0.001);
    assert_eq!(cfg.entropy_min_len, 20);

    restore_env(saved);
}
```

**Step 2: Add fields to `Config`**

```rust
pub struct Config {
    // ... existing fields ...
    pub entropy_enabled: bool,
    pub entropy_threshold: f64,
    pub entropy_min_len: usize,
}
```

In `from_env()`:
```rust
entropy_enabled: bool_env("KEYCLAW_ENTROPY_ENABLED", true),
entropy_threshold: f64_env("KEYCLAW_ENTROPY_THRESHOLD", 3.5),
entropy_min_len: usize_env("KEYCLAW_ENTROPY_MIN_LEN", 20),
```

Add helper functions:
```rust
fn f64_env(key: &str, fallback: f64) -> f64 {
    match env::var(key) {
        Ok(v) => v.trim().parse::<f64>().unwrap_or(fallback),
        Err(_) => fallback,
    }
}

fn usize_env(key: &str, fallback: usize) -> usize {
    match env::var(key) {
        Ok(v) => v.trim().parse::<usize>().unwrap_or(fallback),
        Err(_) => fallback,
    }
}
```

**Step 3: Wire entropy config in `bootstrap.rs`**

In `build_processor()`, after loading the ruleset, set:

```rust
ruleset.entropy_config = EntropyConfig {
    enabled: cfg.entropy_enabled,
    threshold: cfg.entropy_threshold,
    min_len: cfg.entropy_min_len,
};
```

**Step 4: Update `test_config` in `bootstrap.rs` tests**

Add the 3 new fields with defaults.

**Step 5: Run tests**

Run: `cargo test -- --nocapture`
Expected: All tests PASS

**Step 6: Commit**

```
feat: add KEYCLAW_ENTROPY_* env var configuration
```

---

### Task 5: Register `entropy` module in `lib.rs`

**Files:**
- Modify: `src/lib.rs`

**Step 1: Add module declaration**

```rust
pub mod entropy;
```

This must be done early (before Task 1's tests can compile), so in practice this step is folded into Task 1. Listed here for completeness — if building sequentially, add this line when creating `src/entropy.rs`.

---

### Task 6: Add integration test for entropy in the full pipeline

**Files:**
- Modify: `tests/pipeline.rs`

**Step 1: Write the test**

```rust
#[test]
fn rewrite_detects_high_entropy_token_not_matched_by_regex() {
    let processor = make_processor(false);

    // A custom internal token that no gitleaks regex catches but has high entropy
    let body = br#"{"messages":[{"role":"user","content":"connect with token xK9mP2vL8nQ4wR6tY0uI3oA5sD7fG1hJ"}]}"#;
    let result = processor.rewrite_and_evaluate(body).expect("rewrite");

    let rewritten = String::from_utf8_lossy(&result.body);
    // The token should be caught by entropy analysis
    assert!(
        !rewritten.contains("xK9mP2vL8nQ4wR6tY0uI3oA5sD7fG1hJ"),
        "high-entropy token should be redacted: {rewritten}"
    );
}
```

Note: This test may or may not flag the token depending on whether the bundled gitleaks rules catch it first. If the rules do catch it, the test still passes (the token is redacted either way). The key assertion is that the token does NOT appear in the rewritten output.

**Step 2: Run tests**

Run: `cargo test pipeline -- --nocapture`
Expected: PASS

**Step 3: Commit**

```
test: add pipeline integration test for entropy detection
```

---

### Task 7: Final build and full test suite

**Step 1: Full build**

Run: `cargo build --release`
Expected: Compiles without warnings

**Step 2: Full test suite**

Run: `cargo test`
Expected: All tests PASS

**Step 3: Commit any fixups, then final commit**

```
feat: Shannon entropy secret detection (closes #52)
```

---

## Execution Order Summary

| Task | What | New/Modified Files |
|------|------|--------------------|
| 1 | Core `shannon_entropy()` function | Create `src/entropy.rs`, modify `src/lib.rs` |
| 2 | Tokenizer + `find_high_entropy_tokens()` | Modify `src/entropy.rs` |
| 3 | `EntropyConfig` + integrate in `RuleSet::find_secrets()` | Modify `src/entropy.rs`, `src/gitleaks_rules.rs` |
| 4 | Env var configuration | Modify `src/config.rs`, `src/launcher/bootstrap.rs` |
| 5 | (Folded into Task 1) | `src/lib.rs` |
| 6 | Pipeline integration test | Modify `tests/pipeline.rs` |
| 7 | Final build + full test suite | — |
