# Supported Secret Patterns

KeyClaw uses the bundled [`gitleaks.toml`](../gitleaks.toml) ruleset plus an entropy detector to decide what to redact from live traffic.

## What Gets Detected

The bundled rules cover several categories:

- **Cloud credentials:** AWS, GCP, Azure, and related provider access tokens
- **LLM/API provider keys:** OpenAI, Anthropic, Stripe, Slack, GitHub, GitLab, Twilio, and similar platform credentials
- **Generic patterns:** values assigned to names like `api_key`, `access_token`, `secret_key`, and related forms
- **Private key material:** PEM blocks for RSA, EC, OpenSSH, PGP, age, and similar formats
- **High-entropy tokens:** strings that do not match a provider-specific regex but still look secret-like

## Detection Pipeline

1. KeyClaw loads and compiles the bundled gitleaks rules into native Rust regexes.
2. Request payloads are scanned for rule matches.
3. Optional entropy detection catches sufficiently random token-like strings that were not matched by provider-specific rules.
4. Local allowlists are applied last to suppress intentionally safe matches.

## Placeholder Shape

KeyClaw rewrites each secret into a deterministic placeholder:

```text
{{KEYCLAW_SECRET_<prefix>_<16 hex chars>}}
```

Example:

```text
{{KEYCLAW_SECRET_api_k_77dc0005c514277d}}
```

## Custom Rules

To use a custom ruleset:

```bash
export KEYCLAW_GITLEAKS_CONFIG="$HOME/.config/keyclaw/gitleaks.toml"
keyclaw doctor
```

If the custom ruleset is invalid, `keyclaw doctor` surfaces that error and the runtime fails closed by default.

## Adding A New Secret Pattern

1. Edit [`gitleaks.toml`](../gitleaks.toml).
2. Run the targeted tests:

```bash
cargo test placeholder
cargo test --test integration_proxy
```

3. If loader or compiler behavior must change, update `src/gitleaks_rules.rs`.

## What This Does Not Guarantee

- Perfect coverage for every provider or credential format
- Protection for secrets that never enter proxied traffic
- Protection if the client bypasses the proxy entirely

For the trust boundary and deployment assumptions, see [threat-model.md](threat-model.md).
