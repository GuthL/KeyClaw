## Summary

- Describe the change and the user or maintainer impact.

## Validation

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo build --locked`
- [ ] `cargo test --locked`
- [ ] `cargo test --locked --test e2e_cli -- --ignored --test-threads=1`
- [ ] `cargo doc --no-deps`

## Docs

- [ ] README updated if public behavior changed
- [ ] `docs/` updated if deeper reference material changed
- [ ] Screenshots or SVG assets updated if the repo-facing experience changed

## Notes

- Call out risks, follow-ups, or release considerations here.
