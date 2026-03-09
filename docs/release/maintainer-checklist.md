# KeyClaw Maintainer Release Checklist

This checklist is the release source of truth for artifact naming, verification, publication, and rollback handling.

## Versioning

1. Confirm the release tag is in `v{version}` format and matches `Cargo.toml`.
2. Confirm the supported release targets remain:
   - `x86_64-unknown-linux-gnu`
   - `x86_64-apple-darwin`
   - `aarch64-apple-darwin`
3. Confirm the published archives follow the documented naming contract:
   - `keyclaw-v{version}-x86_64-unknown-linux-gnu.tar.gz`
   - `keyclaw-v{version}-x86_64-apple-darwin.tar.gz`
   - `keyclaw-v{version}-aarch64-apple-darwin.tar.gz`
4. Confirm the release payload also includes `SHA256SUMS`.

## Verification

1. Review [docs/plans/2026-03-07-release-candidate-verification.md](/home/claw/KeyClaw/docs/plans/2026-03-07-release-candidate-verification.md) before cutting the tag.
2. Run the standard local release gate:
   - `cargo fmt --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo test`
   - `cargo build --release`
3. Run the operator smoke suite against the release binary:
   - `scripts/smoke-release.sh target/release/keyclaw`
4. Rehearse crates.io publication:
   - `cargo publish --dry-run`
5. Verify tagged release artifacts and checksums:
   - release workflow outputs the three `.tar.gz` archives above
   - release workflow outputs `SHA256SUMS`
   - packaged archives include `keyclaw`, `README.md`, `LICENSE`, and `SECURITY.md`

## Publication

1. Push the `v{version}` tag after local verification is green.
2. Confirm `.github/workflows/release.yml` builds the three supported targets and uploads draft assets.
3. Review the generated draft GitHub Release artifacts and `SHA256SUMS`.
4. Publish to crates.io:
   - `cargo publish`
5. Publish the GitHub Release after final maintainer verification.

## Rollback

1. If artifact verification fails, delete the draft release assets and cut a new tag from a corrected commit.
2. If crates.io publication is blocked, do not publish a GitHub Release that implies crates.io availability.
3. If a known issue is accepted for the release, document it in the GitHub Release notes before publishing.
