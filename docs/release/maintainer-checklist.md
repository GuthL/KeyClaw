# KeyClaw Maintainer Release Checklist

This checklist is the release source of truth for artifact naming, verification, publication, and rollback handling.

## Versioning

- Confirm the release version and tag format are aligned before cutting the release.
- Build archives with the documented `keyclaw-v{version}-{target}.tar.gz` naming.
- Ship binaries for `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`.

## Verification

- Run the release-candidate dry run documented in `docs/plans/2026-03-07-release-candidate-verification.md`.
- Build `target/release/keyclaw` and run `scripts/smoke-release.sh target/release/keyclaw` before publishing.
- Generate and publish `SHA256SUMS` alongside the release archives.
- Verify the archive contents and smoke results for every supported target.

## Publication

- Rehearse crates.io publication with `cargo publish --dry-run`.
- After the dry run is clean and the release assets are verified, perform the final publish with `cargo publish`.
- Publish the GitHub release assets and checksums that match the documented archive names.

## Rollback

- If publication or asset verification fails, pause the release and record known issues before retrying.
- If a bad release escapes, document the rollback steps, affected versions, and replacement artifacts before resuming publication.
