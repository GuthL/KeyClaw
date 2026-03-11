# KeyClaw Release Candidate Verification

This plan records the dry run used to validate a release candidate before publication.

## Scope

- Build `target/release/keyclaw` for the documented targets.
- Run `scripts/smoke-release.sh target/release/keyclaw`.
- Confirm archive naming, packaged contents, and `SHA256SUMS`.
- Rehearse crates.io publication with `cargo publish --dry-run`.

## Exit Criteria

- The release artifacts match `keyclaw-v{version}-{target}.tar.gz`.
- Smoke verification passes for the packaged binary.
- Checksums are generated and ready for publication.
- Any known issues are documented before the final `cargo publish` step.
