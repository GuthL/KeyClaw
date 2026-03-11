# Maintainer Release Checklist

This is the source of truth for releasing KeyClaw.

## Targets And Artifacts

Supported release targets:

- `x86_64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Published artifacts must include:

- `keyclaw-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
- `keyclaw-vX.Y.Z-x86_64-apple-darwin.tar.gz`
- `keyclaw-vX.Y.Z-aarch64-apple-darwin.tar.gz`
- `SHA256SUMS`

Each archive should contain at least:

- `keyclaw`
- `README.md`
- `LICENSE`
- `SECURITY.md`

## Versioning

1. Update the version in `Cargo.toml`.
2. Confirm the release notes and public docs match the shipped runtime.
3. Make sure any compatibility or operator-facing behavior changes are called
   out explicitly.
4. Create the git tag as `vX.Y.Z`.

## Verification

Run the standard fast loop first:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release --locked
cargo test --locked
```

Run the slow daemon/proxy tier:

```bash
cargo test --locked --test e2e_cli -- --ignored --test-threads=1
```

Run the package and contract verification scripts:

```bash
scripts/package-release.sh X.Y.Z x86_64-unknown-linux-gnu target/release/keyclaw dist
scripts/verify-release-contract.sh X.Y.Z dist
scripts/smoke-release.sh target/release/keyclaw
```

Before publishing to crates.io, rehearse publication locally:

```bash
cargo publish --dry-run --locked
```

Keep the documented release dry run handy:

- `docs/plans/2026-03-07-release-candidate-verification.md`

## Publication

1. Push the release commit and tag.
2. Let the GitHub release workflow build the target matrix and draft the
   release.
3. Confirm the draft release contains the three archives and `SHA256SUMS`.
4. Publish the crate:

```bash
cargo publish --locked
```

5. Publish the GitHub release draft after artifact verification.
6. Confirm the Homebrew tap update, if configured, points at the same version.

## Rollback

If the release is broken after publication:

1. mark the GitHub release clearly as broken or add a prominent known-issues
   note
2. publish a follow-up patch release instead of force-rewriting history
3. document the operator impact in the release notes
4. if crates.io publication is the problem, yank the crate version when that is
   the least disruptive fix

## Known Issues

Track any release-specific caveats in the GitHub release notes. Prefer a short,
operator-facing statement over a vague internal note.
