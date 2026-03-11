#[test]
fn release_ci_workflow_covers_supported_matrix_and_gates() {
    let workflow = std::fs::read_to_string(".github/workflows/rust.yml")
        .expect("read .github/workflows/rust.yml");
    let lint = job_section(&workflow, "lint", Some("test"));
    let test = job_section(&workflow, "test", Some("release-build"));
    let release_build = job_section(&workflow, "release-build", Some("publish-dry-run"));
    let publish_dry_run = job_section(&workflow, "publish-dry-run", None);

    assert!(
        workflow.contains("push:\n    branches: [ \"master\", \"main\" ]"),
        "workflow should target master and main pushes: {workflow}"
    );
    assert!(
        workflow.contains("pull_request:\n    branches: [ \"master\", \"main\" ]"),
        "workflow should target master and main pull requests: {workflow}"
    );
    assert!(
        lint.contains("matrix:"),
        "lint job should run as a matrix: {lint}"
    );
    assert!(
        lint.contains("ubuntu-latest") && lint.contains("macos-latest"),
        "lint job should cover linux and macOS: {lint}"
    );
    assert!(
        lint.contains("cargo fmt --check"),
        "lint job should run rustfmt: {lint}"
    );
    assert!(
        lint.contains("cargo clippy --all-targets --all-features -- -D warnings"),
        "lint job should run clippy with warnings denied: {lint}"
    );
    assert!(
        test.contains("ubuntu-latest") && test.contains("macos-latest"),
        "test job should cover linux and macOS: {test}"
    );
    assert!(
        test.contains("cargo test --locked"),
        "test job should run the full test suite: {test}"
    );
    assert!(
        release_build.contains("ubuntu-latest") && release_build.contains("macos-latest"),
        "release-build job should cover linux and macOS: {release_build}"
    );
    assert!(
        release_build.contains("cargo build --release --locked"),
        "release-build job should build release artifacts: {release_build}"
    );
    assert!(
        publish_dry_run.contains("ubuntu-latest"),
        "publish-dry-run job should run on Linux: {publish_dry_run}"
    );
    assert!(
        publish_dry_run.contains("cargo publish --dry-run --locked"),
        "publish-dry-run job should rehearse crates.io publication in CI: {publish_dry_run}"
    );
}

#[test]
fn contributor_validation_splits_fast_and_slow_loops() {
    let contributing = std::fs::read_to_string("CONTRIBUTING.md").expect("read CONTRIBUTING.md");
    let pr_template = std::fs::read_to_string(".github/pull_request_template.md")
        .expect("read .github/pull_request_template.md");
    let ci =
        std::fs::read_to_string(".github/workflows/ci.yml").expect("read .github/workflows/ci.yml");

    let fast = "cargo test --locked";
    let slow = "cargo test --locked --test e2e_cli -- --ignored --test-threads=1";

    assert!(
        contributing.contains("Routine local iteration") && contributing.contains(fast),
        "CONTRIBUTING should document the fast local loop: {contributing}"
    );
    assert!(
        contributing.contains("Full verification before a pull request")
            && contributing.contains(slow),
        "CONTRIBUTING should document the slow daemon/proxy verification tier: {contributing}"
    );
    assert!(
        pr_template.contains(fast) && pr_template.contains(slow),
        "PR template should ask contributors for both the fast and slow verification commands: {pr_template}"
    );
    assert!(
        ci.contains("cargo test --locked")
            && ci.contains("cargo test --locked --test e2e_cli -- --ignored --test-threads=1"),
        "CI should keep the slow ignored daemon/proxy tier covered explicitly: {ci}"
    );
}

#[test]
fn contributing_release_docs_point_to_repo_release_contract() {
    let contributing = std::fs::read_to_string("CONTRIBUTING.md").expect("read CONTRIBUTING.md");

    for required in [
        "scripts/package-release.sh",
        "scripts/smoke-release.sh",
        "scripts/verify-release-contract.sh",
        "scripts/render-homebrew-formula.sh",
        ".github/workflows/release.yml",
        "cargo publish --dry-run --locked",
    ] {
        assert!(
            contributing.contains(required),
            "CONTRIBUTING should document `{required}` in the release contract: {contributing}"
        );
    }
}

#[test]
fn cargo_manifest_is_ready_for_crates_io_publication() {
    let manifest = std::fs::read_to_string("Cargo.toml").expect("read Cargo.toml");
    let gitignore = std::fs::read_to_string(".gitignore").expect("read .gitignore");

    for required in [
        "description = ",
        "license = ",
        "readme = ",
        "repository = ",
        "homepage = ",
    ] {
        assert!(
            manifest.contains(required),
            "Cargo.toml should include {required} for crates.io publication: {manifest}"
        );
    }

    assert!(
        gitignore.contains("*.bak"),
        ".gitignore should ignore local backup files so publish rehearsal stays clean: {gitignore}"
    );
    assert!(
        gitignore.contains("docs/plans/") && gitignore.contains("docs/release/"),
        ".gitignore should ignore internal plan and release docs: {gitignore}"
    );
}

#[test]
fn tagged_release_workflow_packages_documented_archives_and_checksums() {
    let workflow = std::fs::read_to_string(".github/workflows/release.yml")
        .expect("read .github/workflows/release.yml");

    assert!(
        workflow.contains("tags: [ \"v*\" ]"),
        "release workflow should trigger on version tags: {workflow}"
    );
    assert!(
        workflow.contains("x86_64-unknown-linux-gnu")
            && workflow.contains("x86_64-apple-darwin")
            && workflow.contains("aarch64-apple-darwin"),
        "release workflow should build every documented release target: {workflow}"
    );
    assert!(
        workflow.contains("cargo build --release --locked --target"),
        "release workflow should build tagged release binaries: {workflow}"
    );
    assert!(
        workflow.contains("scripts/package-release.sh"),
        "release workflow should package archives through the shared script: {workflow}"
    );
    assert!(
        workflow.contains("SHA256SUMS"),
        "release workflow should generate published checksums: {workflow}"
    );
    assert!(
        workflow.contains("softprops/action-gh-release"),
        "release workflow should attach packaged assets to a GitHub release draft: {workflow}"
    );
}

#[test]
fn release_packaging_scripts_enforce_archive_contract() {
    let package_script = std::fs::read_to_string("scripts/package-release.sh")
        .expect("read scripts/package-release.sh");
    let smoke_script =
        std::fs::read_to_string("scripts/smoke-release.sh").expect("read scripts/smoke-release.sh");
    let verify_script = std::fs::read_to_string("scripts/verify-release-contract.sh")
        .expect("read scripts/verify-release-contract.sh");

    for required in ["README.md", "LICENSE", "SECURITY.md"] {
        assert!(
            package_script.contains(required),
            "package script should ship {required}: {package_script}"
        );
    }
    assert!(
        package_script.contains("keyclaw-v${version}-${target}.tar.gz"),
        "package script should emit the documented archive naming: {package_script}"
    );
    assert!(
        verify_script.contains("SHA256SUMS"),
        "verification script should check the published checksum file: {verify_script}"
    );
    assert!(
        verify_script.contains("tar -tzf"),
        "verification script should inspect archive contents: {verify_script}"
    );
    for required in ["doctor", "proxy", "codex", "claude"] {
        assert!(
            smoke_script.contains(required),
            "smoke script should cover {required}: {smoke_script}"
        );
    }
}

fn job_section<'a>(workflow: &'a str, job: &str, next_job: Option<&str>) -> &'a str {
    let marker = format!("\n  {job}:\n");
    let start = workflow.find(&marker).expect("job section start") + 1;
    let rest = &workflow[start..];
    if let Some(next_job) = next_job {
        let next_marker = format!("\n  {next_job}:\n");
        let end = rest.find(&next_marker).expect("next job section start");
        &rest[..end]
    } else {
        rest
    }
}
