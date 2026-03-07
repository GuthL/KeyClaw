#[test]
fn release_ci_workflow_covers_supported_matrix_and_gates() {
    let workflow = std::fs::read_to_string(".github/workflows/rust.yml")
        .expect("read .github/workflows/rust.yml");
    let lint = job_section(&workflow, "lint", Some("test"));
    let test = job_section(&workflow, "test", Some("release-build"));
    let release_build = job_section(&workflow, "release-build", None);

    assert!(
        workflow.contains("push:\n    branches: [ \"master\" ]"),
        "workflow should target master pushes: {workflow}"
    );
    assert!(
        workflow.contains("pull_request:\n    branches: [ \"master\" ]"),
        "workflow should target master pull requests: {workflow}"
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
