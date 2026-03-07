#[test]
fn launcher_module_stays_thin_and_delegates_doctor_and_bootstrap() {
    let launcher = std::fs::read_to_string("src/launcher.rs").expect("read src/launcher.rs");

    assert!(
        launcher.contains("mod bootstrap;"),
        "launcher.rs should delegate runtime bootstrap helpers to a submodule: {launcher}"
    );
    assert!(
        launcher.contains("mod doctor;"),
        "launcher.rs should delegate doctor logic to a submodule: {launcher}"
    );

    for marker in [
        "struct Runner {",
        "fn build_processor(",
        "fn check_proxy_bind(",
        "fn resolve_ca_cert_path(",
    ] {
        assert!(
            !launcher.contains(marker),
            "launcher.rs should not keep `{marker}` after the split: {launcher}"
        );
    }
}
