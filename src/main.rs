fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
        )
        .with_writer(std::io::stderr)
        .init();

    let code = keyclaw::launcher::run_cli(std::env::args().skip(1).collect());
    std::process::exit(code);
}
