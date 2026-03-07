fn main() {
    let code = keyclaw::launcher::run_cli(std::env::args().skip(1).collect());
    std::process::exit(code);
}
