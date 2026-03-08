mod bootstrap;
mod doctor;

use std::io::{self, Read, Write};
use std::sync::Arc;

use clap::error::ErrorKind;
use clap::{Arg, ArgMatches, ColorChoice};

use crate::config::Config;
use crate::errors::{code_of, KeyclawError};
use crate::pipeline::Processor;

use self::bootstrap::{build_processor, configure_unsafe_logging, run_proxy, Runner};
use self::doctor::run_doctor;

pub fn run_cli(args: Vec<String>) -> i32 {
    let command = match parse_cli(args) {
        Ok(command) => command,
        Err(err) => {
            let _ = err.print();
            return err.exit_code();
        }
    };

    let cfg = Config::from_env();
    crate::logging::configure(cfg.log_level);

    match command {
        CliCommand::Doctor => run_doctor(&cfg),
        CliCommand::Mitm { tool, child_args } => {
            configure_unsafe_logging(&cfg);
            match build_processor(&cfg) {
                Ok(processor) => run_mitm(&cfg, processor, &tool, child_args),
                Err(err) => {
                    print_error(&err);
                    1
                }
            }
        }
        CliCommand::Proxy => {
            configure_unsafe_logging(&cfg);
            match build_processor(&cfg) {
                Ok(processor) => run_proxy(&cfg, processor),
                Err(err) => {
                    print_error(&err);
                    1
                }
            }
        }
        CliCommand::RewriteJson => {
            configure_unsafe_logging(&cfg);
            match build_processor(&cfg) {
                Ok(processor) => run_rewrite_json(processor),
                Err(err) => {
                    print_error(&err);
                    1
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CliCommand {
    Doctor,
    Mitm {
        tool: String,
        child_args: Vec<String>,
    },
    Proxy,
    RewriteJson,
}

fn parse_cli(args: Vec<String>) -> Result<CliCommand, clap::Error> {
    let matches = cli()
        .try_get_matches_from(std::iter::once("keyclaw".to_string()).chain(args.into_iter()))?;

    match matches.subcommand() {
        Some(("doctor", _)) => Ok(CliCommand::Doctor),
        Some(("proxy", _)) => Ok(CliCommand::Proxy),
        Some(("rewrite-json", _)) => Ok(CliCommand::RewriteJson),
        Some(("mitm", subcommand)) => Ok(CliCommand::Mitm {
            tool: required_string_arg(subcommand, "tool", "mitm")?,
            child_args: subcommand
                .get_many::<String>("child_args")
                .map(|values| values.cloned().collect())
                .unwrap_or_default(),
        }),
        Some((name, _)) => Err(clap::Error::raw(
            ErrorKind::InvalidSubcommand,
            format!("unsupported subcommand `{name}`"),
        )),
        None => Err(clap::Error::raw(
            ErrorKind::MissingSubcommand,
            "a subcommand is required",
        )),
    }
}

fn required_string_arg(
    matches: &ArgMatches,
    name: &str,
    subcommand: &str,
) -> Result<String, clap::Error> {
    matches.get_one::<String>(name).cloned().ok_or_else(|| {
        clap::Error::raw(
            ErrorKind::MissingRequiredArgument,
            format!("missing required argument `{name}` for `{subcommand}`"),
        )
    })
}

fn cli() -> clap::Command {
    clap::Command::new("keyclaw")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Local MITM proxy for secret-safe AI CLI traffic")
        .color(ColorChoice::Never)
        .disable_help_subcommand(true)
        .subcommand_required(true)
        .subcommand(clap::Command::new("proxy").about("Start the global proxy daemon"))
        .subcommand(
            clap::Command::new("mitm")
                .about("Run a supported CLI behind the local MITM proxy")
                .arg(
                    Arg::new("tool")
                        .value_name("TOOL")
                        .help("CLI to launch through KeyClaw")
                        .required(true),
                )
                .arg(
                    Arg::new("child_args")
                        .value_name("CHILD_ARGS")
                        .help("Arguments forwarded to the child CLI")
                        .num_args(0..)
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true),
                ),
        )
        .subcommand(
            clap::Command::new("rewrite-json")
                .about("Read JSON from stdin, redact secrets, and write JSON to stdout"),
        )
        .subcommand(clap::Command::new("doctor").about("Run operator health checks"))
}

fn run_mitm(cfg: &Config, processor: Arc<Processor>, tool: &str, child_args: Vec<String>) -> i32 {
    let tool = tool.trim().to_lowercase();
    if tool != "codex" && tool != "claude" {
        crate::logging::error(&format!("unsupported tool \"{tool}\""));
        return 2;
    }

    let mut runner = Runner::new(cfg.clone(), processor);
    match runner.launch(&tool, child_args) {
        Ok(code) => code,
        Err(err) => {
            print_error(&err);
            1
        }
    }
}

fn run_rewrite_json(processor: Arc<Processor>) -> i32 {
    let mut input = Vec::new();
    if io::stdin().read_to_end(&mut input).is_err() {
        crate::logging::error("failed to read stdin");
        return 1;
    }

    match processor.rewrite_and_evaluate(&input) {
        Ok(result) => {
            if io::stdout().write_all(&result.body).is_err() {
                crate::logging::error("failed to write stdout");
                return 1;
            }
            0
        }
        Err(err) => {
            print_error(&err);
            1
        }
    }
}

fn print_error(err: &KeyclawError) {
    let code = code_of(err);
    let msg = err.display_without_code();
    if let Some(code) = code {
        crate::logging::error_with_code(code, &msg);
    } else {
        crate::logging::error(&msg);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn parse_cli_routes_simple_subcommands() {
        assert_eq!(
            super::parse_cli(vec!["doctor".into()]).unwrap(),
            super::CliCommand::Doctor
        );
        assert_eq!(
            super::parse_cli(vec!["proxy".into()]).unwrap(),
            super::CliCommand::Proxy
        );
        assert_eq!(
            super::parse_cli(vec!["rewrite-json".into()]).unwrap(),
            super::CliCommand::RewriteJson
        );
    }

    #[test]
    fn parse_cli_extracts_mitm_tool_and_child_args() {
        assert_eq!(
            super::parse_cli(vec![
                "mitm".into(),
                "codex".into(),
                "exec".into(),
                "--model".into(),
                "gpt-5".into(),
            ])
            .unwrap(),
            super::CliCommand::Mitm {
                tool: "codex".into(),
                child_args: vec!["exec".into(), "--model".into(), "gpt-5".into()],
            }
        );
    }

    #[test]
    fn launcher_bypass_risk_detects_exact_host_matches() {
        let risk = super::bootstrap::launcher_bypass_risk(
            "api.openai.com",
            &[
                String::from("api.openai.com"),
                String::from("api.anthropic.com"),
            ],
        );

        assert_eq!(risk.as_deref(), Some("NO_PROXY includes api.openai.com"));
    }

    #[test]
    fn launcher_bypass_risk_detects_suffix_matches() {
        let risk = super::bootstrap::launcher_bypass_risk(
            ".openai.com",
            &[String::from("api.openai.com")],
        );

        assert_eq!(
            risk.as_deref(),
            Some("NO_PROXY includes .openai.com (matches api.openai.com)")
        );
    }

    #[test]
    fn launcher_bypass_risk_detects_host_port_matches() {
        let risk = super::bootstrap::launcher_bypass_risk(
            "api.openai.com:443",
            &[String::from("api.openai.com")],
        );

        assert_eq!(
            risk.as_deref(),
            Some("NO_PROXY includes api.openai.com:443 (matches api.openai.com)")
        );
    }

    #[test]
    fn launcher_bypass_risk_normalizes_case_and_whitespace() {
        let risk = super::bootstrap::launcher_bypass_risk(
            " API.OPENAI.COM:443 ",
            &[String::from("api.openai.com")],
        );

        assert_eq!(
            risk.as_deref(),
            Some("NO_PROXY includes API.OPENAI.COM:443 (matches api.openai.com)")
        );
    }

    #[test]
    fn launcher_bypass_risk_ignores_unrelated_entries() {
        let risk = super::bootstrap::launcher_bypass_risk(
            "example.com,.internal.local",
            &[String::from("api.openai.com")],
        );

        assert_eq!(risk, None);
    }

    #[cfg(unix)]
    #[test]
    fn proxy_env_script_disables_stale_pid_reused_by_unrelated_process() {
        let temp = tempfile::tempdir().expect("tempdir");
        let env_path = temp.path().join("env.sh");
        let pid_path = temp.path().join("proxy.pid");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut unrelated = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn unrelated process");

        fs::write(&pid_path, unrelated.id().to_string()).expect("write proxy.pid");
        let script = super::bootstrap::render_proxy_env_script(
            unrelated.id(),
            "http://127.0.0.1:8877",
            Path::new("/tmp/keyclaw-ca.crt"),
            Path::new("/tmp/keyclaw"),
            &pid_path,
        );
        fs::write(&env_path, script).expect("write env.sh");

        let output = Command::new("bash")
            .arg("-lc")
            .arg(format!(
                "source \"{}\"; \
                 if [ -n \"${{HTTP_PROXY:-}}\" ]; then echo proxy=enabled; else echo proxy=disabled; fi; \
                 if [ -e \"{}\" ]; then echo pid=present; else echo pid=missing; fi",
                env_path.display(),
                pid_path.display()
            ))
            .env_clear()
            .env("PATH", path)
            .output()
            .expect("source env.sh");

        let _ = unrelated.kill();
        let _ = unrelated.wait();

        assert_eq!(
            output.status.code(),
            Some(0),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("proxy=disabled"), "stdout={stdout}");
        assert!(stdout.contains("pid=missing"), "stdout={stdout}");
    }
}
