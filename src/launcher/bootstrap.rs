mod autostart;
mod detection;
mod no_proxy;
mod proxy_daemon;
mod runner;

pub(super) use autostart::{
    run_proxy_autostart_disable, run_proxy_autostart_enable, run_proxy_autostart_status,
};
pub(super) use detection::{build_processor, configure_unsafe_logging};
pub(super) use no_proxy::launcher_bypass_risk;
#[cfg(test)]
pub(super) use proxy_daemon::render_proxy_env_script;
pub(super) use proxy_daemon::{
    run_proxy_detached, run_proxy_foreground, run_proxy_status, run_proxy_stop,
};
pub(super) use runner::Runner;

#[cfg(test)]
mod tests;
