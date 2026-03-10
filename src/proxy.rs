//! Proxy server entrypoint and handler wiring.

mod common;
mod http;
mod streaming;
mod websocket;

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use hudsucker::{Proxy, rustls::crypto::aws_lc_rs};

use crate::errors::KeyclawError;
use crate::pipeline::Processor;

use self::common::{build_ca_authority, log_warn, normalize_hosts};

pub use self::common::{set_log_file, set_unsafe_log};

/// Configured proxy server ready to start.
pub struct Server {
    /// Local listen address.
    pub listen_addr: String,
    /// Lowercased hostnames eligible for interception.
    pub allowed_hosts: Vec<String>,
    /// Shared rewrite processor used by request and response handlers.
    pub processor: Arc<Processor>,
    /// Maximum request body size accepted for interception.
    pub max_body_bytes: i64,
    /// Timeout for request body collection before inspection.
    pub body_timeout: Duration,
    /// Optional persistent audit log path.
    pub audit_log_path: Option<PathBuf>,
    /// PEM-encoded local CA certificate.
    pub ca_cert_pem: String,
    /// PEM-encoded local CA private key.
    pub ca_key_pem: String,
    intercepted: Arc<AtomicI64>,
}

/// Handle to a running proxy instance.
pub struct RunningServer {
    /// Effective listen address after bind or fallback selection.
    pub addr: String,
    intercepted: Arc<AtomicI64>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

#[derive(Clone)]
struct KeyclawHttpHandler {
    allowed_hosts: Vec<String>,
    processor: Arc<Processor>,
    max_body_bytes: i64,
    body_timeout: Duration,
    audit_log_path: Option<PathBuf>,
    intercepted: Arc<AtomicI64>,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl RunningServer {
    /// Return the number of intercepted requests handled by this process.
    pub fn intercept_count(&self) -> i64 {
        self.intercepted.load(Ordering::SeqCst)
    }
}

impl Server {
    /// Create a new proxy server with the provided listen address, allowed
    /// hosts, processor, and runtime CA material.
    pub fn new(
        listen_addr: String,
        allowed_hosts: Vec<String>,
        processor: Arc<Processor>,
        ca_cert_pem: String,
        ca_key_pem: String,
    ) -> Self {
        Self {
            listen_addr,
            allowed_hosts: normalize_hosts(&allowed_hosts),
            processor,
            max_body_bytes: 2 * 1024 * 1024,
            body_timeout: Duration::from_secs(3),
            audit_log_path: None,
            ca_cert_pem,
            ca_key_pem,
            intercepted: Arc::new(AtomicI64::new(0)),
        }
    }

    /// Start the proxy and return a handle that can be dropped or shut down
    /// later.
    pub fn start(&self) -> Result<RunningServer, KeyclawError> {
        self.processor.warm_up()?;

        let bind_addr = if self.listen_addr.trim().is_empty() {
            "127.0.0.1:8877".to_string()
        } else {
            self.listen_addr.clone()
        };

        let listener = match TcpListener::bind(&bind_addr) {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                let fallback = "127.0.0.1:0";
                log_warn(format!(
                    "proxy listen address {bind_addr} is busy, falling back to {fallback}"
                ));
                TcpListener::bind(fallback).map_err(|fallback_err| {
                    KeyclawError::uncoded(format!(
                        "listen on {bind_addr} failed ({e}); fallback {fallback} failed ({fallback_err})"
                    ))
                })?
            }
            Err(e) => {
                return Err(KeyclawError::uncoded(format!(
                    "listen on {bind_addr} failed: {e}"
                )));
            }
        };
        let addr = listener
            .local_addr()
            .map_err(|e| KeyclawError::uncoded(format!("read local addr failed: {e}")))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| KeyclawError::uncoded(format!("set listener nonblocking failed: {e}")))?;

        let allowed_hosts = self.allowed_hosts.clone();
        let processor = Arc::clone(&self.processor);
        let intercepted = Arc::clone(&self.intercepted);
        let max_body_bytes = self.max_body_bytes;
        let body_timeout = self.body_timeout;
        let audit_log_path = self.audit_log_path.clone();

        let ca_cert_pem = self.ca_cert_pem.clone();
        let ca_key_pem = self.ca_key_pem.clone();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let ready_tx_err = ready_tx.clone();

        let join = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx_err.send(Err(format!("create tokio runtime failed: {e}")));
                    return;
                }
            };

            let result = runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .map_err(|e| format!("adopt listener failed: {e}"))?;

                let ca =
                    build_ca_authority(&ca_cert_pem, &ca_key_pem).map_err(|e| e.to_string())?;

                let handler = KeyclawHttpHandler {
                    allowed_hosts,
                    processor,
                    max_body_bytes,
                    body_timeout,
                    audit_log_path,
                    intercepted,
                };

                let shutdown = async move {
                    let _ = shutdown_rx.await;
                };

                let proxy = Proxy::builder()
                    .with_listener(listener)
                    .with_ca(ca)
                    .with_rustls_connector(aws_lc_rs::default_provider())
                    .with_http_handler(handler.clone())
                    .with_websocket_handler(handler)
                    .with_graceful_shutdown(shutdown)
                    .build()
                    .map_err(|e| format!("build proxy failed: {e}"))?;

                let _ = ready_tx.send(Ok(()));

                proxy
                    .start()
                    .await
                    .map_err(|e| format!("proxy exited with error: {e}"))
            });

            if let Err(err) = result {
                let _ = ready_tx_err.send(Err(err));
            }
        });

        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(RunningServer {
                addr: addr.to_string(),
                intercepted: Arc::clone(&self.intercepted),
                shutdown: Some(shutdown_tx),
                join: Some(join),
            }),
            Ok(Err(msg)) => Err(KeyclawError::uncoded(msg)),
            Err(_) => Err(KeyclawError::uncoded("proxy startup timeout")),
        }
    }
}
