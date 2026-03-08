mod common;
mod http;
mod streaming;
mod websocket;

use std::net::TcpListener;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use hudsucker::{rustls::crypto::aws_lc_rs, Proxy};

use crate::errors::KeyclawError;
use crate::pipeline::Processor;

use self::common::{build_ca_authority, log_warn, normalize_hosts};

pub use self::common::{set_log_file, set_unsafe_log};

pub struct Server {
    pub listen_addr: String,
    pub allowed_hosts: Vec<String>,
    pub processor: Arc<Processor>,
    pub max_body_bytes: i64,
    pub body_timeout: Duration,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    intercepted: Arc<AtomicI64>,
}

pub struct RunningServer {
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
    pub fn intercept_count(&self) -> i64 {
        self.intercepted.load(Ordering::SeqCst)
    }
}

impl Server {
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
            ca_cert_pem,
            ca_key_pem,
            intercepted: Arc::new(AtomicI64::new(0)),
        }
    }

    pub fn start(&self) -> Result<RunningServer, KeyclawError> {
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
