use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Serializes tests that mutate process-wide environment variables like HOME.
pub static PROCESS_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
