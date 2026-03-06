use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use tempfile::Builder;

use crate::errors::KeyclawError;
use crate::placeholder;

const FILE_VERSION: i32 = 1;

#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    passphrase: String,
    lock: Mutex<()>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileEnvelope {
    version: i32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

impl Store {
    pub fn new(path: impl Into<PathBuf>, passphrase: String) -> Self {
        Self {
            path: path.into(),
            passphrase,
            lock: Mutex::new(()),
        }
    }

    pub fn save(&self, entries: &HashMap<String, String>) -> Result<(), KeyclawError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| KeyclawError::uncoded("vault mutex poisoned"))?;

        let plaintext = serde_json::to_vec(entries)
            .map_err(|e| KeyclawError::uncoded_with_source("marshal vault plaintext", e))?;

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(&self.passphrase, &salt)?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| KeyclawError::uncoded_with_source("create aes-gcm cipher", e))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| KeyclawError::uncoded(format!("encrypt vault payload: {e}")))?;

        let payload = FileEnvelope {
            version: FILE_VERSION,
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce_bytes),
            ciphertext: BASE64.encode(ciphertext),
        };
        let encoded = serde_json::to_vec(&payload)
            .map_err(|e| KeyclawError::uncoded_with_source("marshal vault payload", e))?;

        atomic_write(&self.path, &encoded, 0o600)
    }

    pub fn load(&self) -> Result<HashMap<String, String>, KeyclawError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| KeyclawError::uncoded("vault mutex poisoned"))?;

        let bytes = match fs::read(&self.path) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(e) => return Err(KeyclawError::uncoded_with_source("read vault file", e)),
        };

        let payload: FileEnvelope = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(HashMap::new()),
        };
        if payload.version != FILE_VERSION {
            return Ok(HashMap::new());
        }

        let salt = match BASE64.decode(payload.salt) {
            Ok(v) => v,
            Err(_) => return Ok(HashMap::new()),
        };
        let nonce = match BASE64.decode(payload.nonce) {
            Ok(v) => v,
            Err(_) => return Ok(HashMap::new()),
        };
        let ciphertext = match BASE64.decode(payload.ciphertext) {
            Ok(v) => v,
            Err(_) => return Ok(HashMap::new()),
        };

        let key = derive_key(&self.passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| KeyclawError::uncoded_with_source("create aes-gcm cipher", e))?;
        if nonce.len() != 12 {
            return Ok(HashMap::new());
        }
        let plaintext = match cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref()) {
            Ok(v) => v,
            Err(_) => return Ok(HashMap::new()),
        };

        let entries: Option<HashMap<String, String>> = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(_) => return Ok(HashMap::new()),
        };
        Ok(entries.unwrap_or_default())
    }

    pub fn store_secret(&self, secret: &str) -> Result<String, KeyclawError> {
        let mut entries = self.load()?;
        let id = placeholder::make_id(secret);
        entries.insert(id.clone(), secret.to_string());
        self.save(&entries)?;
        Ok(id)
    }

    pub fn resolve(&self, id: &str) -> Result<Option<String>, KeyclawError> {
        let entries = self.load()?;
        Ok(entries.get(id).cloned())
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], KeyclawError> {
    // Keep KDF cost meaningful while avoiding proxy request timeouts in debug/test runs.
    let params = ScryptParams::new(13, 8, 1, 32)
        .map_err(|e| KeyclawError::uncoded_with_source("configure scrypt", e))?;

    let mut key = [0u8; 32];
    scrypt(passphrase.as_bytes(), salt, &params, &mut key)
        .map_err(|e| KeyclawError::uncoded_with_source("derive key", e))?;
    Ok(key)
}

fn atomic_write(path: &Path, content: &[u8], perm: u32) -> Result<(), KeyclawError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)
        .map_err(|e| KeyclawError::uncoded_with_source("create vault dir", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }

    let mut tmp = Builder::new()
        .prefix(".vault-tmp-")
        .tempfile_in(dir)
        .map_err(|e| KeyclawError::uncoded_with_source("create temp file", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(perm))
            .map_err(|e| KeyclawError::uncoded_with_source("chmod temp file", e))?;
    }
    #[cfg(not(unix))]
    {
        let _ = perm;
    }

    tmp.write_all(content)
        .map_err(|e| KeyclawError::uncoded_with_source("write temp file", e))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|e| KeyclawError::uncoded_with_source("sync temp file", e))?;

    tmp.persist(path)
        .map_err(|e| KeyclawError::uncoded_with_source("rename temp file", e.error))?;

    if let Ok(dir_file) = File::open(dir) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}
