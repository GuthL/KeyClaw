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
pub const LEGACY_DEFAULT_VAULT_PASSPHRASE: &str = "keyclaw-default-passphrase";

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

#[derive(Debug, Clone)]
pub(crate) enum VaultPassphraseStatus {
    EnvOverride,
    LegacyEnvOverride,
    GeneratedKeyReady(PathBuf),
    GeneratedKeyWillBeCreated(PathBuf),
    LegacyVaultWillMigrate(PathBuf),
}

enum VaultLoadFailure {
    Missing,
    WrongPassphrase,
    Error(KeyclawError),
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
        save_entries(&self.path, &self.passphrase, entries)
    }

    pub fn load(&self) -> Result<HashMap<String, String>, KeyclawError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| KeyclawError::uncoded("vault mutex poisoned"))?;
        match load_entries(&self.path, &self.passphrase) {
            Ok(entries) => Ok(entries),
            Err(VaultLoadFailure::Missing) => Ok(HashMap::new()),
            Err(VaultLoadFailure::WrongPassphrase) => Err(KeyclawError::uncoded(format!(
                "vault {} could not be decrypted with the configured key material; restore the correct key or set KEYCLAW_VAULT_PASSPHRASE",
                self.path.display()
            ))),
            Err(VaultLoadFailure::Error(err)) => Err(err),
        }
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

pub fn vault_key_path(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("key")
}

pub fn resolve_vault_passphrase(
    vault_path: &Path,
    configured_passphrase: Option<&str>,
) -> Result<String, KeyclawError> {
    if let Some(passphrase) = normalized_passphrase(configured_passphrase) {
        return Ok(passphrase.to_string());
    }

    let key_path = vault_key_path(vault_path);
    if key_path.exists() {
        return read_vault_key(&key_path);
    }

    if !vault_path.exists() {
        return create_vault_key(&key_path);
    }

    match load_entries(vault_path, LEGACY_DEFAULT_VAULT_PASSPHRASE) {
        Ok(entries) => migrate_legacy_vault(vault_path, &key_path, &entries),
        Err(VaultLoadFailure::WrongPassphrase) => {
            Err(missing_vault_key_error(vault_path, &key_path))
        }
        Err(VaultLoadFailure::Missing) => create_vault_key(&key_path),
        Err(VaultLoadFailure::Error(err)) => Err(err),
    }
}

pub(crate) fn inspect_vault_passphrase_status(
    vault_path: &Path,
    configured_passphrase: Option<&str>,
) -> Result<VaultPassphraseStatus, KeyclawError> {
    if let Some(passphrase) = normalized_passphrase(configured_passphrase) {
        return if passphrase == LEGACY_DEFAULT_VAULT_PASSPHRASE {
            Ok(VaultPassphraseStatus::LegacyEnvOverride)
        } else {
            Ok(VaultPassphraseStatus::EnvOverride)
        };
    }

    let key_path = vault_key_path(vault_path);
    if key_path.exists() {
        read_vault_key(&key_path)?;
        return Ok(VaultPassphraseStatus::GeneratedKeyReady(key_path));
    }

    if !vault_path.exists() {
        return Ok(VaultPassphraseStatus::GeneratedKeyWillBeCreated(key_path));
    }

    match load_entries(vault_path, LEGACY_DEFAULT_VAULT_PASSPHRASE) {
        Ok(_) => Ok(VaultPassphraseStatus::LegacyVaultWillMigrate(key_path)),
        Err(VaultLoadFailure::WrongPassphrase) => {
            Err(missing_vault_key_error(vault_path, &key_path))
        }
        Err(VaultLoadFailure::Missing) => {
            Ok(VaultPassphraseStatus::GeneratedKeyWillBeCreated(key_path))
        }
        Err(VaultLoadFailure::Error(err)) => Err(err),
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

fn save_entries(
    path: &Path,
    passphrase: &str,
    entries: &HashMap<String, String>,
) -> Result<(), KeyclawError> {
    let plaintext = serde_json::to_vec(entries)
        .map_err(|e| KeyclawError::uncoded_with_source("marshal vault plaintext", e))?;

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt)?;

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

    atomic_write(path, &encoded, 0o600)
}

fn load_entries(
    path: &Path,
    passphrase: &str,
) -> Result<HashMap<String, String>, VaultLoadFailure> {
    let bytes = match fs::read(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VaultLoadFailure::Missing)
        }
        Err(e) => {
            return Err(VaultLoadFailure::Error(KeyclawError::uncoded_with_source(
                format!("read vault file {}", path.display()),
                e,
            )))
        }
    };

    let payload: FileEnvelope = serde_json::from_slice(&bytes)
        .map_err(|_| VaultLoadFailure::Error(invalid_vault_error(path, "invalid JSON envelope")))?;
    if payload.version != FILE_VERSION {
        return Err(VaultLoadFailure::Error(invalid_vault_error(
            path,
            "unsupported vault version",
        )));
    }

    let salt = BASE64
        .decode(payload.salt)
        .map_err(|_| VaultLoadFailure::Error(invalid_vault_error(path, "invalid salt encoding")))?;
    let nonce = BASE64.decode(payload.nonce).map_err(|_| {
        VaultLoadFailure::Error(invalid_vault_error(path, "invalid nonce encoding"))
    })?;
    let ciphertext = BASE64.decode(payload.ciphertext).map_err(|_| {
        VaultLoadFailure::Error(invalid_vault_error(path, "invalid ciphertext encoding"))
    })?;

    let key = derive_key(passphrase, &salt).map_err(VaultLoadFailure::Error)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        VaultLoadFailure::Error(KeyclawError::uncoded_with_source(
            "create aes-gcm cipher",
            e,
        ))
    })?;
    if nonce.len() != 12 {
        return Err(VaultLoadFailure::Error(invalid_vault_error(
            path,
            "invalid nonce length",
        )));
    }

    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| VaultLoadFailure::WrongPassphrase)?;

    let entries: Option<HashMap<String, String>> =
        serde_json::from_slice(&plaintext).map_err(|_| {
            VaultLoadFailure::Error(invalid_vault_error(path, "invalid decrypted payload"))
        })?;
    Ok(entries.unwrap_or_default())
}

fn normalized_passphrase(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn create_vault_key(key_path: &Path) -> Result<String, KeyclawError> {
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let key = BASE64.encode(key_bytes);
    atomic_write(key_path, key.as_bytes(), 0o600)?;
    Ok(key)
}

fn read_vault_key(key_path: &Path) -> Result<String, KeyclawError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(key_path).map_err(|err| {
            KeyclawError::uncoded(format!(
                "cannot access vault key {}: {err}",
                key_path.display()
            ))
        })?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyclawError::uncoded(format!(
                "vault key {} is too broadly readable; run `chmod 600 {}`",
                key_path.display(),
                key_path.display()
            )));
        }
    }

    let key = fs::read_to_string(key_path).map_err(|err| {
        KeyclawError::uncoded(format!(
            "cannot read vault key {}: {err}",
            key_path.display()
        ))
    })?;
    let key = key.trim();
    if key.is_empty() {
        return Err(KeyclawError::uncoded(format!(
            "vault key {} is empty; restore it or set KEYCLAW_VAULT_PASSPHRASE",
            key_path.display()
        )));
    }
    Ok(key.to_string())
}

fn migrate_legacy_vault(
    vault_path: &Path,
    key_path: &Path,
    entries: &HashMap<String, String>,
) -> Result<String, KeyclawError> {
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let new_passphrase = BASE64.encode(key_bytes);

    save_entries(vault_path, &new_passphrase, entries)?;
    if let Err(err) = atomic_write(key_path, new_passphrase.as_bytes(), 0o600) {
        let _ = save_entries(vault_path, LEGACY_DEFAULT_VAULT_PASSPHRASE, entries);
        return Err(err);
    }

    Ok(new_passphrase)
}

fn missing_vault_key_error(vault_path: &Path, key_path: &Path) -> KeyclawError {
    KeyclawError::uncoded(format!(
        "vault key {} is required to read existing vault {}; restore it or set KEYCLAW_VAULT_PASSPHRASE",
        key_path.display(),
        vault_path.display()
    ))
}

fn invalid_vault_error(path: &Path, reason: &str) -> KeyclawError {
    KeyclawError::uncoded(format!(
        "vault {} is invalid ({reason}); restore it from backup or remove it to start fresh",
        path.display()
    ))
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
