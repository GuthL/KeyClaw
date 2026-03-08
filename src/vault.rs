use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

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
    lock: Mutex<VaultCryptoState>,
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

#[derive(Debug, Default)]
struct VaultCryptoState {
    salt: Option<[u8; 16]>,
    key: Option<[u8; 32]>,
}

impl Store {
    pub fn new(path: impl Into<PathBuf>, passphrase: String) -> Self {
        Self {
            path: path.into(),
            passphrase,
            lock: Mutex::new(VaultCryptoState::default()),
        }
    }

    pub fn save(&self, entries: &HashMap<String, String>) -> Result<(), KeyclawError> {
        let mut state = self.lock_entries()?;
        save_entries(&self.path, &self.passphrase, &mut state, entries)
    }

    pub fn load(&self) -> Result<HashMap<String, String>, KeyclawError> {
        let mut state = self.lock_entries()?;
        self.load_entries_unlocked(&mut state)
    }

    pub fn store_secret(&self, secret: &str) -> Result<String, KeyclawError> {
        let mut state = self.lock_entries()?;
        let mut entries = self.load_entries_unlocked(&mut state)?;
        let id = placeholder::make_id(secret);
        entries.insert(id.clone(), secret.to_string());
        save_entries(&self.path, &self.passphrase, &mut state, &entries)?;
        Ok(id)
    }

    pub fn resolve(&self, id: &str) -> Result<Option<String>, KeyclawError> {
        let mut state = self.lock_entries()?;
        let entries = self.load_entries_unlocked(&mut state)?;
        Ok(entries.get(id).cloned())
    }

    pub fn warm_up(&self) -> Result<(), KeyclawError> {
        let mut state = self.lock_entries()?;
        prime_vault_state(&self.path, &self.passphrase, &mut state)
    }

    fn lock_entries(&self) -> Result<MutexGuard<'_, VaultCryptoState>, KeyclawError> {
        self.lock
            .lock()
            .map_err(|_| KeyclawError::uncoded("vault mutex poisoned"))
    }

    fn load_entries_unlocked(
        &self,
        state: &mut VaultCryptoState,
    ) -> Result<HashMap<String, String>, KeyclawError> {
        match load_entries(&self.path, &self.passphrase, state) {
            Ok(entries) => Ok(entries),
            Err(VaultLoadFailure::Missing) => Ok(HashMap::new()),
            Err(err) => Err(map_load_failure(&self.path, err)),
        }
    }
}

impl VaultCryptoState {
    fn remember(&mut self, salt: [u8; 16], key: [u8; 32]) {
        self.salt = Some(salt);
        self.key = Some(key);
    }

    fn key_for_salt(&mut self, passphrase: &str, salt: [u8; 16]) -> Result<[u8; 32], KeyclawError> {
        if self.salt == Some(salt) {
            if let Some(key) = self.key {
                return Ok(key);
            }
        }

        let key = derive_key(passphrase, &salt)?;
        self.remember(salt, key);
        Ok(key)
    }

    fn ensure_key(&mut self, passphrase: &str) -> Result<([u8; 16], [u8; 32]), KeyclawError> {
        if let (Some(salt), Some(key)) = (self.salt, self.key) {
            return Ok((salt, key));
        }

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        self.remember(salt, key);
        Ok((salt, key))
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

    match load_entries_once(vault_path, LEGACY_DEFAULT_VAULT_PASSPHRASE) {
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

    match load_entries_once(vault_path, LEGACY_DEFAULT_VAULT_PASSPHRASE) {
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
    // Derive once per vault salt and reuse the result across requests so the KDF stays off the
    // request hot path after startup.
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
    state: &mut VaultCryptoState,
    entries: &HashMap<String, String>,
) -> Result<(), KeyclawError> {
    let plaintext = serde_json::to_vec(entries)
        .map_err(|e| KeyclawError::uncoded_with_source("marshal vault plaintext", e))?;

    let (salt, key) = state.ensure_key(passphrase)?;

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
    state: &mut VaultCryptoState,
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
    let salt: [u8; 16] = salt
        .as_slice()
        .try_into()
        .map_err(|_| VaultLoadFailure::Error(invalid_vault_error(path, "invalid salt length")))?;
    let nonce = BASE64.decode(payload.nonce).map_err(|_| {
        VaultLoadFailure::Error(invalid_vault_error(path, "invalid nonce encoding"))
    })?;
    let ciphertext = BASE64.decode(payload.ciphertext).map_err(|_| {
        VaultLoadFailure::Error(invalid_vault_error(path, "invalid ciphertext encoding"))
    })?;

    let key = state
        .key_for_salt(passphrase, salt)
        .map_err(VaultLoadFailure::Error)?;
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

fn load_entries_once(
    path: &Path,
    passphrase: &str,
) -> Result<HashMap<String, String>, VaultLoadFailure> {
    let mut state = VaultCryptoState::default();
    load_entries(path, passphrase, &mut state)
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

    let mut state = VaultCryptoState::default();
    save_entries(vault_path, &new_passphrase, &mut state, entries)?;
    if let Err(err) = atomic_write(key_path, new_passphrase.as_bytes(), 0o600) {
        let mut legacy_state = VaultCryptoState::default();
        let _ = save_entries(
            vault_path,
            LEGACY_DEFAULT_VAULT_PASSPHRASE,
            &mut legacy_state,
            entries,
        );
        return Err(err);
    }

    Ok(new_passphrase)
}

fn prime_vault_state(
    path: &Path,
    passphrase: &str,
    state: &mut VaultCryptoState,
) -> Result<(), KeyclawError> {
    match load_entries(path, passphrase, state) {
        Ok(_) => Ok(()),
        Err(VaultLoadFailure::Missing) => state.ensure_key(passphrase).map(|_| ()),
        Err(err) => Err(map_load_failure(path, err)),
    }
}

fn map_load_failure(path: &Path, failure: VaultLoadFailure) -> KeyclawError {
    match failure {
        VaultLoadFailure::Missing => {
            KeyclawError::uncoded(format!("vault {} is missing", path.display()))
        }
        VaultLoadFailure::WrongPassphrase => KeyclawError::uncoded(format!(
            "vault {} could not be decrypted with the configured key material; restore the correct key or set KEYCLAW_VAULT_PASSPHRASE",
            path.display()
        )),
        VaultLoadFailure::Error(err) => err,
    }
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
