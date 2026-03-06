use std::fs;
use std::path::{Path, PathBuf};

use crate::errors::KeyclawError;

const CA_CERT_FILENAME: &str = "ca.crt";
const CA_KEY_FILENAME: &str = "ca.key";

pub struct CaPair {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Returns the keyclaw config directory (~/.keyclaw/)
pub fn keyclaw_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".keyclaw")
}

/// Load existing CA cert+key from ~/.keyclaw/, or generate a new pair.
pub fn ensure_ca() -> Result<CaPair, KeyclawError> {
    let dir = keyclaw_dir();
    let cert_path = dir.join(CA_CERT_FILENAME);
    let key_path = dir.join(CA_KEY_FILENAME);

    if cert_path.exists() && key_path.exists() {
        let cert_pem = fs::read_to_string(&cert_path)
            .map_err(|e| KeyclawError::uncoded(format!("read CA cert {}: {e}", cert_path.display())))?;
        let key_pem = fs::read_to_string(&key_path)
            .map_err(|e| KeyclawError::uncoded(format!("read CA key {}: {e}", key_path.display())))?;
        eprintln!("keyclaw: using existing CA from {}", dir.display());
        return Ok(CaPair { cert_pem, key_pem });
    }

    generate_and_save(&dir, &cert_path, &key_path)
}

fn generate_and_save(dir: &Path, cert_path: &Path, key_path: &Path) -> Result<CaPair, KeyclawError> {
    fs::create_dir_all(dir)
        .map_err(|e| KeyclawError::uncoded(format!("create {}: {e}", dir.display())))?;

    eprintln!("keyclaw: generating new CA certificate...");

    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, "KeyClaw CA");
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "KeyClaw");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];

    // Valid for 10 years
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days_since_epoch = (now.as_secs() / 86400) as i64;
    params.not_before = rcgen::date_time_ymd(
        1970 + (days_since_epoch / 365) as i32,
        1, 1,
    );
    params.not_after = rcgen::date_time_ymd(
        1970 + (days_since_epoch / 365) as i32 + 10,
        1, 1,
    );

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| KeyclawError::uncoded(format!("generate CA key: {e}")))?;

    let cert = params.self_signed(&key_pair)
        .map_err(|e| KeyclawError::uncoded(format!("self-sign CA cert: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    fs::write(cert_path, &cert_pem)
        .map_err(|e| KeyclawError::uncoded(format!("write CA cert: {e}")))?;

    // Restrict key file permissions on unix
    fs::write(key_path, &key_pem)
        .map_err(|e| KeyclawError::uncoded(format!("write CA key: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(key_path, fs::Permissions::from_mode(0o600));
    }

    eprintln!("keyclaw: CA cert written to {}", cert_path.display());
    eprintln!("keyclaw: CA key written to {}", key_path.display());

    Ok(CaPair { cert_pem, key_pem })
}
