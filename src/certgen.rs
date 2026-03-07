use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::Builder;
use x509_parser::pem::parse_x509_pem;

use crate::errors::KeyclawError;

const CA_CERT_FILENAME: &str = "ca.crt";
const CA_KEY_FILENAME: &str = "ca.key";
const CA_VALIDITY_YEARS: i32 = 10;
const SECONDS_PER_DAY: u64 = 86_400;
const BROKEN_CA_RECOVERY: &str = "remove the broken CA files and rerun `keyclaw proxy`";

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

    if cert_path.exists() || key_path.exists() {
        let pair = validate_generated_ca_pair(&cert_path, &key_path)?;
        crate::logging::info(&format!("using existing CA from {}", dir.display()));
        return Ok(pair);
    }

    generate_and_save(&dir, &cert_path, &key_path)
}

pub(crate) fn validate_generated_ca_pair(
    cert_path: &Path,
    key_path: &Path,
) -> Result<CaPair, KeyclawError> {
    match (cert_path.exists(), key_path.exists()) {
        (true, false) | (false, true) => {
            let dir = cert_path.parent().unwrap_or_else(|| Path::new("."));
            return Err(broken_ca_error(format!(
                "incomplete CA state in {} (need both ca.crt and ca.key)",
                dir.display()
            )));
        }
        (false, false) => {
            return Err(KeyclawError::uncoded(format!(
                "CA files are missing in {}",
                cert_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .display()
            )));
        }
        (true, true) => {}
    }

    let cert_pem = read_existing_ca_file(cert_path, "CA cert")?;
    let key_pem = read_existing_ca_file(key_path, "CA key")?;

    #[cfg(unix)]
    validate_private_key_permissions(key_path)?;

    let key_pair = rcgen::KeyPair::from_pem(&key_pem).map_err(|err| {
        broken_ca_error(format!(
            "generated CA key {} is malformed: {err}",
            key_path.display()
        ))
    })?;
    let key_public = key_pair.public_key_raw().to_vec();
    let cert_public = read_cert_public_key(cert_path, &cert_pem)?;
    if cert_public != key_public {
        return Err(broken_ca_error(format!(
            "generated CA pair in {} is mismatched",
            cert_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .display()
        )));
    }

    rcgen::Issuer::from_ca_cert_pem(&cert_pem, key_pair).map_err(|err| {
        broken_ca_error(format!(
            "generated CA pair in {} is malformed or mismatched: {err}",
            cert_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .display()
        ))
    })?;

    Ok(CaPair { cert_pem, key_pem })
}

fn ca_validity_window_dates(unix_secs: u64) -> ((i32, u8, u8), (i32, u8, u8)) {
    let days_since_epoch = (unix_secs / SECONDS_PER_DAY) as i64;
    let not_before = calendar_date_from_days_since_epoch(days_since_epoch);
    let not_after = add_years_clamped(not_before, CA_VALIDITY_YEARS);
    (not_before, not_after)
}

fn calendar_date_from_days_since_epoch(days_since_epoch: i64) -> (i32, u8, u8) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };

    (year as i32, month as u8, day as u8)
}

fn add_years_clamped((year, month, day): (i32, u8, u8), years: i32) -> (i32, u8, u8) {
    let target_year = year + years;
    let clamped_day = day.min(days_in_month(target_year, month));
    (target_year, month, clamped_day)
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => unreachable!("invalid month from calendar conversion"),
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn generate_and_save(
    dir: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> Result<CaPair, KeyclawError> {
    fs::create_dir_all(dir)
        .map_err(|e| KeyclawError::uncoded(format!("create {}: {e}", dir.display())))?;

    crate::logging::info("generating new CA certificate...");

    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "KeyClaw CA");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "KeyClaw");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let (not_before, not_after) = ca_validity_window_dates(now.as_secs());
    params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| KeyclawError::uncoded(format!("generate CA key: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| KeyclawError::uncoded(format!("self-sign CA cert: {e}")))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    write_ca_pair_atomically(dir, cert_path, key_path, &cert_pem, &key_pem)?;

    crate::logging::info(&format!("CA cert written to {}", cert_path.display()));
    crate::logging::info(&format!("CA key written to {}", key_path.display()));

    validate_generated_ca_pair(cert_path, key_path)
}

fn read_existing_ca_file(path: &Path, label: &str) -> Result<String, KeyclawError> {
    let metadata = fs::metadata(path).map_err(|err| {
        broken_ca_error(format!("cannot access {label} {}: {err}", path.display()))
    })?;
    if !metadata.is_file() {
        return Err(broken_ca_error(format!(
            "{label} path {} is not a regular file",
            path.display()
        )));
    }

    fs::read_to_string(path)
        .map_err(|err| broken_ca_error(format!("cannot read {label} {}: {err}", path.display())))
}

fn read_cert_public_key(path: &Path, cert_pem: &str) -> Result<Vec<u8>, KeyclawError> {
    let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).map_err(|err| {
        broken_ca_error(format!(
            "generated CA cert {} is malformed: {err}",
            path.display()
        ))
    })?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).map_err(|err| {
        broken_ca_error(format!(
            "generated CA cert {} is malformed: {err}",
            path.display()
        ))
    })?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

#[cfg(unix)]
fn validate_private_key_permissions(path: &Path) -> Result<(), KeyclawError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)
        .map_err(|err| broken_ca_error(format!("cannot access CA key {}: {err}", path.display())))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyclawError::uncoded(format!(
            "CA key {} permissions are too broad ({mode:o}); set them to 600 or {BROKEN_CA_RECOVERY}",
            path.display()
        )));
    }
    Ok(())
}

fn write_ca_pair_atomically(
    dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &str,
    key_pem: &str,
) -> Result<(), KeyclawError> {
    fs::create_dir_all(dir)
        .map_err(|e| KeyclawError::uncoded(format!("create {}: {e}", dir.display())))?;

    let cert_tmp = write_temp_file(dir, ".ca-cert-tmp-", cert_pem.as_bytes(), None, "CA cert")?;
    let key_tmp = write_temp_file(
        dir,
        ".ca-key-tmp-",
        key_pem.as_bytes(),
        Some(0o600),
        "CA key",
    )?;

    persist_temp_file(key_tmp, key_path, "write CA key")?;
    if let Err(err) = persist_temp_file(cert_tmp, cert_path, "write CA cert") {
        let cleanup = fs::remove_file(key_path);
        return match cleanup {
            Ok(()) => Err(err),
            Err(cleanup_err) => Err(KeyclawError::uncoded(format!(
                "{err}; cleanup {} failed: {cleanup_err}",
                key_path.display()
            ))),
        };
    }

    if let Ok(dir_file) = File::open(dir) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

fn write_temp_file(
    dir: &Path,
    prefix: &str,
    content: &[u8],
    #[cfg(unix)] perm: Option<u32>,
    #[cfg(not(unix))] _perm: Option<u32>,
    label: &str,
) -> Result<tempfile::NamedTempFile, KeyclawError> {
    let mut tmp = Builder::new()
        .prefix(prefix)
        .tempfile_in(dir)
        .map_err(|err| KeyclawError::uncoded(format!("create temp {label} file: {err}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Some(perm) = perm {
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(perm)).map_err(|err| {
                KeyclawError::uncoded(format!(
                    "set permissions on temp {label} file {}: {err}",
                    tmp.path().display()
                ))
            })?;
        }
    }

    tmp.write_all(content)
        .map_err(|err| KeyclawError::uncoded(format!("write temp {label} file: {err}")))?;
    tmp.as_file_mut()
        .sync_all()
        .map_err(|err| KeyclawError::uncoded(format!("sync temp {label} file: {err}")))?;
    Ok(tmp)
}

fn persist_temp_file(
    tmp: tempfile::NamedTempFile,
    path: &Path,
    label: &str,
) -> Result<(), KeyclawError> {
    tmp.persist(path)
        .map_err(|err| KeyclawError::uncoded(format!("{label}: {}", err.error)))
        .map(|_| ())
}

fn broken_ca_error(message: String) -> KeyclawError {
    KeyclawError::uncoded(format!("{message}; {BROKEN_CA_RECOVERY}"))
}

#[cfg(test)]
mod tests {
    use super::{CA_CERT_FILENAME, CA_KEY_FILENAME};

    use once_cell::sync::Lazy;
    use std::env;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Mutex;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn validity_window_keeps_late_year_dates_in_the_same_calendar_year() {
        let late_december_2024 = 1_735_603_200_u64;

        let (not_before, not_after) = super::ca_validity_window_dates(late_december_2024);

        assert_eq!(not_before, (2024, 12, 31));
        assert_eq!(not_after, (2034, 12, 31));
    }

    #[test]
    fn validity_window_clamps_leap_day_expiry_to_a_real_calendar_date() {
        let leap_day_2024 = 1_709_164_800_u64;

        let (not_before, not_after) = super::ca_validity_window_dates(leap_day_2024);

        assert_eq!(not_before, (2024, 2, 29));
        assert_eq!(not_after, (2034, 2, 28));
    }

    #[test]
    fn ensure_ca_rejects_partial_state() {
        with_temp_home(|home| {
            let ca_dir = home.join(".keyclaw");
            fs::create_dir_all(&ca_dir).expect("create keyclaw dir");
            fs::write(ca_dir.join(CA_CERT_FILENAME), "placeholder").expect("write partial cert");

            let err = match super::ensure_ca() {
                Ok(_) => panic!("partial state should fail"),
                Err(err) => err,
            };

            assert!(err.to_string().contains("incomplete CA state"), "err={err}");
        });
    }

    #[test]
    fn ensure_ca_rejects_malformed_existing_pair() {
        with_temp_home(|home| {
            let ca_dir = home.join(".keyclaw");
            fs::create_dir_all(&ca_dir).expect("create keyclaw dir");
            fs::write(ca_dir.join(CA_CERT_FILENAME), "not-a-cert").expect("write malformed cert");
            fs::write(ca_dir.join(CA_KEY_FILENAME), "not-a-key").expect("write malformed key");
            tighten_key_permissions(&ca_dir.join(CA_KEY_FILENAME));

            let err = match super::ensure_ca() {
                Ok(_) => panic!("malformed pair should fail"),
                Err(err) => err,
            };

            assert!(
                err.to_string().contains("remove the broken CA files"),
                "err={err}"
            );
        });
    }

    #[test]
    fn ensure_ca_rejects_mismatched_existing_pair() {
        with_temp_home(|home| {
            let pair_one_dir = home.join("pair-one");
            let pair_two_dir = home.join("pair-two");
            let pair_one = super::generate_and_save(
                &pair_one_dir,
                &pair_one_dir.join("ca.crt"),
                &pair_one_dir.join("ca.key"),
            )
            .expect("generate first pair");
            let pair_two = super::generate_and_save(
                &pair_two_dir,
                &pair_two_dir.join("ca.crt"),
                &pair_two_dir.join("ca.key"),
            )
            .expect("generate second pair");

            let ca_dir = home.join(".keyclaw");
            fs::create_dir_all(&ca_dir).expect("create keyclaw dir");
            fs::write(ca_dir.join(CA_CERT_FILENAME), pair_one.cert_pem).expect("write cert");
            fs::write(ca_dir.join(CA_KEY_FILENAME), pair_two.key_pem).expect("write key");
            tighten_key_permissions(&ca_dir.join(CA_KEY_FILENAME));

            let err = match super::ensure_ca() {
                Ok(_) => panic!("mismatched pair should fail"),
                Err(err) => err,
            };

            assert!(
                err.to_string().contains("remove the broken CA files"),
                "err={err}"
            );
        });
    }

    #[test]
    fn generate_and_save_cleans_up_if_key_persist_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let ca_dir = temp.path().join(".keyclaw");
        let cert_path = ca_dir.join(CA_CERT_FILENAME);
        let key_path = ca_dir.join(CA_KEY_FILENAME);

        fs::create_dir_all(&ca_dir).expect("create keyclaw dir");
        fs::create_dir_all(&key_path).expect("block key path with dir");

        let err = match super::generate_and_save(&ca_dir, &cert_path, &key_path) {
            Ok(_) => panic!("generation should fail"),
            Err(err) => err,
        };

        assert!(
            !cert_path.exists(),
            "cert file should be cleaned up after failure"
        );
        assert!(err.to_string().contains("write CA key"), "err={err}");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_ca_rejects_world_readable_key_permissions() {
        with_temp_home(|home| {
            super::ensure_ca().expect("generate CA");
            let key_path = home.join(".keyclaw").join(CA_KEY_FILENAME);
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))
                .expect("weaken key perms");

            let err = match super::ensure_ca() {
                Ok(_) => panic!("weak key permissions should fail"),
                Err(err) => err,
            };

            assert!(err.to_string().contains("permissions"), "err={err}");
        });
    }

    fn with_temp_home(test: impl FnOnce(&Path)) {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved_home = env::var_os("HOME");
        let temp = tempfile::tempdir().expect("tempdir");
        env::set_var("HOME", temp.path());
        test(temp.path());
        match saved_home {
            Some(value) => env::set_var("HOME", value),
            None => env::remove_var("HOME"),
        }
    }

    fn tighten_key_permissions(path: &Path) {
        #[cfg(unix)]
        {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("tighten key permissions");
        }
    }
}
