use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn vault_encrypts_and_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.enc");
    let store = keyclaw::vault::Store::new(path.clone(), "test-passphrase".to_string());

    let mut entries = HashMap::new();
    entries.insert(
        "a".to_string(),
        "sk-ABCDEF0123456789ABCDEF0123456789".to_string(),
    );
    entries.insert("b".to_string(), "hello".to_string());

    store.save(&entries).expect("save");
    let raw = fs::read_to_string(&path).expect("read file");
    assert!(!raw.contains("sk-ABCDEF0123456789ABCDEF0123456789"));

    let loaded = store.load().expect("load");
    assert_eq!(loaded.get("a"), entries.get("a"));
    assert_eq!(loaded.get("b"), entries.get("b"));
}

#[test]
fn vault_atomic_write_no_temp_files_left() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.enc");
    let store = keyclaw::vault::Store::new(path, "test-passphrase".to_string());

    let mut entries = HashMap::new();
    entries.insert("x".to_string(), "y".to_string());
    store.save(&entries).expect("save");

    for entry in fs::read_dir(dir.path()).expect("readdir") {
        let name = entry.expect("entry").file_name();
        let name = name.to_string_lossy();
        assert!(
            !name.starts_with(".vault-tmp-"),
            "temporary file leaked: {name}"
        );
    }
}

#[test]
fn vault_generated_key_is_created_and_reused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.enc");

    let first = keyclaw::vault::resolve_vault_passphrase(&path, None).expect("create key");
    let second = keyclaw::vault::resolve_vault_passphrase(&path, None).expect("reuse key");

    assert_eq!(first, second);
    assert_ne!(first, keyclaw::vault::LEGACY_DEFAULT_VAULT_PASSPHRASE);
    assert!(
        path.with_extension("key").exists(),
        "vault key file missing"
    );
}

#[test]
fn vault_generated_key_migrates_legacy_default_vault() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.enc");
    let legacy = keyclaw::vault::Store::new(
        path.clone(),
        keyclaw::vault::LEGACY_DEFAULT_VAULT_PASSPHRASE.to_string(),
    );

    let mut entries = HashMap::new();
    entries.insert(
        "legacy".to_string(),
        "sk-ABCDEF0123456789ABCDEF0123456789".to_string(),
    );
    legacy.save(&entries).expect("save legacy vault");

    let migrated = keyclaw::vault::resolve_vault_passphrase(&path, None).expect("migrate key");
    let store = keyclaw::vault::Store::new(path, migrated);
    let loaded = store.load().expect("load migrated vault");

    assert_eq!(loaded, entries);
    assert!(
        dir.path().join("vault.key").exists(),
        "vault key file missing"
    );
}

#[test]
fn vault_existing_file_without_key_material_fails_loudly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.enc");
    let store = keyclaw::vault::Store::new(path.clone(), "custom-passphrase".to_string());

    let mut entries = HashMap::new();
    entries.insert(
        "custom".to_string(),
        "sk-ABCDEF0123456789ABCDEF0123456789".to_string(),
    );
    store.save(&entries).expect("save");

    let err = keyclaw::vault::resolve_vault_passphrase(&path, None).expect_err("missing key");
    let msg = err.to_string();
    assert!(msg.contains("vault.key") || msg.contains("KEYCLAW_VAULT_PASSPHRASE"));
}

#[test]
fn vault_store_secret_fails_on_corrupt_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.enc");
    fs::write(&path, b"not-a-valid-vault").expect("seed corrupt file");

    let store = keyclaw::vault::Store::new(path, "test-passphrase".to_string());
    let secret = "sk-ABCDEF0123456789ABCDEF0123456789";
    let err = store
        .store_secret(secret)
        .expect_err("corrupt vault should fail");

    assert!(err.to_string().contains("vault"));
}

#[test]
fn concurrent_store_secret_preserves_all_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.enc");
    let store = Arc::new(keyclaw::vault::Store::new(
        path,
        "test-passphrase".to_string(),
    ));
    let barrier = Arc::new(Barrier::new(3));
    let secrets = [
        "sk-CONCURRENT000000000000000000000001",
        "sk-CONCURRENT000000000000000000000002",
    ];

    let mut handles = Vec::new();
    for secret in secrets {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let id = store.store_secret(secret).expect("store secret");
            (id, secret.to_string())
        }));
    }

    barrier.wait();

    let mut expected = HashMap::new();
    for handle in handles {
        let (id, secret) = handle.join().expect("join store thread");
        expected.insert(id, secret);
    }

    let loaded = store.load().expect("load");
    assert_eq!(
        loaded.len(),
        expected.len(),
        "concurrent store lost entries: loaded={loaded:?}, expected={expected:?}"
    );
    for (id, secret) in expected {
        assert_eq!(loaded.get(&id), Some(&secret));
    }
}
