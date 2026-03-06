use std::collections::HashMap;
use std::fs;

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
fn vault_store_secret_recovers_from_unreadable_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault.enc");
    fs::write(&path, b"not-a-valid-vault").expect("seed corrupt file");

    let store = keyclaw::vault::Store::new(path, "test-passphrase".to_string());
    let secret = "sk-ABCDEF0123456789ABCDEF0123456789";
    let id = store.store_secret(secret).expect("store secret");

    let loaded = store.load().expect("load recovered vault");
    assert_eq!(loaded.get(&id), Some(&secret.to_string()));
}
