//! Phase 1 integration tests over the public core API: round trips, wrong
//! password rejection, tamper detection, and the sqlite backend.

use password_manager_core::secrecy::SecretString;
use password_manager_core::{
    new_entry_id, next_modified, EntryData, KdfParams, LocalSqlite, Storage, Vault, VaultError,
};

/// Small Argon2 parameters so tests stay fast. Production defaults are
/// exercised by `KdfParams::default()` in real use and by the KAT in the
/// crypto module.
fn test_kdf() -> KdfParams {
    KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn password(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn sample_entry() -> EntryData {
    EntryData {
        title: "example.com".into(),
        username: "mikko".into(),
        password: "correct horse battery staple".into(),
        url: "https://example.com/login".into(),
        notes: "personal account".into(),
        created_ms: 1_700_000_000_000,
    }
}

#[test]
fn entry_round_trip() {
    let (vault, _meta) = Vault::create(&password("master"), test_kdf()).unwrap();
    let id = new_entry_id().unwrap();
    let data = sample_entry();
    let record = vault.seal_entry(id, 1_000, &data).unwrap();

    assert_eq!(record.id, id);
    assert_eq!(record.modified_ms, 1_000);
    assert_eq!(record.nonce.len(), 24);
    assert!(!record.deleted);
    // Ciphertext is not the plaintext.
    let json = serde_json::to_vec(&data).unwrap();
    assert_ne!(record.ciphertext, json);

    let opened = vault.open_entry(&record).unwrap();
    assert_eq!(opened, data);
}

#[test]
fn unlock_with_correct_password_works() {
    let (_, meta) = Vault::create(&password("master"), test_kdf()).unwrap();
    assert!(Vault::unlock(&password("master"), &meta).is_ok());
}

#[test]
fn wrong_password_is_rejected() {
    let (_, meta) = Vault::create(&password("master"), test_kdf()).unwrap();
    let err = Vault::unlock(&password("mastre"), &meta).unwrap_err();
    assert!(matches!(err, VaultError::WrongPassword));
}

#[test]
fn wrong_password_cannot_open_entries() {
    let (vault_a, _) = Vault::create(&password("master"), test_kdf()).unwrap();
    let (vault_b, _) = Vault::create(&password("other"), test_kdf()).unwrap();
    let record = vault_a
        .seal_entry(new_entry_id().unwrap(), 1, &sample_entry())
        .unwrap();
    assert!(vault_b.open_entry(&record).is_err());
}

#[test]
fn tampered_ciphertext_fails_tag_check() {
    let (vault, _) = Vault::create(&password("master"), test_kdf()).unwrap();
    let mut record = vault
        .seal_entry(new_entry_id().unwrap(), 1, &sample_entry())
        .unwrap();
    for i in [0, record.ciphertext.len() / 2, record.ciphertext.len() - 1] {
        let mut tampered = record.clone();
        tampered.ciphertext[i] ^= 0x01;
        assert!(vault.open_entry(&tampered).is_err(), "flipped byte {i}");
    }
    // Truncation fails too.
    record.ciphertext.pop();
    assert!(vault.open_entry(&record).is_err());
}

#[test]
fn tampered_nonce_fails_tag_check() {
    let (vault, _) = Vault::create(&password("master"), test_kdf()).unwrap();
    let mut record = vault
        .seal_entry(new_entry_id().unwrap(), 1, &sample_entry())
        .unwrap();
    record.nonce[0] ^= 0x01;
    assert!(vault.open_entry(&record).is_err());
}

/// The AAD binds each ciphertext to its UUID: records cannot be swapped
/// between entries without failing the tag check.
#[test]
fn record_bound_to_uuid() {
    let (vault, _) = Vault::create(&password("master"), test_kdf()).unwrap();
    let mut record = vault
        .seal_entry(new_entry_id().unwrap(), 1, &sample_entry())
        .unwrap();
    record.id = new_entry_id().unwrap();
    assert!(vault.open_entry(&record).is_err());
}

/// The AAD binds each ciphertext to its modified timestamp: a record cannot
/// be re-stamped without failing the tag check.
#[test]
fn record_bound_to_modified_timestamp() {
    let (vault, _) = Vault::create(&password("master"), test_kdf()).unwrap();
    let mut record = vault
        .seal_entry(new_entry_id().unwrap(), 1_000, &sample_entry())
        .unwrap();
    record.modified_ms = 2_000;
    assert!(vault.open_entry(&record).is_err());
}

#[test]
fn key_check_tamper_reads_as_wrong_password() {
    let (_, mut meta) = Vault::create(&password("master"), test_kdf()).unwrap();
    meta.key_check_ct[0] ^= 0x01;
    let err = Vault::unlock(&password("master"), &meta).unwrap_err();
    assert!(matches!(err, VaultError::WrongPassword));
}

#[test]
fn vaults_use_unique_salts() {
    let (_, meta_a) = Vault::create(&password("master"), test_kdf()).unwrap();
    let (_, meta_b) = Vault::create(&password("master"), test_kdf()).unwrap();
    assert_ne!(meta_a.salt, meta_b.salt);
}

#[test]
fn next_modified_is_strictly_increasing() {
    assert_eq!(next_modified(0, 100), 100);
    assert_eq!(next_modified(100, 100), 101);
    assert_eq!(next_modified(200, 100), 201);
}

#[test]
fn sqlite_meta_round_trip_and_single_init() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (_, meta) = Vault::create(&password("master"), test_kdf()).unwrap();

    {
        let mut store = LocalSqlite::open(&path).unwrap();
        assert!(store.vault_meta().unwrap().is_none());
        store.init_vault(&meta).unwrap();
        assert_eq!(store.vault_meta().unwrap().unwrap(), meta);
        // A second init must not overwrite the existing vault.
        let err = store.init_vault(&meta).unwrap_err();
        assert!(matches!(
            err,
            password_manager_core::StorageError::AlreadyInitialized
        ));
    }

    // Metadata survives reopening the file.
    let mut reopened = LocalSqlite::open(&path).unwrap();
    assert_eq!(reopened.vault_meta().unwrap().unwrap(), meta);
}

#[test]
fn sqlite_entry_crud_and_dirty_tracking() {
    let mut store = LocalSqlite::open_in_memory().unwrap();
    let (vault, meta) = Vault::create(&password("master"), test_kdf()).unwrap();
    store.init_vault(&meta).unwrap();

    let id_a = new_entry_id().unwrap();
    let id_b = new_entry_id().unwrap();
    let rec_a = vault.seal_entry(id_a, 100, &sample_entry()).unwrap();
    let rec_b = vault.seal_entry(id_b, 200, &sample_entry()).unwrap();
    store.upsert_entry(&rec_a).unwrap();
    store.upsert_entry(&rec_b).unwrap();

    assert_eq!(store.entry(id_a).unwrap().unwrap(), rec_a);
    assert!(store.entry(new_entry_id().unwrap()).unwrap().is_none());
    assert_eq!(store.entries().unwrap(), vec![rec_a.clone(), rec_b.clone()]);

    // Both local edits are dirty until confirmed synced.
    assert_eq!(
        store.dirty_entries().unwrap(),
        vec![rec_a.clone(), rec_b.clone()]
    );
    store.mark_synced(id_a, rec_a.modified_ms).unwrap();
    assert_eq!(store.dirty_entries().unwrap(), vec![rec_b.clone()]);

    // A remote record applied through apply_synced lands clean.
    let id_c = new_entry_id().unwrap();
    let rec_c = vault.seal_entry(id_c, 250, &sample_entry()).unwrap();
    store.apply_synced(&rec_c).unwrap();
    assert_eq!(store.dirty_entries().unwrap(), vec![rec_b.clone()]);

    // Editing a clean record makes it dirty again.
    let mut data = vault.open_entry(&rec_a).unwrap();
    data.password = "new password".into();
    let rec_a2 = vault
        .seal_entry(id_a, next_modified(rec_a.modified_ms, 150), &data)
        .unwrap();
    store.upsert_entry(&rec_a2).unwrap();
    assert_eq!(store.entry(id_a).unwrap().unwrap(), rec_a2);
    assert!(store.dirty_entries().unwrap().iter().any(|r| r.id == id_a));

    // Authenticated tombstone: verifiable, ciphertext present but opaque.
    let tombstone = vault
        .seal_tombstone(id_b, next_modified(rec_b.modified_ms, 300))
        .unwrap();
    store.upsert_entry(&tombstone).unwrap();
    let stored = store.entry(id_b).unwrap().unwrap();
    assert!(stored.deleted);
    assert!(vault.verify_record(&stored).is_ok());
    assert!(vault.open_entry(&stored).is_err());
}

/// Conflict-copy ids are stable for the same losing version (idempotent
/// retries) and distinct for different versions, even with the same entry id
/// and timestamp.
#[test]
fn conflict_copy_ids_are_stable_and_collision_free() {
    let (vault, _) = Vault::create(&password("master"), test_kdf()).unwrap();
    let id = new_entry_id().unwrap();
    let version_a = vault.seal_entry(id, 100, &sample_entry()).unwrap();
    let version_b = vault.seal_entry(id, 100, &sample_entry()).unwrap();

    use password_manager_core::vault::conflict_copy_id;
    assert_eq!(conflict_copy_id(&version_a), conflict_copy_id(&version_a));
    assert_ne!(conflict_copy_id(&version_a), conflict_copy_id(&version_b));
}

#[test]
fn tombstone_authentication_detects_forgery() {
    let (vault, _) = Vault::create(&password("master"), test_kdf()).unwrap();
    let id = new_entry_id().unwrap();

    // A genuine tombstone verifies.
    let real = vault.seal_tombstone(id, 500).unwrap();
    assert!(vault.verify_record(&real).is_ok());

    // A forged empty tombstone (what a server could fabricate) does not.
    let forged = password_manager_core::EntryRecord {
        id,
        modified_ms: 500,
        nonce: Vec::new(),
        ciphertext: Vec::new(),
        deleted: true,
    };
    assert!(vault.verify_record(&forged).is_err());

    // Re-stamping a genuine tombstone to a different timestamp breaks the tag.
    let mut restamped = real.clone();
    restamped.modified_ms = 9_999;
    assert!(vault.verify_record(&restamped).is_err());
}

#[test]
fn record_and_meta_serde_round_trip() {
    let (vault, meta) = Vault::create(&password("master"), test_kdf()).unwrap();
    let record = vault
        .seal_entry(new_entry_id().unwrap(), 42, &sample_entry())
        .unwrap();

    let meta_json = serde_json::to_string(&meta).unwrap();
    let record_json = serde_json::to_string(&record).unwrap();
    assert_eq!(
        serde_json::from_str::<password_manager_core::VaultMeta>(&meta_json).unwrap(),
        meta
    );
    assert_eq!(
        serde_json::from_str::<password_manager_core::EntryRecord>(&record_json).unwrap(),
        record
    );
}
