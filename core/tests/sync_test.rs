//! Sync engine tests over an in-memory remote that mirrors the server's
//! last-write-wins semantics.

use std::collections::BTreeMap;

use password_manager_core::secrecy::SecretString;
use password_manager_core::sync::{
    lww_push_decision, sync, PushDecision, PushOutcome, Side, SyncError, SyncRemote,
};
use password_manager_core::uuid::Uuid;
use password_manager_core::{
    new_entry_id, EntryData, EntryRecord, KdfParams, LocalSqlite, Storage, StorageError, Vault,
    VaultMeta,
};

/// In-memory stand-in for the sync server, with the same last-write-wins
/// push rules the real server applies.
#[derive(Default)]
struct MemRemote {
    meta: Option<VaultMeta>,
    entries: BTreeMap<Uuid, EntryRecord>,
}

impl SyncRemote for MemRemote {
    fn vault_meta(&mut self) -> Result<Option<VaultMeta>, StorageError> {
        Ok(self.meta.clone())
    }

    fn init_vault(&mut self, meta: &VaultMeta) -> Result<(), StorageError> {
        match &self.meta {
            Some(existing) if existing == meta => Ok(()),
            Some(_) => Err(StorageError::AlreadyInitialized),
            None => {
                self.meta = Some(meta.clone());
                Ok(())
            }
        }
    }

    fn changed_since(&mut self, since_ms: i64) -> Result<Vec<EntryRecord>, StorageError> {
        Ok(self
            .entries
            .values()
            .filter(|r| r.modified_ms > since_ms)
            .cloned()
            .collect())
    }

    fn push(&mut self, record: &EntryRecord) -> Result<PushOutcome, StorageError> {
        // Same rule as the real server: both call core's lww_push_decision.
        match lww_push_decision(self.entries.get(&record.id), record) {
            PushDecision::Apply => {
                self.entries.insert(record.id, record.clone());
                Ok(PushOutcome::Applied)
            }
            PushDecision::Idempotent => Ok(PushOutcome::Applied),
            PushDecision::Reject => Ok(PushOutcome::Rejected(
                self.entries
                    .get(&record.id)
                    .expect("reject implies existing")
                    .clone(),
            )),
        }
    }
}

fn test_kdf() -> KdfParams {
    KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn password() -> SecretString {
    SecretString::from("sync test password".to_string())
}

fn entry(title: &str) -> EntryData {
    EntryData {
        title: title.into(),
        username: "user".into(),
        password: "pw".into(),
        url: String::new(),
        notes: String::new(),
        created_ms: 1,
    }
}

/// A device: unlocked vault plus local storage holding the shared meta.
fn device(meta: &VaultMeta) -> (Vault, LocalSqlite) {
    let vault = Vault::unlock(&password(), meta).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(meta).unwrap();
    (vault, store)
}

fn titles(vault: &Vault, store: &mut LocalSqlite) -> Vec<String> {
    let mut out: Vec<String> = store
        .entries()
        .unwrap()
        .iter()
        .filter(|r| !r.deleted)
        .map(|r| vault.open_entry(r).unwrap().title.clone())
        .collect();
    out.sort();
    out
}

/// Titles of live entries that are conflict copies.
fn conflict_titles(vault: &Vault, store: &mut LocalSqlite) -> Vec<String> {
    titles(vault, store)
        .into_iter()
        .filter(|t| t.contains("(conflict "))
        .collect()
}

#[test]
fn first_sync_pushes_meta_and_entries() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();
    let mut remote = MemRemote::default();

    let a = vault
        .seal_entry(new_entry_id().unwrap(), 100, &entry("alpha"))
        .unwrap();
    let b = vault
        .seal_entry(new_entry_id().unwrap(), 200, &entry("beta"))
        .unwrap();
    store.upsert_entry(&a).unwrap();
    store.upsert_entry(&b).unwrap();

    let report = sync(&vault, &mut store, &mut remote, 500).unwrap();
    assert_eq!(report.pushed, 2);
    assert_eq!(report.pulled, 0);
    assert!(report.conflicts.is_empty());
    assert_eq!(remote.meta.as_ref(), Some(&meta));
    assert_eq!(remote.entries.len(), 2);
    // After a push both records are clean, so a second sync does nothing.
    let again = sync(&vault, &mut store, &mut remote, 600).unwrap();
    assert_eq!(again.pushed, 0);
    assert_eq!(again.pulled, 0);
}

#[test]
fn second_device_pulls_and_decrypts() {
    let (vault_a, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store_a = LocalSqlite::open_in_memory().unwrap();
    store_a.init_vault(&meta).unwrap();
    let mut remote = MemRemote::default();
    let rec = vault_a
        .seal_entry(new_entry_id().unwrap(), 100, &entry("shared"))
        .unwrap();
    store_a.upsert_entry(&rec).unwrap();
    sync(&vault_a, &mut store_a, &mut remote, 500).unwrap();

    // Device B adopts the same vault meta (the CLI bootstraps this) and
    // pulls. The entry decrypts under the key derived from the same
    // password and salt.
    let (vault_b, mut store_b) = device(&meta);
    let report = sync(&vault_b, &mut store_b, &mut remote, 600).unwrap();
    assert_eq!(report.pulled, 1);
    assert_eq!(report.pushed, 0);
    assert_eq!(titles(&vault_b, &mut store_b), vec!["shared".to_string()]);
    // The pulled record is clean: it is not re-pushed on the next sync.
    let again = sync(&vault_b, &mut store_b, &mut remote, 700).unwrap();
    assert_eq!(again.pushed, 0);
    assert_eq!(again.pulled, 0);
}

/// Regression: the pull side must never skip a record because of clock skew.
/// A device with a lagging clock can push a record whose timestamp is below
/// this device's most recent activity; a timestamp-cursor pull would miss it.
#[test]
fn pull_is_immune_to_clock_skew() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();
    let mut remote = MemRemote::default();

    // This device pushes an entry stamped far in the future (fast clock).
    let mine = vault
        .seal_entry(new_entry_id().unwrap(), 10_000, &entry("mine"))
        .unwrap();
    store.upsert_entry(&mine).unwrap();
    assert_eq!(
        sync(&vault, &mut store, &mut remote, 20_000)
            .unwrap()
            .pushed,
        1
    );

    // Another device with a lagging clock pushes an entry with a much lower
    // timestamp straight onto the remote.
    let theirs = vault
        .seal_entry(new_entry_id().unwrap(), 50, &entry("theirs"))
        .unwrap();
    remote.entries.insert(theirs.id, theirs.clone());

    let report = sync(&vault, &mut store, &mut remote, 30_000).unwrap();
    assert_eq!(
        report.pulled, 1,
        "low-timestamp remote record must be pulled"
    );
    assert_eq!(store.entry(theirs.id).unwrap().unwrap(), theirs);
}

/// A malicious or buggy server cannot inject a record the vault key did not
/// authenticate, nor forge a deletion.
#[test]
fn forged_remote_records_are_ignored() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();

    // A genuine synced entry.
    let id = new_entry_id().unwrap();
    let real = vault.seal_entry(id, 100, &entry("real")).unwrap();
    let mut remote = MemRemote {
        meta: Some(meta),
        entries: BTreeMap::new(),
    };
    remote.entries.insert(id, real.clone());
    sync(&vault, &mut store, &mut remote, 200).unwrap();
    assert_eq!(store.entry(id).unwrap().unwrap(), real);

    // The server forges a garbage edit and a garbage deletion.
    let forged_edit = EntryRecord {
        id,
        modified_ms: 999,
        nonce: vec![0u8; 24],
        ciphertext: vec![1u8; 40],
        deleted: false,
    };
    let forged_delete = EntryRecord {
        id: new_entry_id().unwrap(),
        modified_ms: 999,
        nonce: Vec::new(),
        ciphertext: Vec::new(),
        deleted: true,
    };
    remote.entries.insert(id, forged_edit);
    remote
        .entries
        .insert(forged_delete.id, forged_delete.clone());

    let report = sync(&vault, &mut store, &mut remote, 300).unwrap();
    assert_eq!(report.pulled, 0);
    // The genuine record is untouched and the forged deletion never landed.
    assert_eq!(store.entry(id).unwrap().unwrap(), real);
    assert!(store.entry(forged_delete.id).unwrap().is_none());
    // The drops are surfaced, never silent.
    assert_eq!(report.skipped_unverifiable, 2);
}

/// Regression: a server rollback (or replay of an old backup) must not
/// silently revert data this device already synced. The clean local record
/// is newer; it gets re-pushed instead of being overwritten.
#[test]
fn server_rollback_does_not_revert_synced_data() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();
    let mut remote = MemRemote::default();

    // v1 synced, then v2 synced.
    let id = new_entry_id().unwrap();
    let v1 = vault.seal_entry(id, 100, &entry("v1")).unwrap();
    store.upsert_entry(&v1).unwrap();
    sync(&vault, &mut store, &mut remote, 150).unwrap();
    let v2 = vault.seal_entry(id, 200, &entry("v2")).unwrap();
    store.upsert_entry(&v2).unwrap();
    sync(&vault, &mut store, &mut remote, 250).unwrap();
    assert_eq!(remote.entries.get(&id).unwrap(), &v2);

    // The server is restored from an old backup that still holds v1.
    remote.entries.insert(id, v1.clone());

    let report = sync(&vault, &mut store, &mut remote, 300).unwrap();
    assert_eq!(report.pushed, 1, "the newer local version is restored");
    assert_eq!(report.pulled, 0);
    assert_eq!(
        store.entry(id).unwrap().unwrap(),
        v2,
        "local data not reverted"
    );
    assert_eq!(
        remote.entries.get(&id).unwrap(),
        &v2,
        "server restored to v2"
    );
}

#[test]
fn conflict_preserves_loser_on_both_sides() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();
    let mut remote = MemRemote::default();

    // Both sides start from a synced entry.
    let id = new_entry_id().unwrap();
    let base = vault.seal_entry(id, 100, &entry("base")).unwrap();
    store.upsert_entry(&base).unwrap();
    sync(&vault, &mut store, &mut remote, 150).unwrap();

    // The other device edited it at t=300 (lands on the remote); this
    // device edited it at t=200. Remote wins.
    let mut remote_edit = entry("base");
    remote_edit.username = "remote edit".into();
    let remote_rec = vault.seal_entry(id, 300, &remote_edit).unwrap();
    remote.entries.insert(id, remote_rec.clone());

    let mut local_edit = entry("base");
    local_edit.username = "local edit".into();
    let local_rec = vault.seal_entry(id, 200, &local_edit).unwrap();
    store.upsert_entry(&local_rec).unwrap();

    let report = sync(&vault, &mut store, &mut remote, 1_000).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    let conflict = &report.conflicts[0];
    assert_eq!(conflict.id, id);
    assert_eq!(conflict.winner, Side::Remote);
    assert_eq!(conflict.copies.len(), 1);
    let (copy_id, copy_title) = &conflict.copies[0];
    assert!(copy_title.starts_with("base (conflict "));

    // Winner applied locally.
    let winner_local = store.entry(id).unwrap().unwrap();
    assert_eq!(winner_local, remote_rec);
    assert_eq!(
        vault.open_entry(&winner_local).unwrap().username,
        "remote edit"
    );

    // Losing version preserved on both sides and still decryptable.
    let copy_local = store.entry(*copy_id).unwrap().unwrap();
    let copy_remote = remote.entries.get(copy_id).unwrap();
    assert_eq!(&copy_local, copy_remote);
    assert_eq!(
        vault.open_entry(&copy_local).unwrap().username,
        "local edit"
    );

    // Re-syncing is stable: no new conflicts, no duplicate copies.
    let again = sync(&vault, &mut store, &mut remote, 1_100).unwrap();
    assert!(again.conflicts.is_empty());
    assert_eq!(conflict_titles(&vault, &mut store).len(), 1);
}

#[test]
fn local_newer_wins_and_reaches_remote() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();
    let mut remote = MemRemote::default();

    let id = new_entry_id().unwrap();
    let base = vault.seal_entry(id, 100, &entry("base")).unwrap();
    store.upsert_entry(&base).unwrap();
    sync(&vault, &mut store, &mut remote, 150).unwrap();

    let remote_rec = vault.seal_entry(id, 200, &entry("remote older")).unwrap();
    remote.entries.insert(id, remote_rec);
    let local_rec = vault.seal_entry(id, 300, &entry("local newer")).unwrap();
    store.upsert_entry(&local_rec).unwrap();

    let report = sync(&vault, &mut store, &mut remote, 1_000).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts[0].winner, Side::Local);
    assert_eq!(remote.entries.get(&id).unwrap(), &local_rec);
    // The remote's losing version was preserved.
    assert_eq!(report.conflicts[0].copies.len(), 1);
}

#[test]
fn newer_delete_wins_but_local_edit_survives_as_copy() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();
    let mut remote = MemRemote::default();

    let id = new_entry_id().unwrap();
    let base = vault.seal_entry(id, 100, &entry("doomed")).unwrap();
    store.upsert_entry(&base).unwrap();
    sync(&vault, &mut store, &mut remote, 150).unwrap();

    // Other device deleted at t=300 (an authenticated tombstone); this device
    // edited at t=200.
    let tombstone = vault.seal_tombstone(id, 300).unwrap();
    remote.entries.insert(id, tombstone);
    let local_rec = vault.seal_entry(id, 200, &entry("doomed edit")).unwrap();
    store.upsert_entry(&local_rec).unwrap();

    let report = sync(&vault, &mut store, &mut remote, 1_000).unwrap();
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts[0].winner, Side::Remote);
    // Entry is deleted locally now.
    assert!(store.entry(id).unwrap().unwrap().deleted);
    // The local edit lives on as a conflict copy.
    assert_eq!(report.conflicts[0].copies.len(), 1);
    let (copy_id, _) = report.conflicts[0].copies[0];
    assert!(!store.entry(copy_id).unwrap().unwrap().deleted);
    assert!(remote.entries.contains_key(&copy_id));
}

/// Regression: a conflict resolved twice (as happens when a sync is
/// interrupted after making the copy but before finishing) must reuse the same
/// conflict-copy id rather than accumulating duplicates.
#[test]
fn interrupted_conflict_retry_makes_no_duplicate_copy() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();
    let mut remote = MemRemote::default();

    let id = new_entry_id().unwrap();
    let base = vault.seal_entry(id, 100, &entry("base")).unwrap();
    store.upsert_entry(&base).unwrap();
    sync(&vault, &mut store, &mut remote, 150).unwrap();

    let remote_rec = vault.seal_entry(id, 300, &entry("remote win")).unwrap();
    let local_rec = vault.seal_entry(id, 200, &entry("local lose")).unwrap();

    // First resolution.
    remote.entries.insert(id, remote_rec.clone());
    store.upsert_entry(&local_rec).unwrap();
    let first = sync(&vault, &mut store, &mut remote, 1_000).unwrap();
    let first_copy = first.conflicts[0].copies[0].0;

    // Simulate the same conflict being re-encountered (an interrupted sync
    // whose local edit was never marked clean): re-dirty the local edit and
    // restore the remote winner, then sync again.
    store.upsert_entry(&local_rec).unwrap();
    remote.entries.insert(id, remote_rec);
    let second = sync(&vault, &mut store, &mut remote, 2_000).unwrap();
    if let Some(c) = second.conflicts.first() {
        assert_eq!(c.copies[0].0, first_copy, "retry must reuse the copy id");
    }

    // Exactly one conflict copy exists, on both sides.
    let copies = conflict_titles(&vault, &mut store);
    assert_eq!(copies.len(), 1, "no duplicate conflict copies");
    assert_eq!(
        remote.entries.keys().filter(|k| **k == first_copy).count(),
        1
    );
}

#[test]
fn mismatched_remote_vault_is_refused() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();

    let (_, other_meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut remote = MemRemote {
        meta: Some(other_meta),
        entries: BTreeMap::new(),
    };

    let err = sync(&vault, &mut store, &mut remote, 100).unwrap_err();
    assert!(matches!(err, SyncError::VaultMismatch(_)));
}

#[test]
fn sync_is_idempotent() {
    let (vault, meta) = Vault::create(&password(), test_kdf()).unwrap();
    let mut store = LocalSqlite::open_in_memory().unwrap();
    store.init_vault(&meta).unwrap();
    let mut remote = MemRemote::default();

    let rec = vault
        .seal_entry(new_entry_id().unwrap(), 100, &entry("steady"))
        .unwrap();
    store.upsert_entry(&rec).unwrap();

    let first = sync(&vault, &mut store, &mut remote, 500).unwrap();
    assert_eq!(first.pushed, 1);
    let second = sync(&vault, &mut store, &mut remote, 600).unwrap();
    assert_eq!(second.pushed, 0);
    assert_eq!(second.pulled, 0);
    assert!(second.conflicts.is_empty());
}
