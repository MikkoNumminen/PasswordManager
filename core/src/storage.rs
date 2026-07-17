//! Backend-neutral storage for one vault.
//!
//! A `Storage` moves cleartext metadata and encrypted records only. It has
//! no access to key material or plaintext, and no way to gain any: nothing
//! secret appears in any signature here.

use uuid::Uuid;

use crate::error::StorageError;
use crate::model::{EntryRecord, VaultMeta};

pub trait Storage {
    /// The stored vault metadata, or `None` if no vault exists yet.
    fn vault_meta(&mut self) -> Result<Option<VaultMeta>, StorageError>;

    /// Store metadata for a new vault. Fails with `AlreadyInitialized` if a
    /// vault is already present; overwriting metadata would orphan every
    /// existing ciphertext.
    fn init_vault(&mut self, meta: &VaultMeta) -> Result<(), StorageError>;

    /// Insert or replace one entry record from a local edit, including
    /// tombstones. The record is left marked as needing sync (dirty).
    fn upsert_entry(&mut self, record: &EntryRecord) -> Result<(), StorageError>;

    /// Insert or replace one entry record received from the remote during
    /// sync, marking it already in sync with the remote (clean).
    fn apply_synced(&mut self, record: &EntryRecord) -> Result<(), StorageError>;

    /// Mark a local record as in sync with the remote at the given
    /// modified timestamp, after a successful push.
    fn mark_synced(&mut self, id: Uuid, modified_ms: i64) -> Result<(), StorageError>;

    /// One entry record by UUID, tombstones included.
    fn entry(&mut self, id: Uuid) -> Result<Option<EntryRecord>, StorageError>;

    /// Every entry record, tombstones included. Callers filter on `deleted`.
    fn entries(&mut self) -> Result<Vec<EntryRecord>, StorageError>;

    /// Records that have been edited locally but not yet confirmed synced
    /// with the remote, tombstones included. Detection is by a per-record
    /// synced marker, not a timestamp cursor, so it is immune to clock skew
    /// between devices. Drives the push side of sync.
    fn dirty_entries(&mut self) -> Result<Vec<EntryRecord>, StorageError>;
}
