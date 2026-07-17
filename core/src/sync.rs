//! Sync engine: last-write-wins by modified timestamp, with conflicts
//! surfaced instead of silently dropped. See docs/adr/0006-sync-conflict-policy.md.
//!
//! The engine moves ciphertext records between a local `Storage` and a
//! `SyncRemote`. It uses the unlocked vault for two things: verifying that a
//! record pulled from the remote was authored by a vault-key holder (so a
//! malicious server cannot inject forged records or deletions), and
//! preserving the losing side of a conflict as a re-encrypted conflict copy.
//!
//! Change detection never relies on comparing timestamps across devices,
//! which would be unsafe when device clocks disagree. The remote side is
//! pulled in full and reconciled against local state; the local side is
//! tracked with a per-record synced marker (`Storage::dirty_entries`).

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::error::{StorageError, VaultError};
use crate::model::{EntryRecord, VaultMeta};
use crate::storage::Storage;
use crate::vault::{conflict_copy_id, next_modified, Vault};

/// Result of pushing one record to the remote.
pub enum PushOutcome {
    Applied,
    /// The remote holds a record that wins by last-write-wins and returned
    /// it instead of applying ours.
    Rejected(EntryRecord),
}

/// What a store should do with a pushed record under last-write-wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushDecision {
    /// Unknown id or strictly newer timestamp: store it.
    Apply,
    /// Byte-identical to the stored record: succeed without writing, so
    /// interrupted syncs can retry safely.
    Idempotent,
    /// The stored record wins; answer with it so the client can resolve.
    Reject,
}

/// The one last-write-wins push rule. The server handler and every test
/// double call this same function, so the rule cannot drift between the
/// engine's expectations and a store's behavior. Ties reject, which is why
/// the engine's conflict resolution awards ties to the remote.
pub fn lww_push_decision(existing: Option<&EntryRecord>, incoming: &EntryRecord) -> PushDecision {
    match existing {
        None => PushDecision::Apply,
        Some(current) if current == incoming => PushDecision::Idempotent,
        Some(current) if incoming.modified_ms > current.modified_ms => PushDecision::Apply,
        Some(_) => PushDecision::Reject,
    }
}

/// The remote side of a sync, as the engine sees it. Implemented by
/// `RemoteSync` over HTTP and by in-memory doubles in tests.
pub trait SyncRemote {
    fn vault_meta(&mut self) -> Result<Option<VaultMeta>, StorageError>;
    fn init_vault(&mut self, meta: &VaultMeta) -> Result<(), StorageError>;
    fn changed_since(&mut self, since_ms: i64) -> Result<Vec<EntryRecord>, StorageError>;
    fn push(&mut self, record: &EntryRecord) -> Result<PushOutcome, StorageError>;
}

/// Which side won a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
}

/// One surfaced conflict: both sides changed the same entry since the last
/// sync. The winner (by timestamp) is applied everywhere; every losing live
/// version is preserved as a conflict copy on both sides.
#[derive(Debug)]
pub struct Conflict {
    pub id: Uuid,
    pub winner: Side,
    /// UUID and title of each conflict copy created. Empty when the losing
    /// side was a tombstone (nothing to preserve).
    pub copies: Vec<(Uuid, String)>,
}

#[derive(Debug, Default)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    pub conflicts: Vec<Conflict>,
    /// Records the server sent that failed authentication under the vault
    /// key and were ignored. Anything above zero means the server returned
    /// forged or corrupted data and deserves attention.
    pub skipped_unverifiable: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The remote holds a different vault (different salt or key check).
    /// Syncing would mix two unrelated vaults.
    #[error("the remote vault does not match the local vault: {0}")]
    VaultMismatch(String),
}

/// Run one sync. `now` is the current wall clock in milliseconds, used only
/// for stamping conflict copies. Returns what happened.
///
/// The remote is pulled in full and reconciled against local state, so no
/// record is ever skipped because of clock skew between devices. Local edits
/// are found through `dirty_entries`, which tracks a per-record synced marker
/// rather than comparing timestamps.
pub fn sync<L: Storage, R: SyncRemote>(
    vault: &Vault,
    local: &mut L,
    remote: &mut R,
    now: i64,
) -> Result<SyncReport, SyncError> {
    reconcile_meta(local, remote)?;

    // Pull the whole remote set and drop anything the vault key cannot
    // authenticate. A malicious or buggy server cannot inject a forged record
    // or deletion this way: unverifiable records never reach local storage.
    // Every drop is counted and surfaced; silence would hide a tampering
    // server from the user.
    let mut report = SyncReport::default();
    let fetched = remote.changed_since(i64::MIN)?;
    let fetched_count = fetched.len();
    let remote_all: BTreeMap<Uuid, EntryRecord> = fetched
        .into_iter()
        .filter(|r| vault.verify_record(r).is_ok())
        .map(|r| (r.id, r))
        .collect();
    report.skipped_unverifiable = fetched_count - remote_all.len();
    let dirty: BTreeMap<Uuid, EntryRecord> = local
        .dirty_entries()?
        .into_iter()
        .map(|r| (r.id, r))
        .collect();

    // Pull and merge: reconcile every verified remote record against local.
    for (id, rrec) in &remote_all {
        match dirty.get(id) {
            // Changed locally too.
            Some(lrec) if lrec == rrec => {
                // Byte-identical to the remote, for example our own push from
                // an interrupted earlier sync. Just clear the dirty marker.
                local.mark_synced(*id, rrec.modified_ms)?;
            }
            Some(lrec) => {
                let conflict = resolve_conflict(vault, local, remote, lrec, rrec, now)?;
                report.conflicts.push(conflict);
            }
            // Not changed locally: reconcile against the clean local state.
            None => match local.entry(*id)? {
                None => {
                    local.apply_synced(rrec)?;
                    report.pulled += 1;
                }
                Some(current) if &current == rrec => {}
                Some(current) if rrec.modified_ms > current.modified_ms => {
                    local.apply_synced(rrec)?;
                    report.pulled += 1;
                }
                Some(current) if rrec.modified_ms < current.modified_ms => {
                    // The server holds an older version of a record this
                    // device already synced: a server rollback or replay.
                    // Restore our newer version instead of adopting the old
                    // one, which would silently revert data everywhere.
                    match remote.push(&current)? {
                        PushOutcome::Applied => {
                            report.pushed += 1;
                        }
                        PushOutcome::Rejected(newer) => {
                            if vault.verify_record(&newer).is_ok() {
                                let conflict =
                                    resolve_conflict(vault, local, remote, &current, &newer, now)?;
                                report.conflicts.push(conflict);
                            } else {
                                report.skipped_unverifiable += 1;
                            }
                        }
                    }
                }
                Some(current) => {
                    // Same timestamp, different bytes: a genuine tie between
                    // two verified versions. Resolve like any conflict, so
                    // the losing version is preserved, never dropped.
                    let conflict = resolve_conflict(vault, local, remote, &current, rrec, now)?;
                    report.conflicts.push(conflict);
                }
            },
        }
    }

    // Push local edits the remote does not already have.
    for (id, lrec) in &dirty {
        if remote_all.contains_key(id) {
            continue; // handled by the pull-and-merge loop above
        }
        match remote.push(lrec)? {
            PushOutcome::Applied => {
                local.mark_synced(*id, lrec.modified_ms)?;
                report.pushed += 1;
            }
            // Race: the remote gained this id after our full pull. Only merge
            // a server record the vault key can authenticate; otherwise leave
            // the edit dirty to retry next sync, and say so.
            PushOutcome::Rejected(server_rec) => {
                if vault.verify_record(&server_rec).is_ok() {
                    let conflict = resolve_conflict(vault, local, remote, lrec, &server_rec, now)?;
                    report.conflicts.push(conflict);
                } else {
                    report.skipped_unverifiable += 1;
                }
            }
        }
    }

    Ok(report)
}

/// Both sides changed one entry. Last write wins everywhere; every live
/// losing version is preserved as a conflict copy stored on both sides.
fn resolve_conflict<L: Storage, R: SyncRemote>(
    vault: &Vault,
    local: &mut L,
    remote: &mut R,
    local_rec: &EntryRecord,
    remote_rec: &EntryRecord,
    now: i64,
) -> Result<Conflict, SyncError> {
    // Ties go to the remote: deterministic on every device.
    let winner = if local_rec.modified_ms > remote_rec.modified_ms {
        Side::Local
    } else {
        Side::Remote
    };
    let (winner_rec, loser_rec) = match winner {
        Side::Local => (local_rec, remote_rec),
        Side::Remote => (remote_rec, local_rec),
    };

    // Preserve the losing version first, while it is still readable.
    let mut copies = Vec::new();
    if let Some(copy) = preserve_version(vault, local, remote, loser_rec, now)? {
        copies.push(copy);
    }

    // Apply the winner to whichever side lacks it.
    match winner {
        Side::Local => match remote.push(winner_rec)? {
            PushOutcome::Applied => {
                local.mark_synced(local_rec.id, winner_rec.modified_ms)?;
            }
            PushOutcome::Rejected(newer) => {
                // The remote moved again underneath us: `newer` beats our
                // local winner. Preserve the local version too, then adopt
                // the newer remote record.
                if let Some(copy) = preserve_version(vault, local, remote, winner_rec, now)? {
                    copies.push(copy);
                }
                if vault.verify_record(&newer).is_ok() {
                    local.apply_synced(&newer)?;
                }
                return Ok(Conflict {
                    id: local_rec.id,
                    winner: Side::Remote,
                    copies,
                });
            }
        },
        Side::Remote => {
            local.apply_synced(winner_rec)?;
        }
    }

    Ok(Conflict {
        id: local_rec.id,
        winner,
        copies,
    })
}

/// Store a losing live version as a conflict copy, on both sides. The copy's
/// UUID is derived from the losing record (see `conflict_copy_id`), so a sync
/// interrupted and retried regenerates the same copy instead of duplicating
/// it. Tombstones and undecryptable records yield no copy.
fn preserve_version<L: Storage, R: SyncRemote>(
    vault: &Vault,
    local: &mut L,
    remote: &mut R,
    loser: &EntryRecord,
    now: i64,
) -> Result<Option<(Uuid, String)>, SyncError> {
    if loser.deleted {
        return Ok(None);
    }
    let Ok(mut data) = vault.open_entry(loser) else {
        // A record this vault key cannot open would already have failed
        // every other operation; the conflict itself is still resolved.
        return Ok(None);
    };
    let copy_id = conflict_copy_id(loser);
    let short = copy_id.to_string()[..8].to_string();
    data.title = format!("{} (conflict {short})", data.title);
    let copy_rec = vault.seal_entry(copy_id, next_modified(0, now), &data)?;
    local.upsert_entry(&copy_rec)?;
    match remote.push(&copy_rec)? {
        PushOutcome::Applied => local.mark_synced(copy_id, copy_rec.modified_ms)?,
        // A retry already placed this copy on the remote. The local upsert
        // above left it dirty; the next reconcile marks it synced.
        PushOutcome::Rejected(_) => {}
    }
    let title = data.title.clone();
    Ok(Some((copy_id, title)))
}

/// Both sides must hold the same vault before any record moves. The caller
/// bootstraps a missing local vault; the engine pushes a missing remote one.
fn reconcile_meta<L: Storage, R: SyncRemote>(
    local: &mut L,
    remote: &mut R,
) -> Result<(), SyncError> {
    let local_meta = local
        .vault_meta()?
        .ok_or_else(|| SyncError::VaultMismatch("no local vault".into()))?;
    match remote.vault_meta()? {
        None => {
            remote.init_vault(&local_meta)?;
            Ok(())
        }
        Some(remote_meta) if remote_meta.same_vault(&local_meta) => Ok(()),
        Some(_) => Err(SyncError::VaultMismatch(
            "salt or key check differ; refusing to mix two vaults".into(),
        )),
    }
}
