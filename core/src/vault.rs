//! High level vault API: create, unlock, seal entries, open entries.

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, VaultKey, SALT_LEN};
use crate::error::{CryptoError, VaultError};
use crate::model::{EntryData, EntryRecord, VaultMeta, VAULT_FORMAT_VERSION};

/// Domain separation for the key check blob.
const KEYCHECK_AAD: &[u8] = b"password-manager/keycheck/v1";
/// Domain separation prefix for entry payloads.
const ENTRY_AAD_PREFIX: &[u8] = b"password-manager/entry/v1";
/// Domain separation prefix for tombstones. Distinct from the entry prefix so
/// a live entry ciphertext can never be replayed as a deletion, or vice versa.
const TOMBSTONE_AAD_PREFIX: &[u8] = b"password-manager/tombstone/v1";
/// Fixed plaintext sealed inside a tombstone. Its only job is to carry an AEAD
/// tag that proves a vault-key holder authored the deletion.
const TOMBSTONE_MARKER: &[u8] = b"deleted";
/// Size of the random key check plaintext.
const KEYCHECK_LEN: usize = 32;

/// An unlocked vault. Holds the derived key in memory only; the key is
/// zeroized when this value drops. There is no way to extract the key.
pub struct Vault {
    key: VaultKey,
}

/// Debug never exposes the key.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("key", &"<redacted>").finish()
    }
}

impl Vault {
    /// Create a new vault: draw a random salt, derive the key, and seal the
    /// key check blob. Returns the unlocked vault and the metadata to store.
    pub fn create(
        password: &SecretString,
        kdf: KdfParams,
    ) -> Result<(Self, VaultMeta), VaultError> {
        let salt = crypto::random_array::<SALT_LEN>()?.to_vec();
        let key = crypto::derive_key(password.expose_secret().as_bytes(), &salt, &kdf)?;
        let probe = Zeroizing::new(crypto::random_array::<KEYCHECK_LEN>()?);
        let (nonce, ciphertext) = crypto::encrypt(&key, KEYCHECK_AAD, probe.as_slice())?;
        let meta = VaultMeta {
            version: VAULT_FORMAT_VERSION,
            salt,
            kdf,
            key_check_nonce: nonce.to_vec(),
            key_check_ct: ciphertext,
        };
        Ok((Self { key }, meta))
    }

    /// Unlock an existing vault. The password is correct exactly when the
    /// key check blob decrypts with a valid AEAD tag. No other verifier
    /// exists.
    pub fn unlock(password: &SecretString, meta: &VaultMeta) -> Result<Self, VaultError> {
        if meta.version != VAULT_FORMAT_VERSION {
            return Err(VaultError::Meta(format!(
                "unsupported vault format version {}",
                meta.version
            )));
        }
        let key = crypto::derive_key(password.expose_secret().as_bytes(), &meta.salt, &meta.kdf)?;
        crypto::decrypt(
            &key,
            KEYCHECK_AAD,
            &meta.key_check_nonce,
            &meta.key_check_ct,
        )
        .map_err(|_| VaultError::WrongPassword)?;
        Ok(Self { key })
    }

    /// Encrypt an entry payload into a record ready for storage. The
    /// ciphertext is bound to the entry UUID and the modified timestamp via
    /// the associated data, so a record cannot be re-keyed to another UUID
    /// or silently re-stamped.
    pub fn seal_entry(
        &self,
        id: Uuid,
        modified_ms: i64,
        data: &EntryData,
    ) -> Result<EntryRecord, VaultError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(data).map_err(|e| VaultError::Payload(e.to_string()))?,
        );
        let aad = entry_aad(id, modified_ms);
        let (nonce, ciphertext) = crypto::encrypt(&self.key, &aad, &plaintext)?;
        Ok(EntryRecord {
            id,
            modified_ms,
            nonce: nonce.to_vec(),
            ciphertext,
            deleted: false,
        })
    }

    /// Decrypt an entry record. Fails if the record was tampered with in any
    /// way: ciphertext, nonce, UUID, or modified timestamp.
    pub fn open_entry(&self, record: &EntryRecord) -> Result<EntryData, VaultError> {
        if record.deleted {
            return Err(VaultError::Payload("entry is deleted".into()));
        }
        let aad = entry_aad(record.id, record.modified_ms);
        let plaintext = crypto::decrypt(&self.key, &aad, &record.nonce, &record.ciphertext)?;
        serde_json::from_slice(&plaintext).map_err(|e| VaultError::Payload(e.to_string()))
    }

    /// Seal a tombstone for a deleted entry. Like a normal record it is bound
    /// to the entry UUID and modified timestamp, so the sync server cannot
    /// forge a deletion or re-stamp one without failing the tag check.
    pub fn seal_tombstone(&self, id: Uuid, modified_ms: i64) -> Result<EntryRecord, VaultError> {
        let aad = tombstone_aad(id, modified_ms);
        let (nonce, ciphertext) = crypto::encrypt(&self.key, &aad, TOMBSTONE_MARKER)?;
        Ok(EntryRecord {
            id,
            modified_ms,
            nonce: nonce.to_vec(),
            ciphertext,
            deleted: true,
        })
    }

    /// Verify that a record was produced by a holder of this vault key,
    /// without returning its plaintext. Live records must decrypt; tombstones
    /// must carry a valid deletion marker. Used to reject records a malicious
    /// server may have forged before they are stored locally.
    pub fn verify_record(&self, record: &EntryRecord) -> Result<(), VaultError> {
        if record.deleted {
            let aad = tombstone_aad(record.id, record.modified_ms);
            let marker = crypto::decrypt(&self.key, &aad, &record.nonce, &record.ciphertext)?;
            if marker.as_slice() != TOMBSTONE_MARKER {
                return Err(VaultError::Payload("tombstone marker mismatch".into()));
            }
            Ok(())
        } else {
            self.open_entry(record).map(|_| ())
        }
    }
}

/// Associated data for an entry: domain prefix, UUID, and modified
/// timestamp in big endian.
fn entry_aad(id: Uuid, modified_ms: i64) -> Vec<u8> {
    aad_with_prefix(ENTRY_AAD_PREFIX, id, modified_ms)
}

/// Associated data for a tombstone. Same shape as an entry's, under a
/// distinct domain prefix so the two can never be confused.
fn tombstone_aad(id: Uuid, modified_ms: i64) -> Vec<u8> {
    aad_with_prefix(TOMBSTONE_AAD_PREFIX, id, modified_ms)
}

fn aad_with_prefix(prefix: &[u8], id: Uuid, modified_ms: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + 16 + 8);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&modified_ms.to_be_bytes());
    aad
}

/// Deterministic UUID for the conflict copy that preserves a losing version.
/// Derived (UUIDv5) from the losing record's identity, so replaying an
/// interrupted sync regenerates the same copy id and the upsert is idempotent
/// instead of minting a fresh duplicate on every retry.
pub fn conflict_copy_id(loser: &EntryRecord) -> Uuid {
    // Namespace: a fixed random UUID for this application's conflict copies.
    const NS: Uuid = Uuid::from_bytes([
        0x8b, 0x1a, 0x9d, 0x4c, 0x5e, 0x2f, 0x47, 0x6a, 0x9c, 0x3d, 0x21, 0x0e, 0x7f, 0x88, 0x54,
        0x63,
    ]);
    let mut name = Vec::with_capacity(16 + 8);
    name.extend_from_slice(loser.id.as_bytes());
    name.extend_from_slice(&loser.modified_ms.to_be_bytes());
    Uuid::new_v5(&NS, &name)
}

/// Generate a fresh entry UUID (version 4) from OS randomness.
pub fn new_entry_id() -> Result<Uuid, CryptoError> {
    Ok(uuid::Builder::from_random_bytes(crypto::random_array::<16>()?).into_uuid())
}

/// Current wall clock in milliseconds since the Unix epoch.
#[cfg(not(target_arch = "wasm32"))]
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

/// Next modified timestamp for an entry: the current time, but always
/// strictly greater than the previous timestamp so last-write-wins sync
/// never sees a stale rewrite.
pub fn next_modified(prev_ms: i64, now_ms: i64) -> i64 {
    now_ms.max(prev_ms + 1)
}
