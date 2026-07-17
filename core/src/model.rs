//! Data model: cleartext vault metadata, encrypted entry records, and the
//! decrypted entry payload.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::KdfParams;

/// Current on-disk and on-wire vault format version.
pub const VAULT_FORMAT_VERSION: u32 = 1;

/// Cleartext vault metadata. Everything in here is non-secret by design:
/// the salt and KDF parameters must be readable before the password is
/// known, and the key check is ordinary ciphertext under the vault key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMeta {
    // When adding fields, revisit `same_vault`: it defines vault identity for
    // both the server's write-once check and the client's sync guard.
    pub version: u32,
    /// Argon2id salt, random per vault.
    #[serde(with = "crate::b64")]
    pub salt: Vec<u8>,
    pub kdf: KdfParams,
    /// Nonce for the key check ciphertext.
    #[serde(with = "crate::b64")]
    pub key_check_nonce: Vec<u8>,
    /// Random bytes sealed under the vault key. Unlock succeeds only if the
    /// AEAD tag verifies, which is the only password check that exists.
    #[serde(with = "crate::b64")]
    pub key_check_ct: Vec<u8>,
}

impl VaultMeta {
    /// The one rule for vault identity, shared by the server's write-once
    /// metadata check and the client's pre-sync guard. Two metas describe the
    /// same vault only when every field matches: a different salt or KDF
    /// derives a different key, a different key check is a different key, and
    /// a different format version must never be mixed silently.
    pub fn same_vault(&self, other: &VaultMeta) -> bool {
        self == other
    }
}

/// An entry as stored and synced: ciphertext plus non-secret metadata.
/// This is the only shape that ever reaches a storage backend or the
/// sync server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRecord {
    /// Stable identifier. Generated once at entry creation, never reused.
    pub id: Uuid,
    /// Last modification time in milliseconds since the Unix epoch.
    /// Strictly increasing per entry; drives last-write-wins sync.
    pub modified_ms: i64,
    /// AEAD nonce, random per write.
    #[serde(with = "crate::b64")]
    pub nonce: Vec<u8>,
    /// XChaCha20-Poly1305 ciphertext of the serialized `EntryData`.
    /// Empty for tombstones.
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
    /// Tombstone flag. Deleted entries keep their UUID and timestamp so
    /// deletion propagates through sync.
    pub deleted: bool,
}

/// The decrypted contents of an entry. Exists only in memory and is
/// zeroized on drop.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntryData {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// Creation time in milliseconds since the Unix epoch.
    #[serde(default)]
    pub created_ms: i64,
}

/// Equality over decrypted secrets runs in constant time (per field; field
/// lengths are not hidden), so no caller can turn a comparison into a
/// byte-by-byte timing oracle.
impl PartialEq for EntryData {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        let eq = self.title.as_bytes().ct_eq(other.title.as_bytes())
            & self.username.as_bytes().ct_eq(other.username.as_bytes())
            & self.password.as_bytes().ct_eq(other.password.as_bytes())
            & self.url.as_bytes().ct_eq(other.url.as_bytes())
            & self.notes.as_bytes().ct_eq(other.notes.as_bytes())
            & (self.created_ms as u64).ct_eq(&(other.created_ms as u64));
        eq.into()
    }
}

impl Eq for EntryData {}

/// Debug never prints secret fields.
impl std::fmt::Debug for EntryData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryData")
            .field("title", &self.title)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("notes", &"<redacted>")
            .field("created_ms", &self.created_ms)
            .finish()
    }
}
