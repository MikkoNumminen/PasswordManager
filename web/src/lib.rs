//! Browser client core: the same `password-manager-core` crypto compiled to wasm32.
//!
//! The page's JavaScript fetches the vault metadata and the encrypted
//! records from the server and passes them in as JSON. Everything secret
//! happens on this side of the boundary: Argon2id key derivation, the key
//! check, and entry decryption. The server credential (Google ID token or
//! API token) never touches this module.
//!
//! Decrypted entries are returned to JavaScript for display. That is the
//! nature of a browser client and is named in the threat model: an
//! attacker who controls the browser session reads whatever you decrypt.

#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

use password_manager_core::secrecy::SecretString;
use password_manager_core::uuid::Uuid;
use password_manager_core::{EntryData, EntryRecord, Vault, VaultError, VaultMeta};

/// Stable machine-readable error message for a failed unlock. The page
/// matches on this exact string instead of parsing prose, so rewording any
/// human-facing text cannot break the wrong-password flow.
pub const WRONG_PASSWORD_CODE: &str = "wrong-password";

/// An unlocked vault session. The derived key lives inside the wasm heap
/// and is zeroized when the session is freed.
#[wasm_bindgen]
pub struct Session {
    vault: Vault,
}

#[derive(serde::Serialize)]
struct DecryptedEntry {
    id: String,
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    created_ms: i64,
    modified_ms: i64,
}

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen]
impl Session {
    /// Unlock the vault: derive the key with Argon2id (this takes a moment,
    /// by design) and verify it against the key check. Wrong passwords fail
    /// here and nothing else is learned.
    pub fn unlock(meta_json: &str, password: &str) -> Result<Session, JsError> {
        let meta: VaultMeta = serde_json::from_str(meta_json).map_err(err)?;
        let password = SecretString::from(password.to_string());
        match Vault::unlock(&password, &meta) {
            Ok(vault) => Ok(Session { vault }),
            Err(VaultError::WrongPassword) => Err(JsError::new(WRONG_PASSWORD_CODE)),
            Err(e) => Err(err(e)),
        }
    }

    /// Decrypt a JSON array of entry records. Tombstones are skipped.
    /// Returns a JSON array sorted by title. Any record that fails its tag
    /// check aborts the whole call: tampered data is never partially shown.
    pub fn decrypt_entries(&self, records_json: &str) -> Result<String, JsError> {
        let records: Vec<EntryRecord> = serde_json::from_str(records_json).map_err(err)?;
        let mut out = Vec::new();
        for record in &records {
            if record.deleted {
                continue;
            }
            let data = self.vault.open_entry(record).map_err(err)?;
            out.push(DecryptedEntry {
                id: record.id.to_string(),
                title: data.title.clone(),
                username: data.username.clone(),
                password: data.password.clone(),
                url: data.url.clone(),
                notes: data.notes.clone(),
                created_ms: data.created_ms,
                modified_ms: record.modified_ms,
            });
        }
        out.sort_by_key(|e| e.title.to_lowercase());
        serde_json::to_string(&out).map_err(err)
    }

    /// Encrypt one entry into a record ready to PUT to the server. `data_json`
    /// carries the entry fields; the sealing (and the vault key) stay here, so
    /// the server only ever receives ciphertext. Used for both add and edit.
    ///
    /// `modified_ms` is f64 so JavaScript can pass a plain Number (from
    /// Date.now()); millisecond timestamps are well within f64's exact-integer
    /// range, and this avoids the i64/BigInt wasm boundary at the call site.
    pub fn seal_entry(
        &self,
        id: &str,
        modified_ms: f64,
        data_json: &str,
    ) -> Result<String, JsError> {
        let id = Uuid::parse_str(id).map_err(err)?;
        let data: EntryData = serde_json::from_str(data_json).map_err(err)?;
        let record = self
            .vault
            .seal_entry(id, modified_ms as i64, &data)
            .map_err(err)?;
        serde_json::to_string(&record).map_err(err)
    }

    /// Seal a deletion for an entry, ready to PUT to the server. The tombstone
    /// is authenticated under the vault key, so the server cannot forge it.
    pub fn seal_tombstone(&self, id: &str, modified_ms: f64) -> Result<String, JsError> {
        let id = Uuid::parse_str(id).map_err(err)?;
        let record = self
            .vault
            .seal_tombstone(id, modified_ms as i64)
            .map_err(err)?;
        serde_json::to_string(&record).map_err(err)
    }
}
