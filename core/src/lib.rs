//! Core of PasswordManager.
//!
//! This crate is the single crypto implementation for every client. The CLI
//! uses it natively and the web client compiles it to wasm32. There is no
//! second crypto path anywhere.
//!
//! Security invariants enforced here:
//! - The vault key is derived from the master password with Argon2id and
//!   lives only in memory, wrapped in types that zeroize on drop.
//! - Entries are sealed with XChaCha20-Poly1305 under a fresh random 24 byte
//!   nonce on every write.
//! - Each ciphertext is bound to its entry UUID and modified timestamp
//!   through the AEAD associated data, so records cannot be swapped or
//!   re-stamped without failing the tag check.
//! - Master password correctness is verified only by an AEAD tag check on
//!   decrypt. No password hash or verifier derived from the password is
//!   stored.
//! - Storage backends move ciphertext and cleartext metadata only. They never
//!   see key material or plaintext.

#![forbid(unsafe_code)]

pub mod api;
mod b64;
pub mod crypto;
pub mod error;
pub mod model;
pub mod storage;
pub mod sync;
pub mod vault;

#[cfg(feature = "sqlite")]
pub mod local;

#[cfg(feature = "remote")]
pub mod remote;

pub use crypto::KdfParams;
pub use error::{CryptoError, StorageError, VaultError};
pub use model::{EntryData, EntryRecord, VaultMeta};
pub use storage::Storage;
pub use vault::{new_entry_id, next_modified, Vault};

#[cfg(feature = "sqlite")]
pub use local::{LocalSqlite, SyncConfig};

#[cfg(feature = "remote")]
pub use remote::RemoteSync;

#[cfg(not(target_arch = "wasm32"))]
pub use vault::now_ms;

// Re-exported so dependents use the same versions for secret handling.
pub use secrecy;
pub use uuid;
