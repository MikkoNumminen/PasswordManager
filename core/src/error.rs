//! Error types for the core crate.

use thiserror::Error;

/// Errors from the crypto module.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The requested Argon2 parameters are outside the algorithm's limits.
    #[error("invalid KDF parameters: {0}")]
    KdfParams(String),
    /// Key derivation failed for a reason other than bad parameters.
    #[error("key derivation failed: {0}")]
    Kdf(String),
    /// AEAD open failed. Wrong key, tampered ciphertext, tampered nonce, or
    /// mismatched associated data. The cause is indistinguishable by design.
    #[error("decryption failed: wrong key or tampered data")]
    Aead,
    /// AEAD seal failed. Should not happen with valid inputs.
    #[error("encryption failed")]
    Encrypt,
    /// The operating system RNG was unavailable.
    #[error("system RNG unavailable: {0}")]
    Rng(String),
}

/// Errors from the high level vault API.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The master password did not unlock this vault.
    #[error("wrong master password")]
    WrongPassword,
    /// The decrypted payload or the payload to encrypt is malformed.
    #[error("entry payload is not valid: {0}")]
    Payload(String),
    /// The vault metadata is malformed or from an unsupported version.
    #[error("vault metadata is not valid: {0}")]
    Meta(String),
}

/// Errors from storage backends.
#[derive(Debug, Error)]
pub enum StorageError {
    #[cfg(feature = "sqlite")]
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The backend holds no vault yet.
    #[error("vault not initialized")]
    NotInitialized,
    /// The backend already holds a vault and refuses to overwrite it.
    #[error("vault already initialized")]
    AlreadyInitialized,
    /// Stored data does not match the expected shape.
    #[error("storage corrupt: {0}")]
    Corrupt(String),
    /// Backend specific failure, for example a network error.
    #[error("{0}")]
    Backend(String),
}
