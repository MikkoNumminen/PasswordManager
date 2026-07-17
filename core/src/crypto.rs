//! The single crypto implementation.
//!
//! Composition of vetted RustCrypto crates only:
//! - Argon2id (`argon2`) turns the master password into the vault key.
//! - XChaCha20-Poly1305 (`chacha20poly1305`) seals entry payloads.
//! - `getrandom` supplies every salt and nonce.
//!
//! Nothing here is hand rolled. Callers cannot pick nonces: the public
//! `encrypt` draws a fresh random 24 byte nonce on every call, which is safe
//! for XChaCha20-Poly1305's 192 bit nonce space.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;

/// Vault key length in bytes.
pub const KEY_LEN: usize = 32;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// KDF salt length in bytes.
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters. Stored in cleartext next to the vault data.
/// The values are not secret; the salt makes each derivation unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes over memory.
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// RFC 9106 second recommended option: 64 MiB memory, 3 passes, 1 lane.
    /// See docs/adr/0001-kdf-params.md.
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// The symmetric vault key. Derived from the master password, held only in
/// memory, zeroized on drop, never persisted, never serialized.
pub struct VaultKey(SecretBox<[u8; KEY_LEN]>);

impl VaultKey {
    pub(crate) fn from_bytes(bytes: Box<[u8; KEY_LEN]>) -> Self {
        Self(SecretBox::new(bytes))
    }

    fn expose(&self) -> &[u8; KEY_LEN] {
        self.0.expose_secret()
    }
}

/// Fill a buffer from the operating system RNG.
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(buf).map_err(|e| CryptoError::Rng(e.to_string()))
}

/// A fixed size buffer of OS randomness.
pub fn random_array<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    fill_random(&mut buf)?;
    Ok(buf)
}

/// Derive the vault key from the master password with Argon2id.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<VaultKey, CryptoError> {
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|e| CryptoError::KdfParams(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = Box::new([0u8; KEY_LEN]);
    if let Err(e) = argon.hash_password_into(password, salt, key.as_mut_slice()) {
        key.zeroize();
        return Err(CryptoError::Kdf(e.to_string()));
    }
    Ok(VaultKey::from_bytes(key))
}

/// Seal with a caller supplied nonce. Private on purpose: reusing a nonce
/// under the same key breaks the AEAD, so only `encrypt` (fresh random nonce
/// every call) is exposed. Tests use this for known answer vectors.
fn seal(
    key: &VaultKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)
}

/// Encrypt a payload under a fresh random 24 byte nonce.
/// Returns the nonce and the ciphertext (which includes the Poly1305 tag).
pub fn encrypt(
    key: &VaultKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let nonce = random_array::<NONCE_LEN>()?;
    let ciphertext = seal(key, &nonce, aad, plaintext)?;
    Ok((nonce, ciphertext))
}

/// Decrypt and authenticate. Any failure (wrong key, tampered ciphertext,
/// tampered nonce, mismatched associated data) is reported as one opaque
/// error. The plaintext is zeroized when the returned buffer drops.
pub fn decrypt(
    key: &VaultKey,
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::Aead);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose()));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexd(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex in test vector")
    }

    fn key_from(bytes: &[u8]) -> VaultKey {
        let mut key = Box::new([0u8; KEY_LEN]);
        key.copy_from_slice(bytes);
        VaultKey::from_bytes(key)
    }

    /// Known answer test for XChaCha20-Poly1305 from
    /// draft-irtf-cfrg-xchacha-03, appendix A.3. Catches regressions in the
    /// AEAD dependency or in how this module drives it.
    #[test]
    fn kat_xchacha20poly1305() {
        let key = key_from(&hexd(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        ));
        let nonce_bytes = hexd("404142434445464748494a4b4c4d4e4f5051525354555657");
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&nonce_bytes);
        let aad = hexd("50515253c0c1c2c3c4c5c6c7");
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct = hexd(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e",
        );
        let expected_tag = hexd("c0875924c1c7987947deafd8780acf49");

        let sealed = seal(&key, &nonce, &aad, plaintext).unwrap();
        let (body, tag) = sealed.split_at(sealed.len() - 16);
        assert_eq!(body, expected_ct.as_slice());
        assert_eq!(tag, expected_tag.as_slice());

        let opened = decrypt(&key, &aad, &nonce, &sealed).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
    }

    /// Known answer test for Argon2id from RFC 9106 section 5.3.
    /// The RFC vector uses a secret key and associated data, so this drives
    /// the argon2 crate directly with those inputs. It pins the exact
    /// algorithm (Argon2id, version 0x13) that `derive_key` composes.
    #[test]
    fn kat_argon2id_rfc9106() {
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let ad = [0x04u8; 12];
        let expected = hexd("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");

        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&ad).unwrap())
            .build()
            .unwrap();
        let argon =
            Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut out = [0u8; 32];
        argon
            .hash_password_into(&password, &salt, &mut out)
            .unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
    }

    /// `derive_key` is deterministic for fixed inputs and differs across
    /// salts and passwords.
    #[test]
    fn derive_key_depends_on_password_and_salt() {
        let params = KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let k1 = derive_key(b"password", b"0123456789abcdef", &params).unwrap();
        let k2 = derive_key(b"password", b"0123456789abcdef", &params).unwrap();
        let k3 = derive_key(b"password", b"fedcba9876543210", &params).unwrap();
        let k4 = derive_key(b"passworD", b"0123456789abcdef", &params).unwrap();
        assert_eq!(k1.expose(), k2.expose());
        assert_ne!(k1.expose(), k3.expose());
        assert_ne!(k1.expose(), k4.expose());
    }

    /// Fresh random nonces on every call.
    #[test]
    fn encrypt_uses_fresh_nonces() {
        let key = key_from(&[7u8; KEY_LEN]);
        let (n1, c1) = encrypt(&key, b"aad", b"same plaintext").unwrap();
        let (n2, c2) = encrypt(&key, b"aad", b"same plaintext").unwrap();
        assert_ne!(n1, n2);
        assert_ne!(c1, c2);
    }
}
