# ADR 0004: Password verification by AEAD key check only

## Status

Accepted (Phase 1).

## Context

The spec forbids storing the master password in any form and requires that
password correctness is verified only by a successful AEAD tag check on
decrypt. An empty vault still needs a way to distinguish a wrong password
from a correct one, otherwise the first entry added with a mistyped password
would fork the vault irrecoverably.

## Decision

At vault creation, 32 random bytes are sealed under the freshly derived
vault key with XChaCha20-Poly1305 (associated data `password-manager/keycheck/v1`).
The nonce and ciphertext are stored in the cleartext vault metadata.

Unlock derives the key from the entered password and attempts to decrypt
the key check blob. A valid tag means the password is correct. A failed tag
is reported as a wrong password.

No password hash, no HMAC of the password, and no key verifier derived from
the password is stored anywhere. The key check is ordinary ciphertext under
the vault key, exactly as trustworthy as every entry: an attacker who can
attack the key check offline can equally attack any stored entry, so it adds
zero new attack surface beyond what storing ciphertext already implies.

## Consequences

- Wrong passwords are caught at unlock, before any write.
- A tampered key check blob reads as a wrong password. Restoring the vault
  from backup is the answer in both cases.
- Offline password guessing against the key check costs one full Argon2id
  derivation per guess, the same as guessing against an entry.
