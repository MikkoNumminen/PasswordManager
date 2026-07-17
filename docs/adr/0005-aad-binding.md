# ADR 0005: Binding ciphertext to UUID and timestamp via associated data

## Status

Accepted (Phase 1).

## Context

Entry records are stored and synced as (UUID, modified timestamp, nonce,
ciphertext). The sync server is honest-but-curious at best and fully
malicious at worst. Without binding, a malicious server could swap
ciphertexts between UUIDs (your bank password appears under the entry named
in metadata as your forum account) or re-stamp an old record with a newer
timestamp to win last-write-wins sync. Both would decrypt cleanly.

## Decision

The AEAD associated data for every entry is:

    "password-manager/entry/v1" || UUID (16 bytes) || modified_ms (8 bytes, big endian)

Deletions are authenticated the same way. A tombstone seals a fixed marker
under the prefix `password-manager/tombstone/v1` with the same UUID and
timestamp layout, so a deletion proves it was authored by a vault-key
holder, cannot be re-stamped, and cannot be confused with a live entry.
The key check blob uses the distinct constant
`password-manager/keycheck/v1`. Three separate domains, no cross-replay.

Any change to the UUID or the timestamp of a record fails the Poly1305 tag
check on decrypt, with tests asserting exactly that. Clients verify every
record pulled from the sync server against these bindings before storing
it, so a malicious server cannot inject records or forged deletions.

## Consequences

- Records cannot be swapped between entries or re-stamped by anyone who
  lacks the vault key, including the sync server.
- Replay of a complete old record (old ciphertext with its original
  timestamp) still verifies. Last-write-wins sync limits the damage to
  reviving an older version of an entry. Full rollback protection would
  need client-side version state and is out of scope; the threat model in
  the README names this.
- Editing an entry always re-encrypts, since the timestamp is part of the
  authenticated data. That was already true because of per-write nonces.
