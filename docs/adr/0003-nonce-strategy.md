# ADR 0003: Random per-write nonces

## Status

Accepted (Phase 1).

## Context

Every AEAD seal needs a nonce that never repeats under the same key.
Counter-based nonces need durable, synchronized state across every device
that writes to the vault; a counter rollback (restored backup, sync race)
would silently reuse a nonce. Random nonces need no state but must come from
a nonce space large enough that collisions are negligible.

## Decision

A fresh 24 byte nonce from `getrandom` on every encryption, including
re-encryption of an edited entry. No counters, no derived nonces, no state.

XChaCha20-Poly1305's 192 bit nonce space was selected precisely for this
(ADR 0002). Collision probability stays negligible far beyond any realistic
number of writes for a personal vault.

The core crate enforces the policy in its API: the public `encrypt` function
draws the nonce itself, and no public code path accepts a caller-chosen
nonce. Known answer tests reach the fixed-nonce path through a private
function only.

## Consequences

- No nonce state to persist, sync, or get wrong across devices.
- Each write changes the ciphertext completely, even for identical
  plaintext, so ciphertext equality leaks nothing about content equality.
- The nonce is stored in cleartext next to the ciphertext. Nonces are not
  secret; only uniqueness matters.
