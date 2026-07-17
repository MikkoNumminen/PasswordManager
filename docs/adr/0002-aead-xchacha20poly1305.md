# ADR 0002: XChaCha20-Poly1305 as the AEAD

## Status

Accepted (Phase 1).

## Context

Entry payloads are sealed client side with an AEAD. The realistic candidates
are AES-256-GCM and XChaCha20-Poly1305, both available as vetted RustCrypto
crates. Nonces are generated randomly per write (see ADR 0003), so nonce
collision behavior drives the choice.

## Decision

XChaCha20-Poly1305 via the `chacha20poly1305` crate.

Reasons:

- 192 bit nonces make random nonce generation safe. AES-GCM's 96 bit nonce
  space makes random nonces a real collision risk at scale, and a
  nonce-reuse in GCM leaks the authentication key.
- ChaCha20 is constant time in pure software. AES is only reliably constant
  time with hardware AES instructions, which wasm32 does not expose.
- One cipher runs identically on native and wasm targets, which keeps the
  single-crypto-path invariant simple to hold.

## Consequences

- Ciphertext carries a 16 byte Poly1305 tag; decryption fails closed on any
  modification of ciphertext, nonce, or associated data.
- Wrong master password and tampered data are indistinguishable by design.
  The tag check is the only password verifier (see ADR 0004).
