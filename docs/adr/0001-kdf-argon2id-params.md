# ADR 0001: Argon2id as KDF, and its parameters

## Status

Accepted (Phase 1).

## Context

The vault key must be derived from the master password on the client. The
derivation has to be memory hard so that offline guessing against a stolen
ciphertext blob is expensive. The same derivation must run natively and
compiled to wasm32 in a browser.

## Decision

Argon2id, version 0x13, via the `argon2` crate (RustCrypto), producing a
32 byte key.

Default parameters for new vaults:

- memory: 64 MiB (m_cost 65536 KiB)
- passes: t_cost 3
- parallelism: p_cost 1
- salt: 16 random bytes from `getrandom`, unique per vault

This is the second recommended option from RFC 9106 section 4. The first
option (2 GiB, t=1) is hostile to browser wasm heaps, so the lower-memory
variant with more passes was chosen.

Parameters and salt are stored in cleartext with the vault and are read
before the password is known. They are not secret: the salt's job is
uniqueness, and the cost parameters only describe how the key was derived.

## One parameter set for native and wasm

The KDF parameters travel with the vault, so every client must run whatever
the vault was created with. Separate wasm parameters would derive a
different key and could not decrypt the same vault. 64 MiB with 3 passes is
within what browser wasm handles; if unlock in the browser proves too slow
on real hardware, the fix is re-tuning the vault's stored parameters, and
this ADR gets updated with measurements.

## Consequences

- Offline guessing costs roughly 64 MiB and three passes per attempt.
- Unlock takes a noticeable fraction of a second on desktop hardware. That
  cost is deliberate.
- Wrong parameters cannot be introduced silently: the derived key changes
  and the key check tag fails.
