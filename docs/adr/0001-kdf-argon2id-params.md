# ADR 0001: Argon2id as KDF, and its parameters

## Status

Accepted (Phase 1). Revised in the Phase 4 access-layer update: parameters
raised well above library defaults because the public path makes the
password plus this derivation the entire security boundary.

## Context

The vault key must be derived from the master password on the client. The
derivation has to be memory hard so that offline guessing against a stolen
ciphertext blob is expensive. The same derivation must run natively and
compiled to wasm32 in a browser. With the vault reachable through a public
URL (behind Cloudflare Access), the working assumption is hostile: if
ciphertext ever leaks or the edge gate is ever bypassed, nothing but the
master password and these parameters stands between an attacker and the
vault.

## Decision

Argon2id, version 0x13, via the `argon2` crate (RustCrypto), producing a
32 byte key.

Parameters for new vaults:

- memory: 256 MiB (m_cost 262144 KiB)
- passes: t_cost 3
- parallelism: p_cost 1
- salt: 16 random bytes from `getrandom`, unique per vault

Reasoning:

- The `argon2` crate default is 19 MiB with 2 passes (the OWASP interactive
  minimum). That is tuned for high-traffic servers doing many logins, not
  for a single-user vault where one derivation guards everything. 256 MiB
  is roughly 13 times that memory.
- Memory is the dominant cost for GPU and ASIC guessing: each parallel
  guess must hold its own 256 MiB, so a single high-end GPU drops from
  billions of hash-style guesses per second to a few dozen Argon2id
  guesses per second.
- Three passes add stretching on top; one lane, because parallelism
  benefits an attacker with many cores at least as much as it benefits us.
- Measured on the development machine (release build, including process
  start): about 430 ms per unlock. Acceptable for a CLI that derives once
  per command and for a browser session that derives once per unlock.

Parameters and salt are stored in cleartext with the vault and are read
before the password is known. They are not secret: the salt's job is
uniqueness, and the cost parameters only describe how the key was derived.

## One parameter set for native and wasm

The spec allows lighter parameters for the wasm build if in-browser
derivation is too slow. That option is structurally unavailable for a
shared vault, and this is deliberate: the KDF parameters travel with the
vault, every client must run exactly the stored parameters to derive the
same key, and a browser deriving with lighter parameters would simply
compute a different key and fail the key check. Separate wasm parameters
would only apply to a vault created in the browser, which this project
does not do.

So one set serves both, and the browser is the binding constraint. The
wasm build runs the same derivation without native SIMD, estimated at
two to four times the native cost: roughly one to two seconds per unlock
on desktop hardware, longer on phones. That is a deliberate tradeoff:
unlock happens once per session, and weakening the parameters to save
browser seconds would weaken the only boundary the public path has. The
unlock runs in a Web Worker, so the page stays responsive while it grinds.
If a device proves too slow in practice, the remedy is re-creating the
vault with lighter parameters, accepted consciously, not a silent split
between clients.

## Consequences

- Offline guessing costs 256 MiB and three passes per attempt, per guess,
  with no shortcut for parallel hardware.
- Unlock latency is a felt half second natively and a felt second or two
  in the browser. That cost is the point.
- Wrong parameters cannot be introduced silently: the derived key changes
  and the key check tag fails.
- Vaults created before this revision keep their stored 64 MiB parameters
  and continue to work; new vaults get the new defaults.
