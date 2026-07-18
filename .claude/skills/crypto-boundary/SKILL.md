---
name: crypto-boundary
description: Audit that crypto lives only in the core crate - flags crypto crate dependencies or direct use elsewhere and hand-rolled crypto signals (xor loops, non-constant-time secret comparison).
---

# crypto-boundary

The README claims `core` is "the only place crypto exists". This skill detects
drift from that claim.

## Procedure

1. Run the collector FIRST, before anything else:

   ```
   bash .claude/skills/crypto-boundary/scripts/collect.sh
   ```

2. Reason ONLY about the collector output. Do not read source files. The one
   exception: a FINDING you cannot classify from its fact line — then read
   only the exact path the finding names, nothing else.

3. Report: each FINDING with your verdict (real drift / accepted baseline),
   then the SUMMARY line. Exit code 1 means at least one high finding.

## Reading the output

- `cb-deps` / `cb-use` — crypto crates outside `core/`. Severity encodes the
  class: `argon2`, `chacha20poly1305`, `secrecy` outside core are **high**
  (the boundary is broken); `getrandom`, `zeroize`, `subtle` are **low**
  (hygiene/adjacent crates with known deliberate uses — see baseline).
- `cb-xor` — xor-assignment over buffers: hand-rolled cipher signal.
- `cb-cmp` — `==`/`!=` on secret-named values instead of `subtle::ct_eq`.

## Known baseline (2026-07-18)

Deliberate, documented low findings — report them as accepted baseline, not
new drift:

- `cli`: `subtle` (constant-time password-confirm compare), `zeroize`
  (terminal buffer wipe in `cli/src/prompt.rs`).
- `server`: `getrandom` (API token generation), `subtle` (constant-time token
  hash compare in `server/src/app.rs`). The server's Cargo.toml deliberately
  imports core with no crypto features.
- `web`: `getrandom` with the `js` feature (routes the OS RNG to the
  browser); the crate holds no crypto calls of its own.

Anything beyond this list, or any high finding, is new drift.
