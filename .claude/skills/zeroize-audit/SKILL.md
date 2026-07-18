---
name: zeroize-audit
description: Audit that key and plaintext material lives in SecretBox/Zeroizing wrappers or ZeroizeOnDrop types, and flag key material returned by value in unwrapped types.
---

# zeroize-audit

The threat model promises "Keys and plaintext are zeroized after use". This
skill checks the custody chain: derivation, decryption, the data model, and
every place a secret escapes into a raw `Vec<u8>` or `String`.

## Procedure

1. Run the collector FIRST:

   ```
   bash .claude/skills/zeroize-audit/scripts/collect.sh
   ```

2. Reason ONLY about the collector output. Confirmed-good custody is printed
   as OK lines precisely so you do not need the sources. The one exception:
   a FINDING you cannot classify from its fact line — then read only the
   named path:line and its immediate function.

3. Report findings with verdicts, then the SUMMARY.

## Reading the output

- `za-key-wrap` / `za-derive` / `za-decrypt` / `za-entrydata` — the four
  custody anchors. All four OK means: password → Argon2id → `VaultKey`
  (SecretBox) → decrypt → `Zeroizing`/`EntryData` (ZeroizeOnDrop). Any of
  them failing is high: the promise in the threat model is broken.
- `za-export` — functions returning raw key bytes by value. **Known
  baseline:** `core/src/vault.rs export_key` and `web/src/lib.rs export_key`
  are deliberate (the MV3 extension must park the key in
  `chrome.storage.session` across service-worker eviction; documented in
  core::vault and ADR 0008/0009). They stay medium findings on purpose so
  new callers or a third escape cannot appear silently — report them as
  accepted baseline, not new drift.
- `za-pwfield` — `password: String` fields without ZeroizeOnDrop. **Known
  baseline:** `web/src/lib.rs` `DecryptedEntry` (low) — it is serialized to
  JavaScript, which is the browser client's documented nature; the wasm-side
  copy is not wiped.
- `za-skip` — any `#[zeroize(skip)]` attribute: fine on a non-secret field
  (OK), **high** on a secret-named one — the derive stays visible while the
  wiping silently stops, which would fool the other checks.
- `za-copy` — `expose_secret()` copied into a plain String. OK when the copy
  moves into `EntryData` (zeroized on drop) or is the API token (not key
  material, cleartext custody by design per ADR 0007).
- `za-rawfield` — secret-named raw fields; `key_check_*` and `token*` are
  non-secret by design and reported OK.
- `za-keybuf` — derive_key's raw key buffer custody: zeroized on the error
  path, moved into VaultKey on success. A finding here is a broken zeroize
  path in key derivation (high), not a naming issue.
