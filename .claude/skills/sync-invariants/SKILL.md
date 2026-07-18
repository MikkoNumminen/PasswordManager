---
name: sync-invariants
description: Verify the sync/storage invariants - AAD binds uuid+modified_ms at every seal/open site, conflict losers are persisted, and pulled records are verified under the vault key before local storage.
---

# sync-invariants

The three invariants that keep a malicious server harmless: ciphertext is
bound to its identity (no swap/re-stamp), conflict losers survive (no silent
data loss), and nothing unverified reaches local storage (no forged records
or deletions).

## Procedure

1. Run the collector FIRST:

   ```
   bash .claude/skills/sync-invariants/scripts/collect.sh
   ```

2. Reason ONLY about the collector output — with one structured exception
   built into this skill: **REVIEW lines**. A REVIEW line means the collector
   found the anchor but could not decide the invariant mechanically. For each
   REVIEW, read ONLY the exact `path:start-end` range it names (use Read with
   offset/limit), decide the invariant from that range, and say which way it
   went. Do not read anything beyond the named ranges, and do not re-derive
   what the OK lines already state.

3. Report per invariant (bound / preserved / verified), any REVIEW verdicts,
   then the SUMMARY.

## Reading the output

- `si-aad` — the AAD construction (`aad_with_prefix` in core/src/vault.rs)
  includes the entry UUID and modified_ms, with distinct entry/tombstone
  domain prefixes.
- `si-aead` — every AEAD call site, each with the AAD it binds; plus the
  guarantee that no AEAD is driven outside core::vault/core::crypto.
- `si-callers` — seal/open call-site counts per file. The binding is built
  inside `Vault::seal_entry`/`open_entry` from their `(id, modified_ms)`
  parameters, so callers cannot omit it.
- `si-conflict` — `preserve_version` stores the losing version locally AND
  pushes it, before the winner is applied; losing tombstones yield no copy
  (ADR 0006).
- `si-pull` — the full pull is filtered through `verify_record`; every other
  `apply_synced` site is either guarded within the preceding lines or feeds
  from the verified set; every `resolve_conflict` caller hands it a verified
  remote record.
- `si-server` — the server delegates push decisions to core's
  `lww_push_decision` and answers conflicts 409-with-winning-record.

## Deliberately out of scope

The extension and web JS clients (no local persistent store; they seal/open
through the same wasm `Session`, and a failed tag check aborts the whole
decrypt call). Checked implicitly by si-aead/si-callers on the Rust side.
