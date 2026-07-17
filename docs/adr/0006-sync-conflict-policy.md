# ADR 0006: Sync conflict policy

## Status

Accepted (Phase 3). Revised after review: change detection no longer uses a
timestamp cursor, deletions are authenticated, conflict copies are
deterministic, and records pulled from the server are verified before they
are stored.

## Context

Multiple devices edit the same vault and sync through a server that cannot
read anything. Whatever resolves conflicts has to run on ciphertext
metadata (UUID, modified timestamp) plus whatever the unlocked client can
decrypt locally. Silent data loss is the failure mode to avoid: a password
overwritten by a stale copy may be unrecoverable. Device clocks cannot be
trusted to agree, so correctness must not depend on comparing one device's
clock against another's.

## Decision

Last write wins by modified timestamp, with every losing live version
preserved, over clock-skew-immune change detection.

- Each entry carries a modified timestamp in milliseconds, strictly
  increasing per entry on every write (`next_modified`).
- Local change detection is a per-record synced marker in the client
  database (`synced_ms`), set only after the server confirms a push or when
  a record arrives from the server. A record is pushed when its marker does
  not match its content, never because of how its timestamp compares to a
  cursor. A device with a wrong clock can lose conflicts it should win, but
  nothing ever fails to sync.
- The pull side downloads the full remote set and reconciles it against
  local state. Vault sizes are personal scale; correctness beats a delta
  protocol here.
- Every record pulled from the server must authenticate under the vault key
  before it is stored: live records must decrypt, tombstones must carry a
  valid sealed deletion marker (ADR 0005). A server cannot inject records
  or forge deletions; unverifiable records are ignored.
- The push rule lives in one function, `sync::lww_push_decision`, called by
  the real server and by the test double: unknown id or strictly newer
  timestamp applies, a byte-identical record is an idempotent success, and
  anything else is rejected with the server's record in the body (409).
- An entry changed on both sides is a conflict: the newer timestamp wins on
  both sides, ties go to the remote so every device resolves identically.
- The losing version, when it is a live entry, is decrypted and re-sealed
  as a new entry titled `<title> (conflict <short id>)`, stored locally and
  pushed. Its UUID is derived deterministically (UUIDv5) from the losing
  record's identity, so a sync interrupted and retried regenerates the same
  copy instead of accumulating duplicates. A losing deletion has no content
  to preserve and is only reported.
- Every conflict is printed by `password-manager sync` with the winner and
  the name of any conflict copy. Nothing is dropped silently.
- The engine refuses to sync when the remote vault metadata differs from
  the local vault (`VaultMeta::same_vault`): that is a different vault, not
  a conflict.

## Consequences

- No sync ever destroys the only copy of a live entry version. Cleanup of
  conflict copies is manual and visible.
- Clock skew affects only who wins a conflict, never whether data syncs.
  The losing version still survives as a copy, so the damage is ordering,
  never loss.
- Timestamps are bound into the AEAD associated data (ADR 0005), so the
  server cannot re-stamp a record to win last-write-wins. It can only
  replay a complete older record, which the threat model names.
- Pushes go one record per request. At personal scale that is fine; an
  interrupted push resumes safely on the next sync because dirty markers
  only clear on server confirmation. If vaults ever grow large enough for
  round trips to hurt, a batch push endpoint is the extension point.
