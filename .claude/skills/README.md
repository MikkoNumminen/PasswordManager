# Repo-local audit skills

Cheap, repeatable drift detection between what the README/ADRs claim and what
the code does. Each skill is a `SKILL.md` plus a read-only collector script
(`scripts/collect.sh`); the collector gathers ALL context and prints a
compact machine-readable report, and the model reasons only about that
report. Shared helpers live in `_shared/lib.sh`.

Run any collector directly (bash, from anywhere inside the repo — it finds
the workspace root itself):

```bash
bash .claude/skills/crypto-boundary/scripts/collect.sh
```

Output format, designed to be CI-wireable without a model in the loop:

```
OK <check-id> <short fact>
FINDING <check-id> <high|medium|low> <path>:<line> <short fact>
REVIEW <check-id> <path>:<start>-<end> <short fact>     (sync-invariants only)
SUMMARY high=N medium=N low=N
```

Exit code: 0 when there are no high findings, 1 otherwise.

Runtime: seconds on Linux; on Windows (Git Bash, process-spawn bound) expect
roughly 2-25 s per collector, about a minute for all six.

## The skills

| skill | checks | key checks-ids |
|---|---|---|
| `crypto-boundary` | Crypto crates and direct `use` only in `core`; no hand-rolled xor loops; no non-constant-time secret comparison | cb-deps, cb-use, cb-xor, cb-cmp |
| `claims-vs-code` | Argon2id params, AEAD name, nonce length, wasm-bindgen pin, default bind — README/ADR values vs the actual constants | cv-kdf-*, cv-aead, cv-nonce, cv-wbg, cv-bind |
| `secret-hygiene` | Committed secrets in tree and git history, .gitignore coverage, long base64/hex literals outside test vectors, log/print/panic statements touching secret words | sh-tracked, sh-names, sh-ignore, sh-literals, sh-log, sh-history |
| `zeroize-audit` | Key/plaintext custody: SecretBox/Zeroizing/ZeroizeOnDrop wrappers, unwrapped key material returned by value, secret copies into plain Strings | za-key-wrap, za-derive, za-decrypt, za-entrydata, za-export, za-pwfield, za-copy, za-rawfield |
| `adr-integrity` | Every ADR numbered/titled/statused; superseded ADRs name successors; references resolve; no orphans | ai-index, ai-status, ai-super, ai-ref, ai-orphan |
| `sync-invariants` | AAD binds uuid+modified_ms at every AEAD site; conflict losers persisted before winners apply; pulled records verified before storage; server delegates to core's LWW rule | si-aad, si-aead, si-callers, si-conflict, si-pull, si-server |
| `audit-all` | Runs all six, reports high+medium only, one-paragraph verdict | — |

## Known baseline

The repo is not finding-free by design; the accepted findings are documented
in each SKILL.md ("Known baseline"). In short: crypto-adjacent crates
(`getrandom`/`zeroize`/`subtle`) in cli/server/web are deliberate lows, and
the two `export_key -> Vec<u8>` functions (extension key custody across MV3
service-worker eviction) are deliberate mediums. They stay visible on purpose:
an allowlisted-and-silent finding could grow new call sites unnoticed.

## Deliberately NOT checked here

- **Dependency vulnerabilities** — `cargo audit`/Dependabot territory; needs
  a network and a moving database, which collectors must not touch.
- **Formatting and lints** — `cargo fmt --check` and `clippy -D warnings`
  already gate CI.
- **Whether the crypto is correct** — the known-answer tests in
  `core/src/crypto.rs` and `cargo test` do that; collectors never compile.
- **JS-side console hygiene / extension behavior** — no Rust macros there;
  the extension's security gates are reviewed per-PR, not pattern-matched.
- **Live infrastructure** (funnel, oauth2-proxy, running server state) —
  collectors are offline and read-only by contract.

## Adding a check to an existing collector

1. Pick the collector and add a block inside its `main()`. Use the helpers
   from `_shared/lib.sh`: `tracked [ere]` (git-tracked files only — respects
   .gitignore), `scan FILE ERE` (`line:text`), `scan_o` (`line:match`),
   `scan_code` (like scan but stops at `#[cfg(test)]`), `first_line`,
   `window FILE A B`.
2. Emit exactly one of `ok <id> <fact>` / `finding <id> <sev> <path>:<line>
   <fact>` / `review <id> <path>:<a>-<b> <fact>` per result. New check-id =
   the collector's prefix + a short noun (`sh-log`, `si-pull`).
3. Severity: **high** = a README/ADR security promise is broken (fails CI);
   **medium** = real drift or an extraction that lost its anchor; **low** =
   visible-by-design baseline or informational.
4. Keep it deterministic: iterate `tracked` file lists (never glob the
   filesystem), no timestamps, no network, no cargo, no writes.
5. If the check has an accepted baseline hit, prefer an exact-content
   allowlist that prints an OK line with the justification (see `sh-log`) —
   the moment the line changes, it re-flags.
6. Run the collector on the clean tree; confirm the new check emits OK (or a
   documented finding), keeps total output under ~100 lines, and document
   the check in the collector header, its SKILL.md, and the table above.
