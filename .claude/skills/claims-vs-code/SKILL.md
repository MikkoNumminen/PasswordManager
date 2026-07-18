---
name: claims-vs-code
description: Compare security values asserted in README.md and docs/adr (Argon2id parameters, AEAD name, nonce length, wasm-bindgen pin, default bind address) against the constants actually in the code.
---

# claims-vs-code

The README and ADRs assert exact numbers. Docs drift silently; constants do
not. This skill diffs the two.

## Procedure

1. Run the collector FIRST:

   ```
   bash .claude/skills/claims-vs-code/scripts/collect.sh
   ```

2. Reason ONLY about the collector output. Each OK/FINDING line is one
   comparison row carrying every located source, e.g.
   `OK cv-kdf-mem readme_kib=262144 adr0001_kib=262144 crypto_rs_kib=262144`.
   Do not open README.md, the ADRs, or the sources — the values are already
   extracted. The one exception: a FINDING whose extraction failed
   (`no locatable counterpart`) — then read only the file the check names to
   see whether the claim moved or genuinely disappeared.

3. Report each row, flag disagreements, end with the SUMMARY.

## Checks

| id | claim | sources compared |
|---|---|---|
| cv-kdf-mem/passes/lanes | Argon2id 256 MiB / 3 / 1 | README.md, docs/adr/0001, core/src/crypto.rs `KdfParams::default` |
| cv-aead | XChaCha20-Poly1305 | README.md, docs/adr/0002, core/src/crypto.rs |
| cv-nonce | 24-byte nonce | README.md, docs/adr/0003, `NONCE_LEN` |
| cv-wbg | wasm-bindgen 0.2.126 | README install cmd, web/Cargo.toml `=pin`, Cargo.lock; plus a CI probe |
| cv-bind | default 127.0.0.1:7787 | README.md, server/src/main.rs clap default, ops/oauth2-proxy.cfg upstream |

A **high** finding means the docs promise something the code does not do (or
extraction found disagreeing values). A **medium** finding means a claim has
no locatable counterpart — usually the README was reworded and the
collector's extraction pattern needs updating, which is itself worth knowing.
