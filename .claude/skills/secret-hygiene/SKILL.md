---
name: secret-hygiene
description: Scan the working tree and git history for committed secrets, verify .gitignore coverage, and list every log/print/panic statement that touches secret words - logging is the realistic leak path.
---

# secret-hygiene

The README claims "Nothing secret is committed." This skill checks the tree,
the history, the ignore rules, and — the realistic leak path in a
zero-knowledge design — what the code logs.

## Procedure

1. Run the collector FIRST:

   ```
   bash .claude/skills/secret-hygiene/scripts/collect.sh
   ```

2. Reason ONLY about the collector output. Do not read source files or run
   your own git archaeology. The one exception: a FINDING you cannot classify
   from its fact line — then read only the named path (for `sh-history`
   findings, `git log --all --oneline -- <path>` on that one path is allowed
   to see when it entered).

3. Report findings with verdicts, then the SUMMARY.

## Reading the output

- `sh-tracked` — env/key/db/credential-shaped files tracked right now (high).
- `sh-names` — files literally named token/secret/credential. Source modules
  (`vaultctl/src/secrets.rs` manages out-of-repo secrets) are OK by rule;
  their contents are covered by `sh-literals`.
- `sh-ignore` — one line per required .gitignore pattern.
- `sh-literals` — long base64/hex runs. Known-answer vectors in test files or
  `#[cfg(test)]` modules are reported OK (they are supposed to exist);
  `Cargo.lock` checksums are excluded. Anything else is high.
- `sh-log` — every print/log/panic macro mentioning a secret word. Static
  prompt text is OK; interpolating a secret-named value is high. Two exact
  lines are allowlisted by content (the CLI `--reveal` printout and the
  server `token` subcommand's one-time print) — any edit to them re-flags.
- `sh-history` — secret-shaped file names ever added in any commit. A hit is
  high even if the file was later deleted: history retains it.

## Deliberately out of scope

JS `console.log` hygiene in the extension (no Rust macros there), secrets in
the developer's environment, and dependency vulnerabilities. See
`.claude/skills/README.md`.
