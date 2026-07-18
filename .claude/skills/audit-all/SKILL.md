---
name: audit-all
description: Run all six security-audit collectors (crypto-boundary, claims-vs-code, secret-hygiene, zeroize-audit, adr-integrity, sync-invariants) and report only high and medium findings with a one-paragraph verdict.
---

# audit-all

One pass over every audit collector. The collectors do ALL the analysis; this
skill only runs them, merges the numbers, and reports what matters.

## Procedure

1. Run all six collectors in ONE Bash call (each prints its own SUMMARY;
   `|| true` keeps a high finding in one collector from hiding the rest):

   ```bash
   for s in crypto-boundary claims-vs-code secret-hygiene zeroize-audit adr-integrity sync-invariants; do
     echo "== $s"
     bash ".claude/skills/$s/scripts/collect.sh" || true
   done
   ```

2. Do NOT re-run any analysis the collectors already did: no extra greps, no
   file reads, no git commands. REVIEW lines (sync-invariants) are the single
   exception — read only the exact ranges they name, per that skill's rules.

3. Report:
   - Every FINDING of severity **high** and **medium**, one line each, in
     collector order, marking which are the known accepted baseline (the
     per-skill SKILL.md files list them; on a clean tree the only baseline
     mediums are the two `za-export` findings — documented extension key
     custody).
   - Skip low findings and OK lines entirely in the report (say how many
     lows exist, nothing more). Note the collectors still EMIT the lows —
     the current documented baseline is 10 (9 crypto-boundary crate
     placements + web's DecryptedEntry) — you are filtering, they are not.
   - The six SUMMARY lines merged into one total:
     `TOTAL high=N medium=N low=N`.
   - A one-paragraph verdict: does the code still do what the README and
     ADRs claim, is anything new relative to the documented baseline, and
     the single most important item to fix if any.
