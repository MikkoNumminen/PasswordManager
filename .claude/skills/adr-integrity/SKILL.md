---
name: adr-integrity
description: Check the ADR set in docs/adr - every ADR has a status, superseded ADRs name their successor, references point at ADRs that exist, and no ADR is orphaned.
---

# adr-integrity

The ADRs are the argued-for record of the security design; the README leans
on them by number. This skill checks the record stays coherent.

## Procedure

1. Run the collector FIRST:

   ```
   bash .claude/skills/adr-integrity/scripts/collect.sh
   ```

2. Reason ONLY about the collector output. It already lists every ADR with
   number, status, and title, and every cross-reference count. Do not read
   the ADR files. The one exception: a FINDING you cannot classify — then
   read only the named file's `## Status` section.

3. Report findings, then the SUMMARY.

## Reading the output

- `ai-index` — one line per ADR: `ADR 0006 [Accepted] Sync conflict policy`.
- `ai-status` — an ADR without a `## Status` paragraph (medium).
- `ai-super` — a status saying "superseded" must name the successor ADR
  (medium if not). ADR 0008's partial supersession by 0009 is the expected OK.
- `ai-ref` — a reference (`ADR 0123` prose or `docs/adr/0123-...` path) to an
  ADR that does not exist (medium: a broken pointer in docs or code).
- `ai-orphan` — an ADR nothing references outside its own file (low). Cross
  references from other ADRs count.
