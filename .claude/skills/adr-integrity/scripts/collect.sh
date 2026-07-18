#!/usr/bin/env bash
# adr-integrity: the ADR set is complete, statused, and actually referenced.
#   ai-index    every ADR with number, title, status
#   ai-status   ADRs missing a status
#   ai-super    superseded ADRs must name a successor
#   ai-ref      references to ADRs that do not exist
#   ai-orphan   ADRs nothing references
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../../_shared/lib.sh"

# Status paragraph: everything between '## Status' and the next '## ' heading,
# joined to one line.
status_of() {
  awk '/^## Status/{s=1; next} s && /^## /{exit} s{printf "%s ", $0}' "$1" | tr -d '\r' | sed 's/  */ /g; s/^ //; s/ $//'
}

main() {
  adrs=$(tracked '^docs/adr/[0-9]{4}-.*\.md$')
  if [ -z "$adrs" ]; then
    finding ai-index high "docs/adr:0" "no ADR files found where README says they live"
    return
  fi

  nums=""
  for f in $adrs; do
    n=$(basename "$f" | cut -c1-4)
    nums="$nums $n"
    title=$(head -n1 "$f" | tr -d '\r' | sed -E 's/^# *(ADR [0-9]+: *)?//')
    status=$(status_of "$f")
    if [ -z "$status" ]; then
      finding ai-status medium "$f:1" "no status recorded (title: $title)"
    else
      word=$(printf '%s' "$status" | sed -E 's/[ (.].*//')
      ok ai-index "ADR $n [$word] $title"
    fi
    if printf '%s' "$status" | grep -qi 'superseded'; then
      succ=$(printf '%s' "$status" | grep -Eo 'ADR [0-9]{4}' | head -n1)
      if [ -n "$succ" ]; then
        ok ai-super "ADR $n superseded parts name their successor ($succ)"
      else
        finding ai-super medium "$f:3" "marked superseded without naming a successor ADR"
      fi
    fi
  done

  # All references, from every tracked text file EXCEPT the audit skills
  # themselves (.claude/): the auditor's own docs must never create or
  # sustain reference evidence (self-certification) or flag their own format
  # examples. Handles the prose form 'ADR 0009', the list form
  # 'ADR 0002, 0003', and the path form 'docs/adr/0009-...'; every 4-digit
  # group inside a match is one reference.
  refs=$(tracked '\.(md|rs|js|mjs|ts|toml|yml|ps1|cfg|json|html)$' | grep -v '^\.claude/' | while read -r f; do
    scan_o "$f" 'ADR [0-9]{4}(, *[0-9]{4})*|docs/adr/[0-9]{4}' \
      | awk -F: -v f="$f" '{ ln=$1; s=$0; sub(/^[0-9]+:/, "", s)
          while (match(s, /[0-9][0-9][0-9][0-9]/)) {
            print f ":" ln ":" substr(s, RSTART, 4); s = substr(s, RSTART+4) } }'
  done)

  # ai-ref: every referenced number must exist.
  printf '%s\n' "$refs" | sort -u | while IFS=: read -r f ln n; do
    [ -n "$n" ] || continue
    case " $nums " in
      *" $n "*) : ;;
      *) finding ai-ref medium "$f:$ln" "references ADR $n, which does not exist in docs/adr/" ;;
    esac
  done

  # ai-orphan: every ADR must be referenced from somewhere outside itself.
  for n in $nums; do
    cnt=$(printf '%s\n' "$refs" | awk -F: -v n="$n" -v self="docs/adr/$n" \
      'index($1, self) != 1 && $3 == n' | wc -l | tr -d ' ')
    if [ "$cnt" -gt 0 ]; then
      ok ai-orphan "ADR $n referenced ${cnt}x outside its own file"
    else
      finding ai-orphan low "docs/adr:0" "ADR $n is referenced by nothing (dead decision record?)"
    fi
  done
}

run_and_summarize main
