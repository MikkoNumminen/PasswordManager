#!/usr/bin/env bash
# Shared helpers for the repo-local audit collectors. Sourced, never executed.
#
# Contract for every collector that sources this:
#   - Read-only: no file writes, no git mutations, nothing that compiles.
#   - No network.
#   - Output: one line per check result, machine-readable:
#       OK <check-id> <short fact>
#       FINDING <check-id> <high|medium|low> <path>:<line> <short fact>
#       REVIEW <check-id> <path>:<start>-<end> <short fact>   (sync-invariants only)
#     ending with: SUMMARY high=N medium=N low=N
#   - Exit 0 when there are no high findings, 1 otherwise (CI-wireable).

set -u

# Byte collation everywhere: sort order and ERE ranges must not depend on the
# caller's locale, or the "deterministic output" promise breaks across
# machines (empty LANG here, C.UTF-8 on CI runners, en_US.UTF-8 elsewhere).
export LC_ALL=C

# --- workspace root ---------------------------------------------------------

repo_root() {
  r=$(git rev-parse --show-toplevel 2>/dev/null) && { printf '%s\n' "$r"; return 0; }
  # Fallback without git: walk up to the [workspace] Cargo.toml.
  d=$PWD
  while [ -n "$d" ] && [ "$d" != "/" ]; do
    if [ -f "$d/Cargo.toml" ] && grep -q '^\[workspace\]' "$d/Cargo.toml" 2>/dev/null; then
      printf '%s\n' "$d"; return 0
    fi
    d=$(dirname "$d")
  done
  return 1
}

ROOT=$(repo_root) || {
  echo "FINDING lib high .:0 cannot locate the workspace root (no git, no [workspace] Cargo.toml)"
  echo "SUMMARY high=1 medium=0 low=0"
  exit 1
}
cd "$ROOT" || exit 1

# Workspace crates by directory. core is the only crate allowed to hold crypto.
CRATES="core cli server web vaultctl"

# --- file discovery ---------------------------------------------------------

# Tracked files only: respects .gitignore (vendored wasm, node_modules, local
# scratch are never scanned) and git's sorted output keeps runs deterministic.
tracked() { # tracked [ere-filter]
  if [ $# -gt 0 ]; then git ls-files | grep -E "$1" || true
  else git ls-files; fi
}

# Rust sources excluding dedicated test dirs (inline #[cfg(test)] modules are
# handled separately by scan_code).
rust_nontest() {
  tracked '\.rs$' | grep -Ev '(^|/)tests/' || true
}

# --- searching --------------------------------------------------------------
# scan FILE ERE   -> "line:text" matches (ripgrep when available, grep fallback)
# scan_o FILE ERE -> "line:match" (only the matched text)
# CR is stripped so CRLF checkouts compare cleanly.

if command -v rg >/dev/null 2>&1; then
  scan()   { rg -n  --no-filename -e "$2" -- "$1" 2>/dev/null | tr -d '\r'; return 0; }
  scan_o() { rg -no --no-filename -e "$2" -- "$1" 2>/dev/null | tr -d '\r'; return 0; }
else
  scan()   { grep -En  -e "$2" -- "$1" 2>/dev/null | tr -d '\r'; return 0; }
  scan_o() { grep -Eon -e "$2" -- "$1" 2>/dev/null | tr -d '\r'; return 0; }
fi

# First line number in FILE matching ERE; empty when absent.
first_line() { scan "$1" "$2" | head -n1 | cut -d: -f1; }

# Line number of the '#[cfg(test)]' that opens the file's inline test module
# (i.e. is directly followed by a `mod` line); empty if none. Deliberately
# NOT the first #[cfg(test)] anywhere: a cfg-gated import or a comment near
# the top of a file must not blind the scan to all real code below it.
test_mod_line() {
  awk '/#\[cfg\(test\)\]/ { n = NR; getline
         if ($0 ~ /^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]/) { print n; exit } }' "$1"
}

# Like scan, but drops everything at/after the file's inline test module so
# known-answer vectors and fixtures are excluded.
scan_code() {
  cut_at=$(test_mod_line "$1")
  if [ -n "$cut_at" ]; then
    scan "$1" "$2" | awk -F: -v c="$cut_at" '($1+0) < (c+0)'
  else
    scan "$1" "$2"
  fi
}

# Print lines A..B of FILE (read-only window for context checks). Addresses
# are sanitized: non-numeric or empty yields no output instead of sed errors,
# and out-of-order/zero addresses are clamped, so callers can pass raw
# first_line results without guarding.
window() {
  case "$2" in ''|*[!0-9]*) return 0 ;; esac
  case "$3" in ''|*[!0-9]*) return 0 ;; esac
  ws=$2; we=$3
  [ "$ws" -lt 1 ] && ws=1
  [ "$we" -lt "$ws" ] && we=$ws
  sed -n "${ws},${we}p" "$1" | tr -d '\r'
}

# max(1, A-B): for building "N lines back" addresses and REVIEW ranges that
# can never go to zero or negative near the top of a file.
back() {
  br=$(( $1 - $2 ))
  [ "$br" -lt 1 ] && br=1
  printf '%s' "$br"
}

# --- output -----------------------------------------------------------------

trunc() { cut -c1-200; }

ok()      { printf 'OK %s %s\n' "$1" "$2" | trunc; }                 # ok ID FACT
finding() { printf 'FINDING %s %s %s %s\n' "$1" "$2" "$3" "$4" | trunc; } # finding ID SEV PATH:LINE FACT
review()  { printf 'REVIEW %s %s %s\n' "$1" "$2" "$3" | trunc; }     # review ID PATH:A-B FACT

# Run the named function, then derive SUMMARY and the exit code from what it
# printed. Keeps the checks free of counter state (no subshell-loss bugs).
run_and_summarize() {
  report=$("$@")
  [ -n "$report" ] && printf '%s\n' "$report"
  h=$(printf '%s\n' "$report" | grep -c '^FINDING [a-z0-9_-]* high ')
  m=$(printf '%s\n' "$report" | grep -c '^FINDING [a-z0-9_-]* medium ')
  l=$(printf '%s\n' "$report" | grep -c '^FINDING [a-z0-9_-]* low ')
  printf 'SUMMARY high=%s medium=%s low=%s\n' "$h" "$m" "$l"
  [ "$h" -eq 0 ]
}
