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

# Like scan, but drops everything at/after the file's first #[cfg(test)] so
# inline test modules (known-answer vectors, fixtures) are excluded.
scan_code() {
  cut_at=$(first_line "$1" '#\[cfg\(test\)\]')
  if [ -n "$cut_at" ]; then
    scan "$1" "$2" | awk -F: -v c="$cut_at" '($1+0) < (c+0)'
  else
    scan "$1" "$2"
  fi
}

# Print lines A..B of FILE (read-only window for context checks).
window() { sed -n "${2},${3}p" "$1" | tr -d '\r'; }

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
