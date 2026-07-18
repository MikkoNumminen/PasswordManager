#!/usr/bin/env bash
# crypto-boundary: assert crypto lives only in the core crate.
#   cb-deps     crypto crates in each crate's Cargo.toml
#   cb-use      direct `use` of crypto crates outside core/
#   cb-xor      hand-rolled xor loops over buffers
#   cb-cmp      manual (non-constant-time) comparison of secret-named values
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../../_shared/lib.sh"

# argon2/chacha20poly1305/secrecy outside core are a broken boundary: high.
# getrandom/zeroize/subtle are hygiene/adjacent crates with known deliberate
# uses outside core (terminal-buffer zeroize in cli, token ct_eq and token
# generation in server, browser RNG routing in web): flagged low so drift
# stays visible without failing CI.
CORE_ONLY='argon2|chacha20poly1305|secrecy'
DEP_RE='^(argon2|chacha20poly1305|getrandom|zeroize|secrecy|subtle) *='
USE_RE='^ *(pub +)?use (argon2|chacha20poly1305|getrandom|zeroize|secrecy|subtle)(::|;| )'

classify_crate() { # crate-name -> high|low
  case "$1" in
    argon2|chacha20poly1305|secrecy) echo high ;;
    *) echo low ;;
  esac
}

main() {
  # cb-deps ------------------------------------------------------------------
  for c in $CRATES; do
    t="$c/Cargo.toml"
    [ -f "$t" ] || { finding cb-deps medium "$t:0" "expected crate manifest is missing"; continue; }
    hits=$(scan "$t" "$DEP_RE")
    if [ "$c" = core ]; then
      n=$(printf '%s\n' "$hits" | grep -c . )
      ok cb-deps "core/Cargo.toml declares $n crypto crates (the one allowed home)"
      continue
    fi
    if [ -z "$hits" ]; then
      ok cb-deps "$c/Cargo.toml depends on no crypto crates"
      continue
    fi
    printf '%s\n' "$hits" | while IFS=: read -r ln txt; do
      [ -n "$ln" ] || continue
      crate=$(printf '%s' "$txt" | sed -E 's/^([a-z0-9_-]+).*/\1/')
      finding cb-deps "$(classify_crate "$crate")" "$t:$ln" "crypto crate '$crate' declared outside core"
    done
  done

  # cb-use -------------------------------------------------------------------
  use_hits=$(tracked '\.rs$' | grep -v '^core/' | while read -r f; do
    scan "$f" "$USE_RE" | sed "s|^|$f:|"
  done)
  if [ -z "$use_hits" ]; then
    ok cb-use "no direct use of crypto crates in Rust sources outside core/"
  else
    printf '%s\n' "$use_hits" | while IFS=: read -r f ln txt; do
      [ -n "$ln" ] || continue
      crate=$(printf '%s' "$txt" | sed -E 's/^ *(pub +)?use ([a-z0-9_]+).*/\2/')
      finding cb-use "$(classify_crate "$crate")" "$f:$ln" "direct use of '$crate' outside core"
    done
  fi

  # cb-xor -------------------------------------------------------------------
  xor_hits=$(rust_nontest | while read -r f; do
    scan_code "$f" '\^=' | sed "s|^|$f:|"
  done)
  if [ -z "$xor_hits" ]; then
    ok cb-xor "no xor-assignment loops in non-test Rust code (no hand-rolled cipher signal)"
  else
    printf '%s\n' "$xor_hits" | while IFS=: read -r f ln txt; do
      [ -n "$ln" ] || continue
      finding cb-xor high "$f:$ln" "xor over a buffer; possible hand-rolled crypto: $(printf '%s' "$txt" | sed 's/^ *//')"
    done
  fi

  # cb-cmp -------------------------------------------------------------------
  # ==/!= on the same line as a secret-named identifier, unless the line
  # already uses subtle's ct_eq. Catches timing-oracle comparisons.
  cmp_hits=$(rust_nontest | while read -r f; do
    scan_code "$f" '(password|passwd|secret|token|plaintext|[a-z_]key)[a-zA-Z_]* *(==|!=)' \
      | grep -v 'ct_eq' | sed "s|^|$f:|"
  done)
  if [ -z "$cmp_hits" ]; then
    ok cb-cmp "no ==/!= comparisons of secret-named values in non-test Rust code (subtle::ct_eq paths only)"
  else
    printf '%s\n' "$cmp_hits" | while IFS=: read -r f ln txt; do
      [ -n "$ln" ] || continue
      finding cb-cmp high "$f:$ln" "non-constant-time comparison of a secret-named value: $(printf '%s' "$txt" | sed 's/^ *//')"
    done
  fi
}

run_and_summarize main
