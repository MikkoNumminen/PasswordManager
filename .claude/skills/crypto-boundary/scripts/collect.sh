#!/usr/bin/env bash
# crypto-boundary: assert crypto lives only in the core crate.
#   cb-deps     crypto crates in each crate's Cargo.toml (plain, dotted
#               workspace-inheritance, [dependencies.x] table, and
#               package-rename declaration forms)
#   cb-use      direct `use` or fully-qualified `crate::` paths of crypto
#               crates outside core/
#   cb-xor      hand-rolled xor loops over buffers
#   cb-cmp      manual (non-constant-time) comparison of secret-named values
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../../_shared/lib.sh"

# The six crates the design names, plus a broader net of common Rust crypto
# crates so a NEW primitive appearing outside core (aes-gcm, ring, ...) is
# not invisible just because the design never used it.
#   argon2/chacha20poly1305/secrecy outside core: high (broken boundary).
#   getrandom/zeroize/subtle: low (hygiene/adjacent crates with known
#   deliberate uses outside core - see SKILL.md baseline).
#   Anything from OTHER_CRYPTO: high outside core, except the allowlist.
KNOWN='argon2|chacha20poly1305|getrandom|zeroize|secrecy|subtle'
OTHER_CRYPTO='aes|aes-gcm|aes-siv|ring|rsa|dsa|pbkdf2|scrypt|bcrypt|hmac|sha-?1|sha2|sha3|md-?5|blake2|blake3|ed25519-dalek|x25519-dalek|curve25519-dalek|p256|p384|k256|chacha20|salsa20|xsalsa20poly1305|poly1305|crypto_secretbox|crypto_box|sodiumoxide|openssl|orion|dryoc'
OTHER_USE=$(printf '%s' "$OTHER_CRYPTO" | tr -d '-')   # crate names as idents

classify_crate() { # crate-name -> high|low
  case "$1" in
    getrandom|zeroize|subtle) echo low ;;
    *) echo high ;;
  esac
}

# The one accepted OTHER_CRYPTO use: the server hashes the API token with
# SHA-256 (server/src/app.rs documents it; a hash of a non-key credential,
# no encryption, no key material). Printed OK so any second use re-flags.
allowlisted_other() { # crate-name file -> 0 if allowlisted
  case "$1:$2" in
    sha2:server/Cargo.toml|sha2:server/src/*) return 0 ;;
    *) return 1 ;;
  esac
}

main() {
  # cb-deps ------------------------------------------------------------------
  dep_re="^($KNOWN|$OTHER_CRYPTO)( *=|\.)|^\[.*dependencies\.($KNOWN|$OTHER_CRYPTO)\]|package *= *\"($KNOWN|$OTHER_CRYPTO)\""
  for c in $CRATES; do
    t="$c/Cargo.toml"
    [ -f "$t" ] || { finding cb-deps medium "$t:0" "expected crate manifest is missing"; continue; }
    hits=$(scan "$t" "$dep_re")
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
      crate=$(printf '%s' "$txt" | sed -E 's/^\[.*dependencies\.([a-z0-9_-]+)\].*/\1/; s/.*package *= *"([a-z0-9_-]+)".*/\1/; s/^([a-z0-9_-]+).*/\1/')
      if allowlisted_other "$crate" "$t"; then
        ok cb-deps "$t:$ln sha2 hashes the API token only (documented; no encryption, no key material)"
      else
        finding cb-deps "$(classify_crate "$crate")" "$t:$ln" "crypto crate '$crate' declared outside core"
      fi
    done
  done

  # cb-use -------------------------------------------------------------------
  # `use crate::...` imports AND fully-qualified `crate::path` calls (which
  # need no use line). The qualified pattern requires the crate name not to
  # be preceded by path/ident chars, so core's re-exports
  # (password_manager_core::secrecy::...) do not match. A dependency renamed
  # via `package = "..."` is caught by cb-deps at the declaration.
  use_re="^ *(pub +)?use ($KNOWN|$OTHER_USE)(::|;| )|(^|[^:_a-zA-Z0-9])($KNOWN|$OTHER_USE)::"
  # Non-test code only: test files and inline #[cfg(test)] modules may drive
  # crypto crates freely (server tests hash tokens, build vaults, etc.); the
  # boundary claim is about product code.
  use_hits=$(rust_nontest | grep -v '^core/' | while read -r f; do
    scan_code "$f" "$use_re" | sed "s|^|$f:|"
  done)
  if [ -z "$use_hits" ]; then
    ok cb-use "no direct use or qualified path of crypto crates in Rust sources outside core/"
  else
    printf '%s\n' "$use_hits" | while IFS=: read -r f ln txt; do
      [ -n "$ln" ] || continue
      crate=$(printf '%s' "$txt" | grep -Eo "(^|[^:_a-zA-Z0-9])($KNOWN|$OTHER_USE)(::|;| )" | head -n1 | sed -E 's/^[^a-z0-9_]*//; s/[^a-z0-9_].*$//')
      [ -n "$crate" ] || crate=unrecognized
      if allowlisted_other "$crate" "$f"; then
        ok cb-use "$f:$ln sha2 hashes the API token only (documented; no encryption, no key material)"
      else
        finding cb-use "$(classify_crate "$crate")" "$f:$ln" "crypto crate '$crate' referenced outside core"
      fi
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
