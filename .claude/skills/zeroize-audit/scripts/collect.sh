#!/usr/bin/env bash
# zeroize-audit: key and plaintext material must live in Secret*/Zeroizing
# wrappers or ZeroizeOnDrop types. Confirmed-good custody is reported as OK
# lines so the findings stand out against a visible baseline.
#   za-key-wrap    the vault key type wraps SecretBox
#   za-derive      key derivation returns the wrapped type
#   za-decrypt     decrypt returns Zeroizing plaintext
#   za-entrydata   the decrypted entry type zeroizes on drop
#   za-export      key material returned by value in an unwrapped type
#   za-pwfield     password-holding String fields without a zeroize derive
#   za-skip        #[zeroize(skip)] excluding a secret-named field from wiping
#   za-copy        expose_secret() copied into an unmanaged String
#   za-rawfield    key/secret-named raw byte fields
#   za-keybuf      derive_key's raw key buffer custody (zeroize on error,
#                  move into VaultKey on success)
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../../_shared/lib.sh"

CRYPTO_RS=core/src/crypto.rs
VAULT_RS=core/src/vault.rs
MODEL_RS=core/src/model.rs

main() {
  # za-key-wrap --------------------------------------------------------------
  ln=$(first_line "$CRYPTO_RS" 'struct VaultKey\(SecretBox<\[u8; KEY_LEN\]>\)')
  if [ -n "$ln" ]; then
    ok za-key-wrap "VaultKey wraps SecretBox<[u8; KEY_LEN]> ($CRYPTO_RS:$ln); zeroized on drop"
  else
    finding za-key-wrap high "$CRYPTO_RS:0" "VaultKey no longer matches the SecretBox wrapper shape"
  fi

  # za-derive ----------------------------------------------------------------
  ln=$(first_line "$CRYPTO_RS" 'fn derive_key\(')
  sig=$(window "$CRYPTO_RS" "$ln" $((ln+5)) | tr -d '\n')
  if printf '%s' "$sig" | grep -q 'Result<VaultKey'; then
    ok za-derive "derive_key returns VaultKey, never raw bytes ($CRYPTO_RS:$ln)"
  else
    finding za-derive high "$CRYPTO_RS:${ln:-0}" "derive_key does not return the wrapped VaultKey type"
  fi

  # za-decrypt ---------------------------------------------------------------
  ln=$(first_line "$CRYPTO_RS" 'Result<Zeroizing<Vec<u8>>')
  if [ -n "$ln" ]; then
    ok za-decrypt "decrypt returns Zeroizing<Vec<u8>>; plaintext wiped when dropped ($CRYPTO_RS:$ln)"
  else
    finding za-decrypt high "$CRYPTO_RS:0" "decrypt no longer returns Zeroizing plaintext"
  fi

  # za-entrydata -------------------------------------------------------------
  dl=$(first_line "$MODEL_RS" 'struct EntryData')
  der=$(window "$MODEL_RS" "$(back "${dl:-0}" 2)" "$dl")
  if printf '%s' "$der" | grep -q 'ZeroizeOnDrop'; then
    ok za-entrydata "EntryData derives Zeroize + ZeroizeOnDrop ($MODEL_RS:$dl)"
  else
    finding za-entrydata high "$MODEL_RS:${dl:-0}" "EntryData does not derive ZeroizeOnDrop"
  fi

  # za-export ----------------------------------------------------------------
  # Any fn returning raw key material by value. The two export_key fns exist
  # for exactly one client (the extension's chrome.storage.session custody,
  # documented in core::vault) but they ARE unwrapped key bytes; kept visible
  # as medium findings so new callers or new escapes cannot appear silently.
  # Candidate fns are found by name, then the signature is JOINED across up
  # to four lines before testing the return type, so a rustfmt-wrapped
  # signature cannot hide the escape. References (&[u8...]) are borrows, not
  # escapes, and do not match.
  rust_nontest | while read -r f; do
    scan_code "$f" 'fn [a-z_]*(export|key|byte)[a-z_]*\(' | while IFS=: read -r ln txt; do
      [ -n "$ln" ] || continue
      sig=$(window "$f" "$ln" $((ln+3)) | tr -d '\n')
      printf '%s' "$sig" | grep -Eq -- '-> *(Vec<u8>|Box<\[u8|\[u8;|String)' || continue
      printf '%s' "$sig" | grep -Eq 'key_check|token_hash' && continue
      finding za-export medium "$f:$ln" "returns raw key material by value: $(printf '%s' "$txt" | sed 's/^ *//')"
    done
  done
  n=$(rust_nontest | while read -r f; do scan_code "$f" '\.export_key\(\)'; done | grep -c .)
  ok za-export "export_key call sites in Rust: $n (web Session::export_key wrapping core; extension-only custody)"

  # za-pwfield ---------------------------------------------------------------
  rust_nontest | while read -r f; do
    scan_code "$f" '^ *(pub )?password: *String' | while IFS=: read -r ln txt; do
      [ -n "$ln" ] || continue
      # Look back up to 12 lines for the struct's derive attribute.
      start=$((ln > 14 ? ln - 14 : 1))
      ctx=$(window "$f" "$start" "$ln")
      if window "$f" "$(back "$ln" 2)" "$ln" | grep -q 'zeroize *( *skip *)'; then
        finding za-pwfield high "$f:$ln" "password field carries #[zeroize(skip)]: excluded from wiping inside a ZeroizeOnDrop struct"
      elif printf '%s' "$ctx" | grep -q 'ZeroizeOnDrop'; then
        ok za-pwfield "$f:$ln password String lives in a ZeroizeOnDrop struct"
      else
        finding za-pwfield low "$f:$ln" "password: String in a struct without ZeroizeOnDrop (unzeroized copy on drop)"
      fi
    done
  done

  # za-skip ------------------------------------------------------------------
  # #[zeroize(skip)] anywhere: fine on non-secret fields, a broken promise on
  # secret-named ones (the derive stays, the wiping silently stops).
  skips=$(rust_nontest | while read -r f; do
    scan_code "$f" 'zeroize *\( *skip *\)' | sed "s|^|$f:|"
  done)
  if [ -z "$skips" ]; then
    ok za-skip "no #[zeroize(skip)] attributes in non-test Rust code"
  else
    printf '%s\n' "$skips" | while IFS=: read -r f ln txt; do
      [ -n "$ln" ] || continue
      fieldline=$(window "$f" $((ln+1)) $((ln+2)) | grep -Ev '^[[:space:]]*(#|//)' | head -n1 | sed 's/^ *//')
      if printf '%s' "$fieldline" | grep -Eqi 'password|passwd|secret|plaintext|key'; then
        finding za-skip high "$f:$ln" "#[zeroize(skip)] on a secret-named field: $fieldline"
      else
        ok za-skip "$f:$ln #[zeroize(skip)] on a non-secret field: $fieldline"
      fi
    done
  fi

  # za-copy ------------------------------------------------------------------
  # expose_secret() copied into a plain String. OK when the copy demonstrably
  # moves into a ZeroizeOnDrop container (EntryData) or is the API token
  # (not key material; stored cleartext by design, ADR 0007). Anything else
  # is an unmanaged secret copy.
  rust_nontest | while read -r f; do
    scan_code "$f" 'expose_secret\(\)\.(to_string|to_owned|clone)\(' | while IFS=: read -r ln txt; do
      [ -n "$ln" ] || continue
      after=$(window "$f" "$ln" $((ln+14)))
      before=$(window "$f" $((ln > 6 ? ln - 6 : 1)) "$ln")
      if printf '%s' "$after" | grep -q 'EntryData'; then
        ok za-copy "$f:$ln secret copy moves into ZeroizeOnDrop EntryData"
      elif printf '%s' "$before" | grep -Eqi 'token'; then
        ok za-copy "$f:$ln copies the API token (not key material; cleartext by design per ADR 0007)"
      else
        finding za-copy medium "$f:$ln" "expose_secret() copied into an unmanaged String: $(printf '%s' "$txt" | sed 's/^ *//')"
      fi
    done
  done

  # za-rawfield --------------------------------------------------------------
  # key/secret-named fields with raw byte types. Non-secret by construction:
  # key_check_* (ciphertext+nonce of the key check), token_hash (a hash).
  rust_nontest | while read -r f; do
    scan_code "$f" '^ *(pub )?[a-z_]*(key|secret|plaintext|token)[a-z_]*: *(Vec<u8>|\[u8|String)' | while IFS=: read -r ln txt; do
      [ -n "$ln" ] || continue
      name=$(printf '%s' "$txt" | sed -E 's/^ *(pub )?([a-z_]+):.*/\2/')
      case "$name" in
        key_check_nonce|key_check_ct) ok za-rawfield "$f:$ln $name is ciphertext/nonce of the key check (non-secret by design)" ;;
        token_hash) ok za-rawfield "$f:$ln token_hash stores a SHA-256 hash, never the token" ;;
        token) ok za-rawfield "$f:$ln API token; not key material, cleartext custody by design (ADR 0007)" ;;
        *) finding za-rawfield medium "$f:$ln" "raw byte/String field with a secret-suggesting name: $name" ;;
      esac
    done
  done

  # za-keybuf ----------------------------------------------------------------
  # The raw key buffer inside derive_key: zeroized on the error path and
  # moved into VaultKey on success. Its own check-id: a hit here is a broken
  # zeroize path in key derivation, not a mis-named struct field.
  ln=$(first_line "$CRYPTO_RS" 'let mut key = Box::new\(\[0u8; KEY_LEN\]\)')
  if [ -n "$ln" ]; then
    ctx=$(window "$CRYPTO_RS" "$ln" $((ln+7)))
    if printf '%s' "$ctx" | grep -q 'zeroize' && printf '%s' "$ctx" | grep -q 'VaultKey::from_bytes'; then
      ok za-keybuf "derive_key's raw buffer is zeroized on error and moved into VaultKey on success ($CRYPTO_RS:$ln)"
    else
      finding za-keybuf high "$CRYPTO_RS:$ln" "derive_key's raw key buffer custody changed; verify zeroize on every path"
    fi
  else
    finding za-keybuf medium "$CRYPTO_RS:0" "derive_key's raw key buffer anchor not found; the custody check lost its target"
  fi
}

run_and_summarize main
