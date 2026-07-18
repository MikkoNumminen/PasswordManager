#!/usr/bin/env bash
# sync-invariants: the seal/open AAD binding, conflict preservation, and
# verify-before-store on the pull path. Where a rule cannot be decided
# mechanically the collector emits REVIEW with the exact line range; the
# model reads only those ranges.
#   si-aad      AAD construction includes entry UUID and modified timestamp
#   si-aead     every AEAD call site lives in core::vault with a bound AAD
#   si-callers  seal/open call sites route through Vault (binding is internal)
#   si-conflict the losing conflict version is persisted on both sides
#   si-pull     records are verified under the vault key before local storage
#   si-server   the server push path delegates to core's LWW rule
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../../_shared/lib.sh"

V=core/src/vault.rs
S=core/src/sync.rs
A=server/src/app.rs

main() {
  # si-aad -------------------------------------------------------------------
  a=$(first_line "$V" 'fn aad_with_prefix')
  if [ -z "$a" ]; then
    review si-aad "$V:1-999" "aad_with_prefix not found; locate the AAD construction and confirm it binds uuid+modified_ms"
  else
    body=$(window "$V" "$a" $((a+8)))
    if printf '%s' "$body" | grep -q 'id\.as_bytes()' && printf '%s' "$body" | grep -q 'modified_ms\.to_be_bytes()'; then
      ok si-aad "AAD = domain prefix + entry uuid + modified_ms (big endian) ($V:$a)"
    else
      review si-aad "$V:$a-$((a+8))" "aad_with_prefix body no longer matches uuid+modified_ms; read this range"
    fi
    for helper in entry_aad tombstone_aad; do
      h=$(first_line "$V" "fn $helper")
      if [ -n "$h" ] && window "$V" "$h" $((h+3)) | grep -q 'aad_with_prefix'; then
        ok si-aad "$helper delegates to aad_with_prefix under its own domain prefix ($V:$h)"
      else
        review si-aad "$V:${h:-1}-$((${h:-1}+3))" "$helper does not visibly delegate to aad_with_prefix; read this range"
      fi
    done
  fi

  # si-aead ------------------------------------------------------------------
  # Call sites of the core AEAD, with the AAD each one binds.
  sites=$(scan_code "$V" 'crypto::(encrypt|decrypt)\(')
  # An empty enumeration is not success: it means the anchor pattern lost
  # the call sites (e.g. a refactor to bare imported encrypt()/decrypt())
  # and the whole AAD-per-site audit would silently evaporate.
  if [ "$(printf '%s\n' "$sites" | grep -c .)" -eq 0 ]; then
    review si-aead "$V:1-999" "no crypto::encrypt/decrypt call sites found; the enumeration lost its anchor (import-style refactor?) - locate the AEAD calls and re-anchor this check"
  fi
  printf '%s\n' "$sites" | while IFS=: read -r ln txt; do
    [ -n "$ln" ] || continue
    if printf '%s' "$txt" | grep -q 'KEYCHECK_AAD'; then
      ok si-aead "$V:$ln keycheck blob under its own domain AAD"
    elif printf '%s' "$txt" | grep -q '&aad'; then
      pre=$(window "$V" $((ln > 4 ? ln - 4 : 1)) "$ln")
      if printf '%s' "$pre" | grep -Eq '(entry_aad|tombstone_aad)\('; then
        ok si-aead "$V:$ln entry/tombstone AAD bound (uuid+modified_ms via helper)"
      else
        review si-aead "$V:$(back "$ln" 6)-$ln" "AEAD call with an aad not visibly built by entry_aad/tombstone_aad; read this range"
      fi
    else
      review si-aead "$V:$(back "$ln" 4)-$ln" "AEAD call with an unrecognized aad argument; read this range"
    fi
  done
  outside=$(rust_nontest | grep -Ev '^core/src/(vault|crypto)\.rs$' | while read -r f; do
    scan_code "$f" 'crypto::(encrypt|decrypt)\(|XChaCha20Poly1305::new|chacha20poly1305::' | sed "s|^|$f:|"
  done)
  if [ -z "$outside" ]; then
    ok si-aead "no AEAD use outside core::vault / core::crypto"
  else
    printf '%s\n' "$outside" | while IFS=: read -r f ln txt; do
      [ -n "$ln" ] && finding si-aead high "$f:$ln" "AEAD driven outside core::vault; AAD binding not guaranteed"
    done
  fi

  # si-callers ---------------------------------------------------------------
  # seal_entry/open_entry take (id, modified_ms) and build the AAD internally,
  # so a caller cannot skip the binding. Report where the callers are.
  rust_nontest | grep -v '^core/src/vault.rs$' | while read -r f; do
    se=$(scan_code "$f" '\.seal_entry\(' | grep -c .)
    oe=$(scan_code "$f" '\.open_entry\(' | grep -c .)
    st=$(scan_code "$f" '\.seal_tombstone\(' | grep -c .)
    [ $((se + oe + st)) -eq 0 ] && continue
    ok si-callers "$f seal_entry=$se open_entry=$oe seal_tombstone=$st (AAD bound inside Vault, not caller-supplied)"
  done

  # si-conflict --------------------------------------------------------------
  p=$(first_line "$S" 'fn preserve_version')
  r=$(first_line "$S" 'fn resolve_conflict')
  if [ -z "$p" ] || [ -z "$r" ]; then
    review si-conflict "$S:1-999" "preserve_version/resolve_conflict not found; locate the conflict path and confirm losers are persisted"
  else
    pbody=$(window "$S" "$p" $((p+32)))
    if printf '%s' "$pbody" | grep -q 'upsert_entry(&copy_rec)' && printf '%s' "$pbody" | grep -q 'push(&copy_rec)'; then
      ok si-conflict "losing version re-sealed as a conflict copy and stored locally AND pushed remotely ($S:$p)"
    else
      review si-conflict "$S:$p-$((p+32))" "preserve_version no longer visibly stores the copy on both sides; read this range"
    fi
    rbody_end=$((p > r ? p : r+50))
    first_preserve=$(scan "$S" 'preserve_version\(' | awk -F: -v a="$r" -v b="$rbody_end" '($1+0)>a && ($1+0)<b {print $1; exit}')
    first_apply=$(scan "$S" 'apply_synced\(|remote\.push\(winner_rec\)' | awk -F: -v a="$r" -v b="$rbody_end" '($1+0)>a && ($1+0)<b {print $1; exit}')
    if [ -n "$first_preserve" ] && [ -n "$first_apply" ] && [ "$first_preserve" -lt "$first_apply" ]; then
      ok si-conflict "loser preserved (line $first_preserve) before the winner is applied (line $first_apply)"
    else
      review si-conflict "$S:$r-$rbody_end" "cannot confirm the loser is preserved before the winner overwrites it; read this range"
    fi
    if printf '%s' "$pbody" | grep -q 'if loser.deleted' ; then
      ok si-conflict "losing tombstones yield no copy (nothing to preserve), per ADR 0006"
    fi
  fi

  # si-pull ------------------------------------------------------------------
  # Rule: nothing reaches local storage unverified. Mechanical decision per
  # apply_synced site: (a) applies a record from the verify-filtered pull set
  # (variable rrec), or (b) has a verify_record guard within the previous 10
  # lines, or (c) applies resolve_conflict's remote arg, which must itself be
  # verified at every resolve_conflict call site.
  filt=$(scan "$S" 'filter\(.*verify_record' | head -n1 | cut -d: -f1)
  if [ -n "$filt" ]; then
    ok si-pull "full pull is filtered through vault.verify_record before reconciliation ($S:$filt)"
  else
    review si-pull "$S:110-145" "the pull-set verify filter is gone or moved; read this range"
  fi
  scan "$S" 'apply_synced\(' | while IFS=: read -r ln txt; do
    [ -n "$ln" ] || continue
    if printf '%s' "$txt" | grep -Eq 'apply_synced\(&?rrec\)'; then
      if [ -n "$filt" ]; then
        ok si-pull "$S:$ln applies a record from the verified pull set"
      else
        review si-pull "$S:$(back "$ln" 10)-$ln" "applies a pull record but the verify filter was not found"
      fi
    elif window "$S" "$(back "$ln" 10)" "$ln" | grep -q 'verify_record'; then
      ok si-pull "$S:$ln guarded by verify_record in the preceding lines"
    elif printf '%s' "$txt" | grep -q 'winner_rec'; then
      : # resolve_conflict's remote-side winner; covered by the caller check below.
    else
      review si-pull "$S:$(back "$ln" 10)-$ln" "apply_synced without a visible verify guard; read this range"
    fi
  done
  # Every resolve_conflict caller must hand it a verified remote record.
  calls=$(scan "$S" 'resolve_conflict\(vault')
  printf '%s\n' "$calls" | while IFS=: read -r ln txt; do
    [ -n "$ln" ] || continue
    if printf '%s' "$txt" | grep -Eq ', &?rrec,'; then
      : # from the verified pull set
    elif window "$S" "$(back "$ln" 4)" "$ln" | grep -q 'verify_record'; then
      : # explicitly verified just above
    else
      review si-pull "$S:$(back "$ln" 6)-$ln" "resolve_conflict called with a remote record not visibly verified; read this range"
    fi
  done
  ncalls=$(printf '%s\n' "$calls" | grep -c .)
  [ "$ncalls" -gt 0 ] && ok si-pull "resolve_conflict callers: $ncalls, each passing a pull-set or explicitly verified remote record (any exception above as REVIEW)"

  # si-server ----------------------------------------------------------------
  pe=$(first_line "$A" 'lww_push_decision\(')
  if [ -n "$pe" ]; then
    ok si-server "server push path delegates to core's lww_push_decision ($A:$pe); one LWW rule, no drift"
  else
    finding si-server high "$A:0" "server push no longer uses core's lww_push_decision; LWW can drift from the engine"
  fi
  cj=$(first_line "$A" 'StatusCode::CONFLICT, Json\(server_rec\)')
  if [ -n "$cj" ]; then
    ok si-server "push conflicts answer 409 with the winning server record ($A:$cj); losers surface, never vanish"
  else
    review si-server "$A:180-210" "the 409-with-winning-record shape changed; read this range"
  fi
}

run_and_summarize main
