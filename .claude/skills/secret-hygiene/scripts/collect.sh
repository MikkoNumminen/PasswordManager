#!/usr/bin/env bash
# secret-hygiene: committed secrets, gitignore coverage, and the realistic
# leak path — logging.
#   sh-tracked   secret-shaped files tracked in the working tree
#   sh-names     files named token/secret/credential
#   sh-ignore    .gitignore covers env files, key material, cloudflared creds
#   sh-literals  long base64/hex literals outside test vectors
#   sh-log       print/log/panic macros whose arguments touch secret words
#   sh-history   secret-shaped file names anywhere in git history
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../../_shared/lib.sh"

SECRET_FILE_RE='(^|/)\.env(\..*)?$|\.(pem|key|p12|db|db-wal|db-shm|db-journal|sqlite|sqlite3)$|credentials.*\.json$|tunnel-token|api-token'
SECRET_WORD='password|passwd|secret|token|plaintext|master|vault_key|key_bytes'

main() {
  # sh-tracked ---------------------------------------------------------------
  bad=$(tracked "$SECRET_FILE_RE")
  if [ -z "$bad" ]; then
    ok sh-tracked "no env/key/db/credential-shaped files tracked"
  else
    printf '%s\n' "$bad" | while read -r f; do
      [ -n "$f" ] && finding sh-tracked high "$f:0" "secret-shaped file is tracked in git"
    done
  fi

  # sh-names -----------------------------------------------------------------
  # Source modules named after secrets are code that MANAGES secrets, not
  # secrets (their contents are covered by sh-literals); anything else with
  # such a name is treated as committed secret material.
  tracked | while read -r f; do
    base=$(basename "$f")
    printf '%s' "$base" | grep -Eqi 'token|secret|credential' || continue
    case "$base" in
      *.rs|*.js|*.mjs|*.ts|*.md)
        ok sh-names "$f is a source/doc module (contents covered by sh-literals)" ;;
      *)
        finding sh-names high "$f:0" "non-source file named after a secret" ;;
    esac
  done

  # sh-ignore ----------------------------------------------------------------
  gi=.gitignore
  if [ ! -f "$gi" ]; then
    finding sh-ignore high ".gitignore:0" "no .gitignore at the workspace root"
  else
    for pat in '.env' '.env.*' '*.pem' '*.key' '*.p12' '.cloudflared/' '*tunnel-token*' 'credentials*.json' '*.db'; do
      if grep -Fqx "$pat" "$gi"; then
        ok sh-ignore "covers $pat"
      else
        finding sh-ignore medium ".gitignore:0" "missing pattern: $pat"
      fi
    done
  fi

  # sh-literals --------------------------------------------------------------
  # Long base64/hex runs are secret-shaped. Known-answer vectors are expected:
  # matches inside dedicated test files or a file's #[cfg(test)] module are OK.
  # Cargo.lock is excluded: its 64-char hex strings are dependency checksums.
  lit_re='[A-Za-z0-9+/]{50,}={0,2}|[0-9a-fA-F]{48,}'
  tracked | grep -Ev '^Cargo\.lock$|package-lock\.json$|\.(png|ico|gif|jpg|woff2?)$' | while read -r f; do
    case "$f" in
      *test*|*/tests/*)
        n=$(scan_o "$f" "$lit_re" | grep -c .)
        [ "$n" -gt 0 ] && ok sh-literals "$f holds $n long literal(s) in a test file (expected vectors/fixtures)"
        continue ;;
    esac
    if [ "${f##*.}" = rs ]; then hits=$(scan_code "$f" "$lit_re"); else hits=$(scan "$f" "$lit_re"); fi
    tn=0
    if [ "${f##*.}" = rs ]; then tn=$(scan "$f" "$lit_re" | grep -c .); fi
    printf '%s\n' "$hits" | while IFS=: read -r ln txt; do
      [ -n "$ln" ] || continue
      match=$(printf '%s' "$txt" | grep -Eo "$lit_re" | head -n1)
      snippet=$(printf '%s' "$match" | cut -c1-24)
      # A long sequential alphabet run means an alphabet constant (e.g. the
      # password-generator charset), not secret entropy.
      if printf '%s' "$match" | grep -Eq 'ABCDEFGHIJ|abcdefghij|0123456789'; then
        ok sh-literals "$f:$ln sequential alphabet constant (charset, not secret entropy): ${snippet}..."
      else
        finding sh-literals high "$f:$ln" "long base64/hex literal outside a test context: ${snippet}..."
      fi
    done
    # Report vectors living in an inline #[cfg(test)] module as OK.
    live=$(printf '%s\n' "$hits" | grep -c .)
    if [ "${f##*.}" = rs ] && [ "$tn" -gt "$live" ]; then
      ok sh-literals "$f holds $((tn - live)) long literal(s) inside #[cfg(test)] (known-answer vectors)"
    fi
  done

  # sh-log -------------------------------------------------------------------
  # Every print/log/panic macro that mentions a secret word. A macro line is a
  # FINDING only when a secret-named value is actually interpolated or passed
  # as an argument; static prompt/help text is listed OK. Two deliberate
  # printouts are allowlisted by exact content and named here so any edit to
  # them re-flags.
  macro_re='(println|eprintln|print|eprint|dbg|panic|unreachable|todo|writeln|write|(tracing::)?(trace|debug|info|warn|error))! *\('
  rust_nontest | while read -r f; do
    scan_code "$f" "$macro_re" | while IFS=: read -r ln txt; do
      [ -n "$ln" ] || continue
      printf '%s' "$txt" | grep -Eqi "$SECRET_WORD" || continue
      line=$(printf '%s' "$txt" | sed 's/^ *//')
      # Allowlist: the CLI --reveal path and the server token subcommand
      # print a secret at the user's explicit request, once, by design.
      case "$f:$line" in
        'cli/src/main.rs:println!("Password: {}", data.password);')
          ok sh-log "$f:$ln --reveal path prints the password at explicit user request (by design)"; continue ;;
        'server/src/main.rs:println!("{token}");')
          ok sh-log "$f:$ln token subcommand prints the new API token once (by design; only its hash is stored)"; continue ;;
      esac
      # Interpolated identifiers plus arguments after the format string.
      idents=$(printf '%s' "$line" | grep -Eo '\{[A-Za-z_][A-Za-z0-9_.]*\}' | tr -d '{}')
      args=$(printf '%s' "$line" | sed -E 's/^[a-z_:]+! *\( *"(\\.|[^"])*"//')
      if printf '%s %s' "$idents" "$args" | grep -Eqi "$SECRET_WORD"; then
        finding sh-log high "$f:$ln" "log/panic output interpolates a secret-named value: $line"
      else
        ok sh-log "$f:$ln mentions a secret word in static text only: $line"
      fi
    done
  done

  # sh-history ---------------------------------------------------------------
  hist=$(git log --all --pretty=format: --name-only --diff-filter=A 2>/dev/null \
    | tr -d '\r' | grep -E "$SECRET_FILE_RE" | sort -u)
  if [ -z "$hist" ]; then
    ok sh-history "no secret-shaped file was ever added in any commit on any branch"
  else
    printf '%s\n' "$hist" | while read -r f; do
      [ -n "$f" ] && finding sh-history high "$f:0" "secret-shaped file exists in git history (deleting it later does not remove it)"
    done
  fi
}

run_and_summarize main
