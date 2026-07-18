#!/usr/bin/env bash
# secret-hygiene: committed secrets, gitignore coverage, and the realistic
# leak path — logging.
#   sh-tracked   secret-shaped files tracked in the working tree
#   sh-names     files named token/secret/credential
#   sh-ignore    .gitignore covers env files, key material, cloudflared creds
#   sh-literals  long base64/hex runs and well-known token shapes outside
#                test vectors
#   sh-log       print/log/panic macros whose arguments touch secret words
#   sh-history   secret-shaped file names anywhere in git history
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../../_shared/lib.sh"

SECRET_FILE_RE='(^|/)\.env(\..*)?$|\.(pem|key|p12|db|db-wal|db-shm|db-journal|sqlite|sqlite3)$|credentials.*\.json$|tunnel-token|api-token'
SECRET_WORD='password|passwd|secret|token|plaintext|master|vault_key|key_bytes'
# Dedicated test locations: a tests/ or test/ path segment, or *.test.* files.
# A path SEGMENT, not a substring — server/src/attest.rs would not qualify.
TEST_PATH_RE='(^|/)tests?(/|$)|\.test\.'

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
  # Read through tr -d '\r' like every other check: on a CRLF checkout the
  # patterns would otherwise all miss ('.env' vs '.env\r') and report nine
  # false mediums.
  gi=.gitignore
  if [ ! -f "$gi" ]; then
    finding sh-ignore high ".gitignore:0" "no .gitignore at the workspace root"
  else
    gi_body=$(tr -d '\r' < "$gi")
    for pat in '.env' '.env.*' '*.pem' '*.key' '*.p12' '.cloudflared/' '*tunnel-token*' 'credentials*.json' '*.db'; do
      if printf '%s\n' "$gi_body" | grep -Fqx "$pat"; then
        ok sh-ignore "covers $pat"
      else
        finding sh-ignore medium ".gitignore:0" "missing pattern: $pat"
      fi
    done
  fi

  # sh-literals --------------------------------------------------------------
  # Two nets: long base64/hex runs (secret-shaped entropy) and well-known
  # credential prefixes (GitHub/Slack/OpenAI/AWS tokens, JWTs) whose runs can
  # be shorter or use the base64url alphabet. Known-answer vectors are
  # expected: matches inside dedicated test paths or a file's #[cfg(test)]
  # module are OK. Cargo.lock is excluded: its hex strings are checksums.
  lit_re='[A-Za-z0-9+/]{50,}={0,2}|[0-9a-fA-F]{48,}|(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{30,}\.eyJ'
  tracked | grep -Ev '^Cargo\.lock$|package-lock\.json$|\.(png|ico|gif|jpg|woff2?)$' | while read -r f; do
    if printf '%s' "$f" | grep -Eq "$TEST_PATH_RE"; then
      n=$(scan_o "$f" "$lit_re" | grep -c .)
      [ "$n" -gt 0 ] && ok sh-literals "$f holds $n long literal(s) in a test file (expected vectors/fixtures)"
      continue
    fi
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
        finding sh-literals high "$f:$ln" "long/credential-shaped literal outside a test context: ${snippet}..."
      fi
    done
    # Report vectors living in an inline #[cfg(test)] module as OK.
    live=$(printf '%s\n' "$hits" | grep -c .)
    if [ "${f##*.}" = rs ] && [ "$tn" -gt "$live" ]; then
      ok sh-literals "$f holds $((tn - live)) long literal(s) inside #[cfg(test)] (known-answer vectors)"
    fi
  done

  # sh-log -------------------------------------------------------------------
  # Every print/log/panic macro that mentions a secret word. Classification
  # looks at the macro line JOINED with the next three lines (rustfmt wraps
  # long calls), and decides on what remains after removing every quoted
  # string: a secret word surviving outside quotes means a secret-named
  # value is interpolated or passed, wherever the macro sits on the line and
  # whatever its first argument is. Interpolated {idents} inside the format
  # string are extracted and tested separately. Static prompt/help text is
  # listed OK. Two deliberate printouts are allowlisted by exact content AND
  # nearby gating context, so a copy pasted elsewhere re-flags.
  macro_re='(println|eprintln|print|eprint|dbg|panic|unreachable|todo|writeln|write|(tracing::)?(trace|debug|info|warn|error))! *\('
  rust_nontest | while read -r f; do
    scan_code "$f" "$macro_re" | while IFS=: read -r ln txt; do
      [ -n "$ln" ] || continue
      # Join the macro call's own lines only: stop at the first line ending
      # the statement, so trailing unrelated code cannot leak into the test.
      joined=$(window "$f" "$ln" $((ln+3)) | awk '{print} /;[ \t]*$/{exit}' | tr -d '\n')
      printf '%s' "$joined" | grep -Eqi "$SECRET_WORD" || continue
      line=$(printf '%s' "$txt" | sed 's/^ *//')
      ctx=$(window "$f" "$(back "$ln" 3)" "$ln")
      # Allowlist: the CLI --reveal path and the server token subcommand
      # print a secret at the user's explicit request, once, by design. The
      # context requirement pins each to its gated location.
      case "$f:$line" in
        'cli/src/main.rs:println!("Password: {}", data.password);')
          if printf '%s' "$ctx" | grep -q 'reveal'; then
            ok sh-log "$f:$ln --reveal path prints the password at explicit user request (by design)"; continue
          fi ;;
        'server/src/main.rs:println!("{token}");')
          if printf '%s' "$ctx" | grep -q 'token'; then
            ok sh-log "$f:$ln token subcommand prints the new API token once (by design; only its hash is stored)"; continue
          fi ;;
      esac
      # The vaultctl rotate flow prints WHERE the token was written (a path
      # via token_file().display()), never the token itself; keyed on both
      # strings so changing the statement to print the value re-flags.
      if printf '%s' "$joined" | grep -qF 'API token rotated. Written to' \
        && printf '%s' "$joined" | grep -qF 'token_file().display()'; then
        ok sh-log "$f:$ln prints the token file PATH after rotation, not the token (by design)"
        continue
      fi
      # Interpolated identifiers inside strings, plus everything that is not
      # a string literal (arguments, writer, surrounding code). Module-path
      # segments like `secrets::` are namespaces, not values — stripped, so
      # `secrets::filled(...)` stays quiet while `secrets::read_token()` is
      # still caught by its function name.
      idents=$(printf '%s' "$joined" | grep -Eo '\{[A-Za-z_][A-Za-z0-9_.]*\}' | tr -d '{}')
      nostr=$(printf '%s' "$joined" | sed -E 's/"(\\.|[^"\\])*"//g; s/[A-Za-z_]*(secret|token|password|key)[A-Za-z_]*:://g')
      if printf '%s %s' "$idents" "$nostr" | grep -Eqi "$SECRET_WORD"; then
        finding sh-log high "$f:$ln" "log/panic output carries a secret-named value: $line"
      else
        ok sh-log "$f:$ln mentions a secret word in static text only: $line"
      fi
    done
  done

  # sh-history ---------------------------------------------------------------
  # Needs full history: on a shallow clone (CI's default fetch-depth 1) the
  # graft commit reports only the current tree, which would make "never
  # added" a false certificate. Degrade loudly instead.
  if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
    finding sh-history low ".git:0" "shallow clone: history not scannable; run with full history (CI: fetch-depth 0) for this check"
  else
    hist=$(git log --all --pretty=format: --name-only --diff-filter=A 2>/dev/null \
      | tr -d '\r' | grep -E "$SECRET_FILE_RE" | sort -u)
    if [ -z "$hist" ]; then
      ok sh-history "no secret-shaped file was ever added in any commit on any branch"
    else
      printf '%s\n' "$hist" | while read -r f; do
        [ -n "$f" ] && finding sh-history high "$f:0" "secret-shaped file exists in git history (deleting it later does not remove it)"
      done
    fi
  fi
}

run_and_summarize main
