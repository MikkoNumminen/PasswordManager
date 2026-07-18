#!/usr/bin/env bash
# claims-vs-code: compare security values asserted in README.md and docs/adr/
# against the constants actually in the sources. One line per value, carrying
# every located source so mismatches are visible in place.
#   cv-kdf-mem / cv-kdf-passes / cv-kdf-lanes   Argon2id parameters
#   cv-aead                                     AEAD name
#   cv-nonce                                    nonce length
#   cv-wbg                                      wasm-bindgen version pin
#   cv-bind                                     default bind address and port
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../../_shared/lib.sh"

CRYPTO_RS=core/src/crypto.rs
SERVER_MAIN=server/src/main.rs
ADR_KDF=docs/adr/0001-kdf-argon2id-params.md
ADR_AEAD=docs/adr/0002-aead-xchacha20poly1305.md
ADR_NONCE=docs/adr/0003-nonce-strategy.md
CI=.github/workflows/ci.yml

# compare ID "claim-label=value ..." — all non-empty values equal -> OK,
# any disagreement -> FINDING high, any empty value -> FINDING medium.
compare() {
  id=$1; shift
  vals=""; missing=""; label_str="$*"
  for pair in "$@"; do
    v=${pair#*=}
    if [ -z "$v" ]; then missing="$missing ${pair%%=*}"; else vals="$vals $v"; fi
  done
  if [ -n "$missing" ]; then
    finding "$id" medium "README.md:0" "no locatable counterpart for:$missing ($label_str)"
    return
  fi
  distinct=$(printf '%s\n' $vals | sort -u | grep -c .)
  if [ "$distinct" -eq 1 ]; then
    ok "$id" "$label_str"
  else
    finding "$id" high "README.md:0" "values disagree: $label_str"
  fi
}

main() {
  # Argon2id parameters. README states MiB; ADR 0001 and the code state KiB.
  kdf_line=$(scan README.md 'Argon2id \([0-9]+ MiB' | head -n1 | sed 's/^[0-9]*://')
  readme_mib=$(printf '%s' "$kdf_line" | sed -En 's/.*Argon2id \(([0-9]+) MiB.*/\1/p')
  readme_passes=$(printf '%s' "$kdf_line" | sed -En 's/.*, ([0-9]+) passes.*/\1/p')
  readme_lanes=$(printf '%s' "$kdf_line" | sed -En 's/.*, ([0-9]+) lane.*/\1/p')
  adr_kib=$(scan_o "$ADR_KDF" 'm_cost [0-9]+ KiB' | head -n1 | sed -E 's/.*m_cost ([0-9]+) KiB/\1/')
  adr_passes=$(scan_o "$ADR_KDF" 't_cost [0-9]+' | head -n1 | sed -E 's/.*t_cost ([0-9]+)/\1/')
  adr_lanes=$(scan_o "$ADR_KDF" 'p_cost [0-9]+' | head -n1 | sed -E 's/.*p_cost ([0-9]+)/\1/')
  code_mem_expr=$(scan_code "$CRYPTO_RS" 'm_cost_kib: *[0-9]' | head -n1 | sed -E 's/.*m_cost_kib: *([0-9 *]+),?.*/\1/')
  code_kib=""
  case "$code_mem_expr" in
    *[!0-9\ \*]*|"") : ;;                         # unexpected shape: leave empty
    *) code_kib=$(( code_mem_expr )) ;;
  esac
  code_passes=$(scan_code "$CRYPTO_RS" 't_cost: *[0-9]' | head -n1 | sed -E 's/.*t_cost: *([0-9]+).*/\1/')
  code_lanes=$(scan_code "$CRYPTO_RS" 'p_cost: *[0-9]' | head -n1 | sed -E 's/.*p_cost: *([0-9]+).*/\1/')
  readme_kib=""; [ -n "$readme_mib" ] && readme_kib=$(( readme_mib * 1024 ))
  compare cv-kdf-mem    "readme_kib=$readme_kib" "adr0001_kib=$adr_kib" "crypto_rs_kib=$code_kib"
  compare cv-kdf-passes "readme=$readme_passes" "adr0001=$adr_passes" "crypto_rs=$code_passes"
  compare cv-kdf-lanes  "readme=$readme_lanes" "adr0001=$adr_lanes" "crypto_rs=$code_lanes"

  # AEAD name: presence of the exact algorithm in all three places.
  r=$(first_line README.md 'XChaCha20-Poly1305')
  a=$(first_line "$ADR_AEAD" 'XChaCha20-Poly1305')
  c=$(first_line "$CRYPTO_RS" 'XChaCha20Poly1305')
  if [ -n "$r" ] && [ -n "$a" ] && [ -n "$c" ]; then
    ok cv-aead "XChaCha20-Poly1305 named in README.md:$r, ADR 0002:$a, and used in $CRYPTO_RS:$c"
  else
    finding cv-aead high "README.md:${r:-0}" "AEAD name not present everywhere (readme=${r:-none} adr=${a:-none} code=${c:-none})"
  fi

  # Nonce length.
  readme_nonce=$(scan_o README.md '[0-9]+ byte nonce' | head -n1 | sed -E 's/.*:([0-9]+) byte nonce/\1/')
  adr_nonce=$(scan_o "$ADR_NONCE" '[0-9]+ byte nonce' | head -n1 | sed -E 's/.*:([0-9]+) byte nonce/\1/')
  code_nonce=$(scan_code "$CRYPTO_RS" 'NONCE_LEN: usize = [0-9]+' | head -n1 | sed -E 's/.*NONCE_LEN: usize = ([0-9]+).*/\1/')
  compare cv-nonce "readme=$readme_nonce" "adr0003=$adr_nonce" "NONCE_LEN=$code_nonce"

  # wasm-bindgen version: README install command, web/Cargo.toml pin,
  # Cargo.lock resolution. CI only cargo-builds the wasm crate (no
  # wasm-bindgen-cli invocation), so there is no fourth pin to drift.
  readme_wbg=$(scan_o README.md 'wasm-bindgen-cli --version [0-9.]+' | head -n1 | sed -E 's/.*--version ([0-9.]+)/\1/')
  toml_wbg=$(scan_o web/Cargo.toml 'wasm-bindgen = "=[0-9.]+"' | head -n1 | sed -E 's/.*"=([0-9.]+)"/\1/')
  lock_wbg=$(awk '/^name = "wasm-bindgen"$/{getline; if ($0 ~ /^version/) {gsub(/[^0-9.]/,""); print; exit}}' Cargo.lock | tr -d '\r')
  compare cv-wbg "readme=$readme_wbg" "web_cargo_toml=$toml_wbg" "cargo_lock=$lock_wbg"
  ci_wbg=$(scan "$CI" 'wasm-bindgen')
  if [ -z "$ci_wbg" ]; then
    ok cv-wbg "ci.yml never invokes wasm-bindgen-cli (no CI-side pin to drift)"
  else
    finding cv-wbg medium ".github/workflows/ci.yml:$(printf '%s' "$ci_wbg" | head -n1 | cut -d: -f1)" "CI now references wasm-bindgen; verify its version matches the =$toml_wbg pin"
  fi

  # Default bind address and port: README claim, clap default, and the
  # oauth2-proxy upstream that must point at the same place.
  readme_bind=$(scan_o README.md 'default bind is [0-9.]+:[0-9]+' | head -n1 | sed -E 's/.*default bind is ([0-9.:]+)/\1/')
  code_bind=$(scan_o "$SERVER_MAIN" 'default_value = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+"' | head -n1 | sed -E 's/.*"([0-9.:]+)"/\1/')
  compare cv-bind "readme=$readme_bind" "server_main_default=$code_bind"
  readme_port=${readme_bind##*:}
  gate_port=$(scan_o ops/oauth2-proxy.cfg 'upstreams = \["http://127\.0\.0\.1:[0-9]+/' | head -n1 | sed -E 's/.*:([0-9]+)\/?/\1/')
  compare cv-bind "readme_port=$readme_port" "oauth2_proxy_upstream_port=$gate_port"
}

run_and_summarize main
