#!/usr/bin/env bash
# Regenerates every committed output in examples/ by running nft-assert for real (needs root and nftables).
# With --check nothing is written: the outputs are produced again and compared with the committed ones.
set -euo pipefail
cd "$(dirname "$0")"

mode="write"
[ "${1:-}" = "--check" ] && mode="check"
nfta=(python3 -m nft_assert)
bad=0

# gen OUTPUT EXPECTED_EXIT_CODE ARGS...: run nft-assert with ARGS and keep what it prints in OUTPUT
gen() {
  local out=$1 want=$2 got=0 tmp
  shift 2
  tmp=$(mktemp)
  "${nfta[@]}" "$@" >"$tmp" || got=$?
  if [ "$got" != "$want" ]; then
    echo "nft-assert $* exited $got, expected $want" >&2
    cat "$tmp" >&2
    exit 1
  fi
  if [ "$mode" = write ]; then
    mv "$tmp" "$out"
    echo "wrote examples/$out"
  else
    if diff -u "$out" "$tmp"; then echo "ok  examples/$out"; else bad=1; echo "OUT OF DATE: examples/$out" >&2; fi
    rm -f "$tmp"
  fi
}

gen edge/check.txt 0 check edge/spec.toml
gen edge/check-broken.txt 1 check edge/spec.toml --ruleset edge/firewall-broken.nft
gen edge/matrix.md 0 matrix edge/spec.toml
gen edge/diff.txt 1 diff edge/spec.toml edge/firewall.nft edge/firewall-broken.nft
gen hardening/check.txt 0 check hardening/spec.toml
gen hardening/matrix.md 0 matrix hardening/spec.toml
gen hardening/diff.txt 1 diff hardening/spec.toml hardening/host.nft hardening/host-with-mysql.nft

exit "$bad"
