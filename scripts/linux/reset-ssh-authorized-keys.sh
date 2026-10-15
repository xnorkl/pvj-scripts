#!/usr/bin/env bash
# Rewrite every discovered authorized keys file down to an allowlist (default: empty).
# Originals are copied to /root/ssh-quarantine-<ts>/ as evidence.
# Input: get-ssh-authorized-keys.sh TSV on stdin.
# Usage: sudo ./get-ssh-authorized-keys.sh | sudo ./reset-ssh-authorized-keys.sh [approved.pub]
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
approved=${1:-/dev/null}
quarantine=/root/ssh-quarantine-$(date +%Y%m%d-%H%M%S)
blobs=$(awk 'NF{print $2}' "$approved")

IFS= read -r header || true
[[ $header == user$'\t'file* ]] || { echo "stdin is not get-ssh-authorized-keys.sh output" >&2; exit 1; }
out=$(cut -f2 | sort -u | while IFS= read -r f; do
  [[ -f $f ]] || continue
  keep=$( [[ -n $blobs ]] && grep -F "$blobs" "$f" || true )
  [[ $(grep -c . "$f") -eq $(grep -c . <<<"$keep") ]] && continue   # already only approved keys
  install -d -m 700 "$quarantine$(dirname "$f")"
  cp -p "$f" "$quarantine$f"
  if [[ -n $keep ]]; then printf '%s\n' "$keep" > "$f"; else : > "$f"; fi
  echo "reset $f ($(wc -l < "$quarantine$f") -> $(wc -l < "$f") lines)"
done)
if [[ -n $out ]]; then echo "$out"; echo "originals saved under $quarantine"; else echo "no change: only approved keys present"; fi
