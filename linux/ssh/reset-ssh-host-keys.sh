#!/usr/bin/env bash
# Usage: sudo ./reset-ssh-host-keys.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
backup=/root/ssh-hostkeys-$(date +%Y%m%d-%H%M%S)
mkdir -m 700 "$backup"

mapfile -t keys < <(sshd -T | awk '$1=="hostkey"{print $2}')
for k in "${keys[@]}"; do
  [[ -f $k ]] || continue
  type=$(ssh-keygen -lf "$k" | awk '{gsub(/[()]/,"",$NF); print tolower($NF)}')
  cp -p "$k" "$k.pub" "$backup/" 2>/dev/null || true
  rm -f "$k" "$k.pub"
  ssh-keygen -q -t "$type" -N '' -f "$k" || echo "WARN: could not regenerate $type key $k" >&2
done

if ! sshd -t; then
  echo "sshd -t failed, restoring old host keys" >&2
  for k in "${keys[@]}"; do cp -p "$backup/$(basename "$k")"* "$(dirname "$k")/"; done
  exit 1
fi
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload
for k in "${keys[@]}"; do [[ -f $k.pub ]] && ssh-keygen -lf "$k.pub"; done
echo "old keys saved under $backup"
