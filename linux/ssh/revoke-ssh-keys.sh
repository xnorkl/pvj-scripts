#!/usr/bin/env bash
# Usage: sudo ./get-ssh-authorized-keys.sh | sudo ./revoke-ssh-keys.sh [approved.pub]
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
approved=${1:-/dev/null}
cfg=/etc/ssh/sshd_config
ts=$(date +%Y%m%d-%H%M%S)

spec=$(mktemp)
trap 'rm -f "$spec"' EXIT
IFS= read -r header || true
[[ $header == user$'\t'file* ]] || { echo "stdin is not get-ssh-authorized-keys.sh output" >&2; exit 1; }
cut -f7 | sort -u | grep -vFf <(awk '{print $2}' "$approved") | sed 's/^/key: /' > "$spec" || true
[[ -s $spec ]] || { echo "no change: nothing to revoke"; exit 0; }

krl=$(sshd -T | awk '$1=="revokedkeys"{print $2}')
if [[ $krl == none ]]; then
  krl=/etc/ssh/revoked_keys
  cp -p "$cfg" "$cfg.bak-$ts"
  sed -i "1i RevokedKeys $krl" "$cfg"   # top of file: must precede any Match block
fi

if [[ -f $krl ]]; then ssh-keygen -k -u -f "$krl" "$spec"; else ssh-keygen -k -f "$krl" "$spec"; fi
chmod 644 "$krl"

if ! sshd -t; then
  echo "sshd -t failed, restoring $cfg" >&2
  [[ -f $cfg.bak-$ts ]] && cp -p "$cfg.bak-$ts" "$cfg"
  exit 1
fi
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service ssh reload
echo "revoked $(wc -l < "$spec") key(s) into $krl"
