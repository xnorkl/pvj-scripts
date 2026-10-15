#!/usr/bin/env bash
# Append a public key to a user's primary authorized_keys file (from sshd's effective config).
# Run this BEFORE revoke/reset so the team keeps key access.
# Usage: sudo ./add-ssh-authorized-key.sh <user> <team-key.pub>
set -euo pipefail
[[ $EUID -eq 0 && $# -eq 2 ]] || { echo "usage (root): $0 <user> <pubkey-file>" >&2; exit 1; }
user=$1 pub=$2
ssh-keygen -lf "$pub" >/dev/null   # refuse anything that is not a valid public key

home=$(getent passwd "$user" | cut -d: -f6)
[[ -n $home ]] || { echo "no such user: $user" >&2; exit 1; }
f=$(sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" | awk '$1=="authorizedkeysfile"{print $2}')
f=${f//%h/$home}; f=${f//%u/$user}; f=${f//%%/%}
[[ $f == /* ]] || f="$home/$f"

install -d -m 700 -o "$user" -g "$(id -gn "$user")" "$(dirname "$f")"
blob=$(awk '{print $2}' "$pub")
grep -qF "$blob" "$f" 2>/dev/null && { echo "no change: already present in $f"; exit 0; }
cat "$pub" >> "$f"
chown "$user:" "$f"; chmod 600 "$f"
echo "added $(ssh-keygen -lf "$pub" | awk '{print $2}') to $f"
