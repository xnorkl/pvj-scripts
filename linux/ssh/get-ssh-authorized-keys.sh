#!/usr/bin/env bash
# Usage: sudo ./get-ssh-authorized-keys.sh > keys.tsv
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

key_re='(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-[a-z0-9-]+@openssh\.com|[a-z0-9-]+-cert-v01@openssh\.com) AAAA[A-Za-z0-9+/=]+'

sshd -T | awk '
  $1 ~ /^(authorizedkeyscommand|authorizedprincipalsfile|authorizedprincipalscommand|trustedusercakeys)$/ && $2 != "none" {
    print "WARN: alternate key trust path: " $0 > "/dev/stderr" }'

printf 'user\tfile\ttype\tfingerprint\tcomment\toptions\tkey\n'
getent passwd | while IFS=: read -r user _ _ _ _ home _; do
  # ponytail: Match on host/addr is evaluated as localhost only
  files=$(sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null | awk '$1=="authorizedkeysfile"{$1="";print}')
  for f in $files; do
    f=${f//%h/$home}; f=${f//%u/$user}; f=${f//%%/%}
    [[ $f == /* ]] || f="$home/$f"
    [[ -f $f ]] || continue
    while IFS= read -r line || [[ -n $line ]]; do
      [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
      if [[ $line =~ $key_re ]]; then
        key=${BASH_REMATCH[0]}
        opts=${line%%"$key"*}; opts=${opts%"${opts##*[![:space:]]}"}
        comment=${line#*"$key"}; comment=${comment#"${comment%%[![:space:]]*}"}
        fp=$(ssh-keygen -lf /dev/stdin <<<"$key" | awk '{print $2}')
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$user" "$f" "${key%% *}" "$fp" "$comment" "$opts" "$key"
      else
        echo "WARN: unparsed line in $f: $line" >&2
      fi
    done < "$f"
  done
done
