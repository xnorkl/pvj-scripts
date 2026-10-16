#!/usr/bin/env bash
# Usage: sudo ./get-privesc-findings.sh   # TSV: status check object detail; exit 2 = FAIL found
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

# GTFOBins binaries that give a shell / file read / privesc when SUID or in a sudo rule
gtfo='^(bash|sh|dash|zsh|ksh|csh|tcsh|env|find|vim|vi|nano|view|less|more|man|awk|gawk|mawk|nmap|perl|python[0-9.]*|ruby|lua[0-9.]*|php|node|tar|zip|cp|dd|nc|ncat|socat|ed|ex|sed|tclsh|expect|git|make|gdb|strace|ltrace|busybox|flock|ionice|nice|nohup|setarch|stdbuf|time|timeout|watch|xargs|rsync|scp|ftp|tee|wget|curl|openssl|base64|xxd|cpulimit|taskset|capsh|systemctl|start-stop-daemon|run-parts|crontab|mount|docker|lxc)$'

fail=0
report() { printf '%s\t%s\t%s\t%s\n' "$@"; if [[ $1 == FAIL ]]; then fail=1; fi; }

pkgfiles=$(mktemp)
trap 'rm -f "$pkgfiles"' EXIT
{ cat /var/lib/dpkg/info/*.list 2>/dev/null || true; rpm -qal 2>/dev/null || true; } | sort -u > "$pkgfiles"
[[ -s $pkgfiles ]] || echo "WARN: no dpkg/rpm file list, every SUID is WARN" >&2
owned() { grep -qxF -e "$1" -e "/usr$1" -e "${1#/usr}" "$pkgfiles"; }   # merged-/usr aware

# Distro-standard SUID binaries: expected, not a finding
base_suid='^(mount|umount|su|sudo|passwd|chsh|chfn|gpasswd|newgrp|pkexec|fusermount|fusermount3|ping|ping6|crontab|at|ssh-keysign|dbus-daemon-launch-helper|unix_chkpwd|chrome-sandbox|snap-confine|polkit-agent-helper-1|write|wall|expiry|chage|mount.nfs|ntfs-3g)$'

# SUID/SGID: known baseline -> skip; GTFOBins shell binary -> FAIL (e.g. bash/find/python); else not from a package -> WARN
while IFS= read -r f; do
  base=${f##*/}
  if [[ $base =~ $base_suid ]]; then
    continue
  elif [[ $base =~ $gtfo ]]; then
    report FAIL suid "$f" "GTFOBins shell/read binary is setuid"
  elif ! owned "$f"; then
    report WARN suid "$f" "setuid binary not from a package"
  fi
done < <(find / -xdev -type f -perm /6000 2>/dev/null || true)

# File capabilities: setuid/setgid/dac are shell-equivalent
while IFS= read -r line; do
  [[ -z $line ]] && continue
  cap=${line#* }
  if [[ $cap == *cap_setuid* || $cap == *cap_setgid* || $cap == *cap_dac_* || $cap == *cap_sys_admin* ]]; then
    report FAIL cap "${line%% *}" "$cap"
  else
    report WARN cap "${line%% *}" "$cap"
  fi
done < <(getcap -r / 2>/dev/null || true)

# sudoers: passwordless or shell-capable binaries
while IFS= read -r src; do
  while IFS= read -r line; do
    case $line in
      *NOPASSWD*)        report FAIL sudoers "$src" "NOPASSWD: ${line:0:160}" ;;
      *\!authenticate*)  report FAIL sudoers "$src" "!authenticate: ${line:0:160}" ;;
      *ALL\ =\ *ALL*|*ALL=*ALL*) report WARN sudoers "$src" "${line:0:160}" ;;
    esac
    for word in $line; do
      b=${word##*/}
      [[ $word == /* && $b =~ $gtfo ]] && report FAIL sudoers "$src" "GTFOBins binary $word in sudo rule"
    done
  done < <(grep -IvE '^[[:space:]]*(#|$|Defaults|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias)' "$src" 2>/dev/null || true)
done < <(find /etc/sudoers /etc/sudoers.d -type f 2>/dev/null || true)

# World-writable files sitting in a PATH dir (hijackable)
IFS=: read -ra pdirs <<<"${PATH}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
while IFS= read -r f; do
  [[ -n $f ]] && report FAIL path-writable "$f" "world-writable file in a PATH directory"
done < <(find "${pdirs[@]}" -maxdepth 1 -xdev -type f -perm -0002 2>/dev/null | sort -u || true)

exit $(( fail ? 2 : 0 ))
