#!/usr/bin/env bash
# Usage: sudo ./get-sshd-config-findings.sh   # TSV: status check object detail; exit 2 = FAIL found
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
cfg=$(sshd -T)
fail=0
report() { printf '%s\t%s\t%s\t%s\n' "$@"; [[ $1 == FAIL ]] && fail=1; return 0; }

# setting ; value must match (ERE) ; status if not ; why
while IFS=';' read -r key ok sev why; do
  [[ -z $key || $key == \#* ]] && continue
  while IFS= read -r val; do
    [[ $val =~ $ok ]] || report "$sev" "$key" "$val" "$why"
  done < <(awk -v k="$key" '$1==k{$1=""; sub(/^ +/,""); sub(/ +$/,""); print}' <<<"$cfg")
done <<'RULES'
# --- alternate ways to trust a key or run code at login (persistence) ---
authorizedkeyscommand;^none$;FAIL;keys come from a program
authorizedprincipalscommand;^none$;FAIL;principals come from a program
trustedusercakeys;^none$;FAIL;any cert this CA signs can log in
authorizedprincipalsfile;^none$;WARN;cert principals file in use
authorizedkeysfile;^\.ssh/authorized_keys$;WARN;non-default key files (authorized_keys2 is a legacy second location)
forcecommand;^none$;FAIL;command wraps every login
permituserenvironment;^no$;FAIL;~/.ssh/environment can set LD_PRELOAD
permituserrc;^no$;WARN;~/.ssh/rc runs on every login
subsystem;^sftp (internal-sftp|/[^ ]*/sftp-server)( |$);FAIL;unexpected subsystem binary
hostkey;^/etc/ssh/ssh_host_[a-z0-9]+_key$;WARN;host key outside /etc/ssh
revokedkeys;^/;WARN;no KRL, run revoke-ssh-keys.sh
# --- authentication ---
permitrootlogin;^(no|prohibit-password|without-password|forced-commands-only)$;FAIL;root can log in with a password
permitemptypasswords;^no$;FAIL;empty passwords allowed
hostbasedauthentication;^no$;FAIL;trust via .rhosts/.shosts
ignorerhosts;^yes$;FAIL;.rhosts honoured
strictmodes;^yes$;FAIL;sshd accepts world-writable key files
passwordauthentication;^no$;INFO;Scorebot may need passwords, so rotate them rather than disabling
# --- pivoting ---
allowtcpforwarding;^no$;WARN;port forwarding (pivot)
allowagentforwarding;^no$;WARN;agent hijack on this host
gatewayports;^no$;WARN;remote forwards bind on all interfaces
permittunnel;^no$;WARN;tun/tap tunnels
x11forwarding;^no$;WARN;X11 forwarding
# --- visibility ---
loglevel;^VERBOSE$;WARN;VERBOSE logs which key fingerprint logged in
syslogfacility;^AUTH(PRIV)?$;WARN;auth logs diverted
RULES

# Config files: sshd_config plus Include targets (relative paths are under /etc/ssh)
mapfile -t files < <(
  echo /etc/ssh/sshd_config
  # shellcheck disable=SC2013,SC2086  # word-split and glob on purpose
  for g in $(awk 'tolower($1)=="include"{$1=""; print}' /etc/ssh/sshd_config); do
    [[ $g == /* ]] || g=/etc/ssh/$g
    for f in $g; do [[ -f $f ]] && echo "$f"; done
  done
)
for f in "${files[@]}"; do
  read -r owner mode mtime < <(stat -c '%U %a %y' "$f")
  [[ $owner == root && $(( 8#$mode & 8#022 )) -eq 0 ]] || report FAIL file "$f ($owner $mode)" "config writable by non-root"
  report INFO file "$f" "modified ${mtime%%.*}"
  # sshd -T shows global values only, so Match blocks can override them unseen
  while IFS= read -r m; do
    report WARN match "$f:$m" "overrides above are invisible to sshd -T: review"
  done < <(grep -niE '^[[:space:]]*match[[:space:]]' "$f" || true)
done

# Login-time scripts
[[ -e /etc/ssh/sshrc ]] && report FAIL file /etc/ssh/sshrc "runs for every user on every login"
while IFS=: read -r _ _ _ _ _ home _; do
  for f in "$home/.ssh/rc" "$home/.ssh/environment"; do
    if [[ -e $f ]]; then report WARN file "$f" "runs or loads at login"; fi
  done
done < <(getent passwd)

exit $(( fail ? 2 : 0 ))
