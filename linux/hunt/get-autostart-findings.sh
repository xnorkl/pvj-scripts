#!/usr/bin/env bash
# Read-only hunt for Linux persistence: cron/at, systemd (units, drop-ins, timers, transient,
# generators, user units), init scripts, shell init files, ld.so.preload, udev, motd, xdg, apt hooks.
#   FAIL  file content looks malicious (reverse shell, /tmp exec, pipe-to-shell, alias sudo=, ...)
#   WARN  file is not owned by any package (dpkg/rpm) -> someone added it: review
#   INFO  every active cron/at entry, so Red's quiet one-liners still show up
# Output TSV (no header): status  check  object  detail
# Exit: 0 clean, 1 error, 2 at least one FAIL  (Ansible: failed_when: rc == 1)
# Usage: sudo ./get-autostart-findings.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

sus='(/dev/shm/|/tmp/|/var/tmp/|/dev/(tcp|udp)/|\b(ba|z|da)?sh -i\b|\bnc(at)?\b.* -[ec]\b|\bsocat\b|mkfifo|base64 +(-d|--decode)|\| *(ba|z|da)?sh\b|python[0-9.]* -c|perl -e|php -r|ruby -e|chmod +[ugoa]*\+s|chmod +[2467][0-7]{3}|LD_PRELOAD|xxd -r|openssl +s_client|\balias +(sudo|su|ssh|passwd)=|PROMPT_COMMAND|trap .*DEBUG)'

fail=0
report() { printf '%s\t%s\t%s\t%s\n' "$@"; if [[ $1 == FAIL ]]; then fail=1; fi; }

pkgfiles=$(mktemp)
trap 'rm -f "$pkgfiles"' EXIT
{ cat /var/lib/dpkg/info/*.list 2>/dev/null || true; rpm -qal 2>/dev/null || true; } | sort -u > "$pkgfiles"
[[ -s $pkgfiles ]] || echo "WARN: no dpkg/rpm file list, every file will be WARN" >&2
owned() { grep -qxF -e "$1" -e "/usr$1" -e "${1#/usr}" "$pkgfiles"; }   # merged-/usr aware

declare -A seen
# check <category> <owned-check yes|no> <paths...>: content -> FAIL, else not packaged -> WARN
check() {
  local cat=$1 pkgcheck=$2 f hit; shift 2
  while IFS= read -r f; do
    f=$(realpath -e "$f" 2>/dev/null) || continue
    [[ -f $f && -z ${seen[$f]:-} ]] || continue
    seen[$f]=1
    if hit=$(grep -IvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | grep -m1 -E "$sus"); then
      report FAIL "$cat" "$f" "${hit:0:200}"
    elif [[ $pkgcheck == yes ]] && ! owned "$f"; then
      report WARN "$cat" "$f" "not from a package, modified $(date -r "$f" '+%F %T')"
    fi
  done < <(find "$@" -xdev \( -type f -o -type l \) 2>/dev/null || true)
}

mapfile -t homes < <(getent passwd | cut -d: -f6 | sort -u | grep -v '^/$' || true)
userfiles=() userdirs=()
for h in "${homes[@]}"; do
  userfiles+=("$h"/.{bashrc,bash_profile,bash_login,profile,bash_logout,zshrc,zprofile,zlogin})
  userdirs+=("$h/.config/systemd/user" "$h/.config/autostart")
done

cron=(/etc/crontab /etc/anacrontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/at)
check cron yes "${cron[@]}"
check systemd yes /etc/systemd/system /etc/systemd/user /run/systemd/system /run/systemd/transient /run/systemd/generator* \
  /usr/lib/systemd/system /usr/lib/systemd/user /usr/local/lib/systemd /etc/systemd/system-generators /usr/lib/systemd/system-generators
check init yes /etc/rc.local /etc/init.d /etc/rc.d
check shell no /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment   # created by postinst, never in a package list
check shell yes /etc/profile.d /etc/zsh
check loader yes /etc/ld.so.conf /etc/ld.so.conf.d
check udev yes /etc/udev/rules.d /run/udev/rules.d
check login yes /etc/update-motd.d /etc/xdg/autostart
check hooks yes /etc/apt/apt.conf.d
check user-shell no "${userfiles[@]}"
check user-autostart yes "${userdirs[@]}"

# Any preload entry injects a library into every process
if [[ -s /etc/ld.so.preload ]] && grep -qvE '^[[:space:]]*(#|$)' /etc/ld.so.preload; then
  report FAIL loader /etc/ld.so.preload "$(grep -vE '^[[:space:]]*(#|$)' /etc/ld.so.preload | head -c 200)"
fi

# Every active cron/at line, even in packaged files (Red appends to /etc/crontab)
while IFS= read -r f; do
  while IFS= read -r line; do
    report INFO cron-entry "$f" "${line:0:200}"
  done < <(grep -IvE '^[[:space:]]*(#|$)|^[[:space:]]*[A-Z_]+=' "$f" 2>/dev/null | grep -v 'run-parts' || true)   # ponytail: stock run-parts lines hidden; anything suspicious still FAILs above
done < <(find /etc/crontab /etc/cron.d /var/spool/cron /var/spool/at -xdev -type f 2>/dev/null || true)

exit $(( fail ? 2 : 0 ))
