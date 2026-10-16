#!/usr/bin/env bash
# Usage: sudo ./get-lotl-findings.sh   # TSV: status check object detail; exit 2 = FAIL found
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }

# reverse shells, downloaders, interpreters run inline (same pattern as the autostart hunt)
sus='(/dev/(tcp|udp)/|\b(ba|z|da)?sh -i\b|\bnc(at)?\b.* -[ec]\b|\bsocat\b|mkfifo|base64 +(-d|--decode)|\| *(ba|z|da)?sh\b|python[0-9.]* -c|perl -e|php -r|ruby -e|xxd -r|openssl +s_client)'

fail=0
report() { printf '%s\t%s\t%s\t%s\n' "$@"; if [[ $1 == FAIL ]]; then fail=1; fi; }

for d in /proc/[0-9]*; do
  pid=${d#/proc/}
  exe=$(readlink "$d/exe" 2>/dev/null) || continue
  cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null); cmd=${cmd% }
  name="pid $pid ($exe)"

  case $exe in
    *" (deleted)")          report FAIL proc-deleted "$name" "${cmd:0:160}" ;;
    /tmp/*|/var/tmp/*|/dev/shm/*) report FAIL proc-tmp "$name" "running from a writable dir: ${cmd:0:160}" ;;
    /memfd:*)               report FAIL proc-memfd "$name" "fileless (memfd): ${cmd:0:160}" ;;
  esac

  [[ $cmd =~ $sus ]] && report FAIL proc-cmdline "$name" "${cmd:0:200}"

  # LD_PRELOAD / LD_LIBRARY_PATH injected into a live process
  while IFS= read -r -d '' env; do
    case $env in LD_PRELOAD=*|LD_LIBRARY_PATH=?*) report FAIL proc-preload "$name" "$env" ;; esac
  done < "$d/environ" 2>/dev/null || true
done

exit $(( fail ? 2 : 0 ))
