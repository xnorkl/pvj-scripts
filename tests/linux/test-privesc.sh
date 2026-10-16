#!/usr/bin/env bash
# Usage: ./tests/linux/test-privesc.sh   # needs docker
set -euo pipefail
cd "$(dirname "$0")/../.."
docker run --rm -v "$PWD":/s:ro ubuntu:24.04 bash -c "$(sed -n '/^# --- container ---$/,$p' "$0")"
exit
# --- container ---
set -eo pipefail
apt-get update -qq >/dev/null && apt-get install -y -qq sudo libcap2-bin python3 >/dev/null 2>&1
cd /s/linux/hunt/continuous
echo "== stock image"
./get-privesc-findings.sh | grep -v '^INFO' || true
./get-privesc-findings.sh >/dev/null && echo "PASS stock exits 0" || { echo "FAIL stock rc=$?"; exit 1; }

echo "== plant privesc"
bash_path=$(command -v bash); chmod u+s "$bash_path"              # named GTFOBins SUID -> FAIL
cp /bin/sleep /usr/local/bin/.weird && chmod u+s /usr/local/bin/.weird  # unknown SUID, not packaged -> WARN
cp "$(command -v python3)" /usr/local/bin/pycap && setcap cap_setuid+ep /usr/local/bin/pycap
echo 'alice ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-alice

rc=0; out=$(./get-privesc-findings.sh) || rc=$?
echo "$out"
ok=1
[[ $rc -eq 2 ]] || { echo "FAIL rc=$rc want 2"; ok=0; }
for want in $'FAIL\tsuid\t'"$bash_path" $'WARN\tsuid\t/usr/local/bin/.weird' $'FAIL\tcap\t/usr/local/bin/pycap' $'FAIL\tsudoers\t/etc/sudoers.d/90-alice'; do
  grep -qF "$want" <<<"$out" && echo "PASS ${want//$'\t'/ }" || { echo "FAIL missing: ${want//$'\t'/ }"; ok=0; }
done
[[ $ok -eq 1 ]]
