#!/usr/bin/env bash
# Usage: ./tests/linux/test-lotl.sh   # needs docker
set -euo pipefail
cd "$(dirname "$0")/../.."
docker run --rm -v "$PWD":/s:ro ubuntu:24.04 bash -c "$(sed -n '/^# --- container ---$/,$p' "$0")"
exit
# --- container ---
set -eo pipefail
cd /s/linux/hunt
echo "== stock image"
./get-lotl-findings.sh >/dev/null && echo "PASS stock exits 0" || { echo "FAIL stock rc=$?"; exit 1; }

echo "== plant: process from /tmp (noexec blocks /dev/shm in CI)"
cp /bin/sleep /tmp/.hidden
/tmp/.hidden 300 &
pid=$!
sleep 1
rc=0; out=$(./get-lotl-findings.sh) || rc=$?
echo "$out"
kill "$pid" 2>/dev/null || true
ok=1
[[ $rc -eq 2 ]] || { echo "FAIL rc=$rc want 2"; ok=0; }
grep -qF "$(printf 'FAIL\tproc-tmp\tpid %s (' "$pid")" <<<"$out" && echo "PASS proc-tmp caught" || { echo "FAIL proc-tmp missed"; ok=0; }
[[ $ok -eq 1 ]]
