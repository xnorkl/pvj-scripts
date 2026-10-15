#!/usr/bin/env bash
# End-to-end check of linux/*.sh in a throwaway Ubuntu container (no range access needed).
# Plants Red keys (incl. a Match-block AuthorizedKeysFile redirect), rotates, then proves
# a re-planted Red key is rejected and the team key still works.
# Usage: ./tests/test-linux-ssh-rotation.sh
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD":/s:ro ubuntu:24.04 bash -c "$(sed -n '/^# --- container ---$/,$p' "$0")"
exit
# --- container ---
set -e
apt-get update -qq >/dev/null && apt-get install -y -qq openssh-server openssh-client >/dev/null 2>&1
mkdir -p /run/sshd
useradd -m alice; useradd -m -s /usr/sbin/nologin svc
# Red persistence: normal key, options key, and a redirected AuthorizedKeysFile via Match
ssh-keygen -q -t ed25519 -N '' -f /tmp/red
ssh-keygen -q -t ed25519 -N '' -f /tmp/team
install -d -m700 -o alice /home/alice/.ssh; cat /tmp/red.pub > /home/alice/.ssh/authorized_keys; chown alice /home/alice/.ssh/authorized_keys; chmod 600 /home/alice/.ssh/authorized_keys
mkdir -p /var/tmp/.k; echo "command=\"/bin/sh -i\",no-pty $(cat /tmp/red.pub)" > /var/tmp/.k/svc; chown -R svc /var/tmp/.k
printf 'Match User svc\n  AuthorizedKeysFile /var/tmp/.k/%%u\n' >> /etc/ssh/sshd_config
/usr/sbin/sshd
cd /s/linux
echo "== inventory"; ./get-ssh-authorized-keys.sh | cut -f1-5
./add-ssh-authorized-key.sh alice /tmp/team.pub
./get-ssh-authorized-keys.sh > /tmp/keys.tsv
echo "== revoke"; ./revoke-ssh-keys.sh /tmp/team.pub < /tmp/keys.tsv
echo "== reset";  ./reset-ssh-authorized-keys.sh /tmp/team.pub < /tmp/keys.tsv
echo "== hostkeys"; ./reset-ssh-host-keys.sh
o=(-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
echo "== red re-plants key after cleanup"; cat /tmp/red.pub >> /home/alice/.ssh/authorized_keys
if ssh "${o[@]}" -i /tmp/red alice@127.0.0.1 true; then echo "FAIL red got in"; exit 1; fi
echo "PASS red key rejected (KRL)"
if ! ssh "${o[@]}" -i /tmp/team alice@127.0.0.1 true; then echo "FAIL team locked out"; exit 1; fi
echo "PASS team key works"
echo "== second run must be a no-op (ansible idempotency)"
./get-ssh-authorized-keys.sh | ./reset-ssh-authorized-keys.sh /tmp/team.pub   # clears the re-plant
./get-ssh-authorized-keys.sh | ./reset-ssh-authorized-keys.sh /tmp/team.pub | grep -q '^no change' && echo "PASS reset idempotent" || { echo "FAIL reset not idempotent"; exit 1; }
./add-ssh-authorized-key.sh alice /tmp/team.pub | grep -q '^no change' && echo "PASS add idempotent" || { echo "FAIL add not idempotent"; exit 1; }
if ./revoke-ssh-keys.sh </dev/null 2>/dev/null; then echo "FAIL revoke accepted empty stdin"; exit 1; fi
echo "PASS empty stdin rejected"
echo "== final inventory"; ./get-ssh-authorized-keys.sh | cut -f1-4
