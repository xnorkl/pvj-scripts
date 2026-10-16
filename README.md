# PvJ 

These scripts assumes literally everything is burned and compromised.

## SSH key rotation

Note: check for ssh service failures with `sshd -t`.

| Step | Linux (`sudo`, `linux/ssh/`) | Windows (admin, `windows/ssh/`) | Pain |
|---|---|---|---|
| 0. Team key (laptop) | `ssh-keygen -t ed25519 -f team -C pvj-blue` | same | — |
| 1. Hunt | `get-ssh-authorized-keys.sh > keys.tsv` | `Get-SshAuthorizedKey.ps1` | odd paths, options, CA/command trust |
| 2. Keep access | `add-ssh-authorized-key.sh root team.pub` | `Add-SshAuthorizedKey.ps1 -UserName Administrator -PublicKeyPath team.pub` | — |
| 3. Revoke | `get-ssh-authorized-keys.sh \| revoke-ssh-keys.sh team.pub` | `Get-SshAuthorizedKey.ps1 \| Revoke-SshKey.ps1 -ApprovedKeyPath team.pub` | re-plant fails |
| 4. Reset files | `get-ssh-authorized-keys.sh \| reset-ssh-authorized-keys.sh team.pub` | `Get-SshAuthorizedKey.ps1 \| Reset-SshAuthorizedKey.ps1 -ApprovedKeyPath team.pub` | hashes |
| 5. Host keys | `reset-ssh-host-keys.sh` | `Reset-SshHostKey.ps1` | stolen host key |
| 6. Audit sshd config | `../hunt/continuous/get-sshd-config-findings.sh` | `..\hunt\continuous\Get-SshdConfigFinding.ps1` | ForceCommand/CA/rc persistence |
| 7. Re-hunt | steps 1 + 6 | steps 1 + 6 | re-plant means Red still has a shell |

## Threat hunting (living off the land)

Read-only. FAIL = looks malicious, WARN = review, INFO = inventory.
Continuous = safe on a controller-side timer; active = run on demand (reads live processes/logs).

Scripts live in `hunt/<scan>/` (e.g. `linux/hunt/continuous/`), so Ansible can run a class with `--tags`.

| Hunt | Scan | Linux (`sudo`, `linux/hunt/<scan>/`) | Windows (admin, `windows/hunt/<scan>/`) |
|---|---|---|---|
| Persistence | continuous | `get-autostart-findings.sh` | `Get-AutostartFinding.ps1` |
| sshd config | continuous | `get-sshd-config-findings.sh` | `Get-SshdConfigFinding.ps1` |
| Privesc | continuous | `get-privesc-findings.sh` | `Get-PrivescFinding.ps1` |
| Living off the land | active | `get-lotl-findings.sh` | `Get-LolbinFinding.ps1` |

## Script rules

| | Hunts (`get-*` / `Get-*`, in `hunt/`) | Changes (in `ssh/`, ...) |
|---|---|---|
| Output | TSV, no header: `status check object detail` (Windows: objects with those properties) | log lines; `no change: ...` when there was nothing to do |
| Exit code | 0 clean, 1 error, 2 a FAIL was found | 0 ok, 1 error |
| Safety | read-only | safe to re-run, keeps a backup, `sshd -t` + undo on failure |
| Shape | one self-contained file, no shared library, so it can be pasted onto a box by hand | same |

## When to use each script

Windows paths are in brackets when they differ.

| Script | Use | Leaves on the host |
|---|---|---|
| `get-ssh-authorized-keys` | Inventory trusted SSH keys. | — |
| `add-ssh-authorized-key` | Install the team key. | — |
| `revoke-ssh-keys` | Revoke compromised keys (KRL). | `/etc/ssh/revoked_keys` [`%ProgramData%\ssh\revoked_keys`], `sshd_config.bak-<ts>` |
| `reset-ssh-authorized-keys` | Purge unapproved keys. | originals in `/root/ssh-quarantine-<ts>/` [`%ProgramData%\ssh\quarantine-<ts>\`] |
| `reset-ssh-host-keys` | Rotate host keys. | old keys in `/root/ssh-hostkeys-<ts>/` [`%ProgramData%\ssh\hostkeys-<ts>\`] |
| `get-sshd-config-findings` | Audit sshd for backdoors. | — |
| `get-autostart-findings` | Hunt persistence. | — |
| `get-privesc-findings` / `Get-PrivescFinding` | Hunt privilege escalation (SUID, caps, sudoers / sticky-keys, services). | — |
| `get-lotl-findings` / `Get-LolbinFinding` | Hunt living-off-the-land execution (reverse shells / certutil, mshta). | — |

## Ansible (`ansible/`)

```sh
cd ansible && cp inventory.example.yml inventory.yml     # fill in from the handout (gitignored)
ansible-playbook hunt.yml -e run=baseline                # all hunts -> ../findings/baseline/<host>/<script>.tsv
ansible-playbook hunt.yml -e run=t1 --tags continuous    # timer sweep: persistence, sshd, privesc only
ansible-playbook hunt.yml -e run=t1 --tags active        # on demand: live processes / LOLBins
diff -r ../findings/baseline ../findings/t1              # what Red added since the last sweep
ansible-playbook ssh-rotate.yml                          # uses ../team.pub; -e approved_pub=... for extra keys
ansible-playbook ssh-hostkeys.yml --tags hostkeys        # never runs without the tag; refreshes known_hosts
```
Hunt scripts are re-copied per run (a Red-modified copy gets overwritten) and findings are deleted from the host after they're fetched.

## Containers

One controller image (`docker/controller.Dockerfile`) runs the playbooks for both testing and the range.

```sh
./tests/test-compose.sh                 # Linux target + ansible controller: hunts, playbooks, tag selection
./tests/test-compose.sh windows         # also boots a real Windows target (dockur/windows) — KVM Linux host only
docker compose -f deploy/compose.yml run --rm controller ansible-playbook hunt.yml -e run=t0   # against the range
```
Deploy networking is bridge; the range VPN runs on the host, so route `100.80.0.0/21` into the controller or run the VPN client inside it (see `deploy/compose.yml`).

## Gotchas
- Run revoke (3) before reset (4). Revoke reads the keys that are still in the files.
- Deleting the KRL (`RevokedKeys`) file breaks **all** key logins.
- Ansible: if it logs in with a key, put that key in `approved_pub` too, or `ssh-rotate.yml` locks Ansible out.
- Windows: use WinRM, not SSH; `Restart-Service sshd` drops SSH sessions. Use `-WhatIf` for a dry run.
- Passwords are untouched. Change them separately.

Fast unit tests (Docker only): `./tests/linux/test-ssh-rotation.sh`, `test-autostart.sh`, `test-privesc.sh`, `test-lotl.sh`, `test-ansible.sh` (last also needs host `ansible-core` + `community.docker`).
End-to-end (Docker Compose, no host ansible): `./tests/test-compose.sh`.
