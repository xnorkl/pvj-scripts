# Ansible control node for the PvJ scripts: used by tests/compose.yml and deploy/compose.yml.
# Build: docker build -f docker/controller.Dockerfile -t pvj-controller .
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass rsync \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
      ansible-core==2.17.6 \
      pywinrm==0.4.3 \
 && ansible-galaxy collection install \
      ansible.windows:==2.5.0 \
      community.docker:==3.13.0 \
      ansible.posix:==1.6.2

WORKDIR /work
