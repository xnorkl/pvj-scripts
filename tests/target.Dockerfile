# Throwaway range-host stand-in for tests/compose.yml.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server cron sudo python3 libcap2-bin iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && echo 'root:pvj' | chpasswd \
 && printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/99-test.conf \
 && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e"]
