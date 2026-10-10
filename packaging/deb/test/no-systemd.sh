#!/bin/sh
# Install the puressh-server package in a container without systemd (used for
# Ubuntu 20.04, which has no GitHub-hosted VM runner any more), start the
# daemon by hand and log in, including a PTY session.
#
# usage: no-systemd.sh path/to/puressh-server.deb
set -eu
DEB=$(readlink -f "$1")
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq openssh-client "$DEB"
/usr/sbin/sshd -V | grep -q puressh
ls /etc/ssh/ssh_host_ed25519_key /etc/ssh/sshd_config
/usr/sbin/sshd -t

id tester >/dev/null 2>&1 || useradd -m -s /bin/bash tester
ssh-keygen -q -t ed25519 -N '' -f /root/tester_key
install -d -m 700 -o tester -g tester /home/tester/.ssh
install -m 600 -o tester -g tester /root/tester_key.pub /home/tester/.ssh/authorized_keys
echo "localhost $(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" >/root/known_hosts

/usr/sbin/sshd -D -E /tmp/sshd.log &
sleep 1
run() {
	ssh -F /dev/null -i /root/tester_key -o BatchMode=yes \
		-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/root/known_hosts "$@"
}
if ! out=$(run tester@localhost 'echo ok; id -un' 2>&1); then
	echo "$out"; cat /tmp/sshd.log; exit 1
fi
echo "$out" | grep -qx ok
echo "$out" | grep -qx tester
run -tt tester@localhost tty | grep -q /dev/pts/ || { cat /tmp/sshd.log; exit 1; }
echo "no-systemd install OK"
