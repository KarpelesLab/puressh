#!/bin/sh
# End-to-end lifecycle test of the puressh-server package on a real Ubuntu
# machine with systemd (run as root on a disposable CI VM):
#
#   stock OpenSSH -> install puressh-server -> reload -> purge openssh-server
#   (host keys restored) -> back to OpenSSH
#
# usage: lifecycle.sh path/to/puressh-server.deb
set -eu
DEB=$(readlink -f "$1")
export DEBIAN_FRONTEND=noninteractive

step() { printf '\n==> %s\n' "$*"; }
fp() { ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}'; }
installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
try_ssh() {
	# Retry briefly: the daemon may still be binding after a restart.
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if out=$(ssh -F /dev/null -i /root/tester_key -o BatchMode=yes \
			-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/root/known_hosts \
			"$@" 2>&1); then
			printf '%s\n' "$out"
			return 0
		fi
		sleep 1
	done
	printf '%s\n' "$out" >&2
	return 1
}

step "baseline: stock openssh-server"
apt-get update -qq
apt-get install -y -qq openssh-server >/dev/null
# Enabled at boot the way a stock install is (CI images ship it disabled):
# through ssh.socket on 24.04, ssh.service before.
if grep -q VERSION_CODENAME=noble /etc/os-release; then
	systemctl enable --now ssh.socket
	systemctl restart ssh.socket
	ls -la /etc/systemd/system/sockets.target.wants/ /etc/systemd/system/ssh.service.requires/ || true
else
	systemctl enable --now ssh.service
	systemctl restart ssh.service
fi
id tester >/dev/null 2>&1 || useradd -m -s /bin/bash tester
rm -f /root/tester_key /root/tester_key.pub
ssh-keygen -q -t ed25519 -N '' -f /root/tester_key
install -d -m 700 -o tester -g tester /home/tester/.ssh
install -m 600 -o tester -g tester /root/tester_key.pub /home/tester/.ssh/authorized_keys
echo "localhost $(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" >/root/known_hosts
FP=$(fp)
try_ssh tester@localhost 'echo openssh-ok'

step "install puressh-server"
apt-get install -y "$DEB"
if installed openssh-server; then echo "openssh-server still installed"; exit 1; fi
/usr/sbin/sshd -V | grep -q puressh
if ! systemctl is-active ssh.service; then
	systemctl status ssh.service --no-pager || true
	journalctl -u ssh.service --no-pager -n 30 || true
	exit 1
fi
if ! systemctl is-enabled ssh.service; then
	ls -la /etc/systemd/system /etc/systemd/system/*.wants /etc/systemd/system/*.requires || true
	ls -la /var/lib/systemd/deb-systemd-helper-enabled /var/lib/systemd/deb-systemd-helper-masked || true
	exit 1
fi
[ "$(fp)" = "$FP" ] || { echo "host key changed"; exit 1; }
out=$(try_ssh tester@localhost 'echo puressh-ok; id -un')
echo "$out" | grep -q puressh-ok
echo "$out" | grep -qx tester
# A PTY session goes through PAM sessions and the privilege drop.
try_ssh -tt tester@localhost 'tty' | grep -q /dev/pts/
ss -ltnp | grep -q ':22 '

step "reload (SIGHUP) keeps serving"
systemctl reload ssh.service
sleep 1
systemctl is-active ssh.service
try_ssh tester@localhost 'echo reload-ok' | grep -q reload-ok

step "purging openssh-server deletes host keys; ssh.service restores them"
apt-get purge -y -qq openssh-server >/dev/null 2>&1 || true
systemctl restart ssh.service
[ "$(fp)" = "$FP" ] || { echo "host key not restored"; exit 1; }
try_ssh tester@localhost 'echo restored-ok' | grep -q restored-ok

step "switch back to openssh-server"
apt-get install -y -qq openssh-server
systemctl restart ssh.socket >/dev/null 2>&1 || systemctl restart ssh.service
/usr/sbin/sshd -V 2>&1 | grep -qi openssh
if installed puressh-server; then echo "puressh-server still installed"; exit 1; fi
[ "$(fp)" = "$FP" ] || { echo "host key changed on the way back"; exit 1; }
try_ssh tester@localhost 'echo back-ok' | grep -q back-ok

step "lifecycle OK"
