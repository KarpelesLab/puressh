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
# On any failure, show what systemd and the SSH daemons were doing.
diagnose() {
	status=$?
	[ "$status" -eq 0 ] && return 0
	printf '\n==> FAILED (exit %s): diagnostics\n' "$status"
	timeout 20 systemctl status ssh.service ssh.socket --no-pager || true
	timeout 20 journalctl --no-pager -n 100 || true
	ps -eo pid,ppid,stat,etime,wchan:20,args --forest | grep -v ' \[' | tail -80 || true
	return "$status"
}
trap diagnose EXIT
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
INSTALLED=$(date '+%Y-%m-%d %H:%M:%S')
sleep 1
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
# A PTY session goes through PAM sessions and the privilege drop, and is
# recorded as OpenSSH records it: utmp (who) while it lasts, wtmp (last)
# and lastlog ("Last login:" at the next interactive login) after.
try_ssh -tt tester@localhost 'tty; sleep 1; who' >/tmp/pty.out
grep -q /dev/pts/ /tmp/pty.out
grep -q '^tester  *pts/' /tmp/pty.out
last -w tester | grep -q '^tester  *pts/'
printf 'exit\n' | try_ssh -tt tester@localhost | tr -d '\r' | grep -q '^Last login: .* from '
ss -ltnp | grep -q ':22 '
# Logins are logged as OpenSSH logs them (syslog, facility AUTH), where
# fail2ban and auth.log readers look.
sleep 1
ours_log() { journalctl --no-pager -o cat --since "$INSTALLED" SYSLOG_FACILITY=4 SYSLOG_IDENTIFIER=sshd; }
ours_log | grep -q '^Server listening on '
ours_log | grep -q '^Accepted publickey for tester from .* port [0-9]* ssh2: ED25519 SHA256:'

step "reload (SIGHUP) picks up an SFTP-only chroot jail"
# The common deployment: a drop-in with Match User + ChrootDirectory +
# ForceCommand internal-sftp, applied by a reload.
id jailed >/dev/null 2>&1 || useradd -m -s /bin/bash jailed
install -d -m 700 -o jailed -g jailed /home/jailed/.ssh
install -m 600 -o jailed -g jailed /root/tester_key.pub /home/jailed/.ssh/authorized_keys
install -d -m 755 -o root -g root /srv/jail/jailed
install -d -m 755 -o jailed -g jailed /srv/jail/jailed/upload
printf '%s\n' 'Match User jailed' '	ChrootDirectory /srv/jail/%u' \
	'	ForceCommand internal-sftp' '	AllowTcpForwarding no' \
	>/etc/ssh/sshd_config.d/50-jail.conf
systemctl reload ssh.service
sleep 1
systemctl is-active ssh.service
try_ssh tester@localhost 'echo reload-ok' | grep -q reload-ok
echo jailed-data >/tmp/jail.txt
printf 'pwd\nput /tmp/jail.txt /upload/jail.txt\nls /\n' >/tmp/jail.batch
if ! sftp -F /dev/null -i /root/tester_key -o BatchMode=yes -o StrictHostKeyChecking=yes \
	-o UserKnownHostsFile=/root/known_hosts -b /tmp/jail.batch jailed@localhost >/tmp/jail.out 2>&1; then
	cat /tmp/jail.out
	exit 1
fi
grep -q 'Remote working directory: /$' /tmp/jail.out
cmp /tmp/jail.txt /srv/jail/jailed/upload/jail.txt
# The jail's root is all the session sees, and no shell is to be had.
if grep -q home /tmp/jail.out; then cat /tmp/jail.out; exit 1; fi
out=$(ssh -F /dev/null -i /root/tester_key -o BatchMode=yes -o StrictHostKeyChecking=yes \
	-o UserKnownHostsFile=/root/known_hosts jailed@localhost 'echo shell-ok' </dev/null 2>&1 || true)
if echo "$out" | grep -q shell-ok; then echo "jailed user got a shell"; exit 1; fi
rm -f /etc/ssh/sshd_config.d/50-jail.conf

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
