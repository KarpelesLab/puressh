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
	for p in $(pgrep -f 'sshd' || true); do
		printf -- '--- pid %s: %s\n' "$p" "$(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null)"
		grep -E '^(State|Uid|Gid)' /proc/$p/status 2>/dev/null || true
		ls -l /proc/$p/fd 2>/dev/null | tail -n +2 || true
		cat /proc/$p/stack 2>/dev/null || true
	done
	return "$status"
}
trap diagnose EXIT
fp() { ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}'; }
installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
try_ssh() {
	# Retry briefly: the daemon may still be binding after a restart.
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		if out=$(timeout 30 ssh -F /dev/null -i /root/tester_key -o BatchMode=yes \
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
# through ssh.socket from 24.04 on, ssh.service before.
if ! grep -qE 'VERSION_CODENAME=(focal|jammy)$' /etc/os-release; then
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
# and lastlog ("Last login:" at the next interactive login) after. From
# 26.04 on there is no utmp (systemd dropped it) and no last(1).
try_ssh -tt tester@localhost 'tty; sleep 1; who' >/tmp/pty.out
grep -q /dev/pts/ /tmp/pty.out
if [ -e /run/utmp ]; then grep -q '^tester  *pts/' /tmp/pty.out; fi
if command -v last >/dev/null; then last -w tester | grep -q '^tester  *pts/'; fi
# One attempt (stdin is consumed), typing `exit` once the shell is up: input
# typed ahead may be eaten by the image's login scripts.
(sleep 5; printf 'exit\n') | timeout 60 ssh -tt -F /dev/null -i /root/tester_key -o BatchMode=yes \
	-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/root/known_hosts tester@localhost \
	>/tmp/login.out 2>&1 && rc=0 || rc=$?
# (Ubuntu's ~/.bash_logout ends with a failing clear_console: exit 1.)
# 26.10 has no lastlog left, and neither daemon prints a last login there.
if [ -e /var/log/lastlog ]; then lastlog='^Last login: .* from '; else lastlog='^tester@'; fi
if [ "$rc" = 124 ] || ! tr -d '\r' </tmp/login.out | grep -q "$lastlog"; then
	echo "interactive login: exit $rc"; cat -A /tmp/login.out; exit 1
fi
# ~/.ssh/rc runs at session start, as the user, in the home directory; and
# a shell without a terminal (`ssh host < script`) reads its commands.
printf 'echo "rc-ran $(id -un) $(pwd)" >rc.out\n' >/home/tester/.ssh/rc
chown tester:tester /home/tester/.ssh/rc
try_ssh tester@localhost true
grep -qx 'rc-ran tester /home/tester' /home/tester/rc.out
rm -f /home/tester/.ssh/rc /home/tester/rc.out
out=$(printf 'echo piped-$((6*7)); tty\n' | timeout 30 ssh -T -F /dev/null -i /root/tester_key \
	-o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/root/known_hosts \
	tester@localhost 2>&1 || true)
echo "$out" | grep -q piped-42 || { echo "shell without a terminal: $out"; exit 1; }
echo "$out" | grep -q 'not a tty'
ss -ltnp | grep -q ':22 '
# Logins are logged as OpenSSH logs them (syslog, facility AUTH), where
# fail2ban and auth.log readers look.
sleep 1
ours_log() { journalctl --no-pager -o cat --since "$INSTALLED" SYSLOG_FACILITY=4 SYSLOG_IDENTIFIER=sshd; }
ours_log | grep -q '^Server listening on '
ours_log | grep -q '^Accepted publickey for tester from .* port [0-9]* ssh2: ED25519 SHA256:'

step "an open session survives an in-place upgrade"
# Hold a session open, then reinstall the package: same postinst path as a
# version upgrade (binary replaced on disk, daemon stopped). puressh handles each connection in a forked worker that must outlive
# the restart; a regression drops the logged-in user mid-upgrade.
timeout 120 ssh -T -F /dev/null -i /root/tester_key -o BatchMode=yes \
	-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/root/known_hosts \
	tester@localhost 'echo up; sleep 90' </dev/null >/tmp/held.out 2>&1 &
held=$!
# Wait until the session is established (its `echo up` has come back).
established=
for _ in $(seq 1 30); do
	if grep -q '^up$' /tmp/held.out 2>/dev/null; then established=1; break; fi
	if ! kill -0 "$held" 2>/dev/null; then break; fi
	sleep 1
done
[ -n "$established" ] || { echo "held session never established"; cat /tmp/held.out; exit 1; }
dpkg -i "$DEB"
systemctl is-active ssh.service
sleep 2
if ! kill -0 "$held" 2>/dev/null; then
	echo "the in-place upgrade dropped an open session"; cat /tmp/held.out; exit 1
fi
kill "$held" 2>/dev/null || true
wait "$held" 2>/dev/null || true
# The upgraded daemon still accepts fresh connections.
try_ssh tester@localhost 'echo upgrade-ok' | grep -q upgrade-ok

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
if ! timeout 60 sftp -F /dev/null -i /root/tester_key -o BatchMode=yes -o StrictHostKeyChecking=yes \
	-o UserKnownHostsFile=/root/known_hosts -b /tmp/jail.batch jailed@localhost >/tmp/jail.out 2>&1; then
	cat /tmp/jail.out
	exit 1
fi
grep -q 'Remote working directory: /$' /tmp/jail.out
cmp /tmp/jail.txt /srv/jail/jailed/upload/jail.txt
# The jail's root is all the session sees, and no shell is to be had.
if grep -q home /tmp/jail.out; then cat /tmp/jail.out; exit 1; fi
out=$(timeout 60 ssh -F /dev/null -i /root/tester_key -o BatchMode=yes -o StrictHostKeyChecking=yes \
	-o UserKnownHostsFile=/root/known_hosts jailed@localhost 'echo shell-ok' </dev/null 2>&1 || true)
if echo "$out" | grep -q shell-ok; then echo "jailed user got a shell"; exit 1; fi
rm -f /etc/ssh/sshd_config.d/50-jail.conf

if [ -e /usr/lib/systemd/system/sshd@.service ]; then
	step "sshd@.service serves a connection from an Accept=yes socket"
	# What systemd-ssh-generator's AF_VSOCK / AF_UNIX sockets do (26.04 on),
	# on a TCP port the test can reach. Without the ephemeral-key
	# credential, ${CREDENTIALS_DIRECTORY} expands to nothing: a missing
	# file, which the daemon must skip.
	printf '%s\n' '[Socket]' 'ListenStream=127.0.0.1:2223' 'Accept=yes' \
		>/run/systemd/system/sshd.socket
	systemctl daemon-reload
	systemctl start sshd.socket
	echo "[localhost]:2223 $(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" >>/root/known_hosts
	try_ssh -p 2223 tester@localhost 'echo per-connection-ok' | grep -q per-connection-ok
	systemctl stop sshd.socket
	rm -f /run/systemd/system/sshd.socket
	systemctl daemon-reload
	systemctl is-active ssh.service
	# sshd.service is a unit of its own, as openssh-server's is.
	systemctl restart sshd.service
	systemctl is-active sshd.service
	try_ssh tester@localhost 'echo sshd-unit-ok' | grep -q sshd-unit-ok
fi

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
