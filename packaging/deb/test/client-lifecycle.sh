#!/bin/sh
# Lifecycle of the puressh-client package (run as root on a disposable CI
# machine; works with or without systemd):
#
#   OpenSSH client -> install puressh-client (OpenSSH's programs diverted) ->
#   ssh / scp / sftp / ssh-keyscan against a private OpenSSH sshd and Ubuntu's
#   stock /etc/ssh/ssh_config -> remove (OpenSSH's back) -> install, purge
#
# usage: client-lifecycle.sh path/to/puressh-client.deb
set -eu
DEB=$(readlink -f "$1")
export DEBIAN_FRONTEND=noninteractive
PROGS="ssh scp sftp ssh-add ssh-agent ssh-keygen ssh-keyscan ssh-copy-id"
TMP=$(mktemp -d)
SSHD_PID=

step() { printf '\n==> %s\n' "$*"; }
diverted() { dpkg-divert --list | grep -c 'by puressh-client' || true; }
diagnose() {
	status=$?
	[ -n "$SSHD_PID" ] && kill "$SSHD_PID" 2>/dev/null
	[ "$status" -eq 0 ] && return 0
	printf '\n==> FAILED (exit %s): diagnostics\n' "$status"
	dpkg-divert --list | grep -i ssh || true
	ls -l /usr/bin/ssh* || true
	cat "$TMP/sshd.log" 2>/dev/null || true
	return "$status"
}
trap diagnose EXIT

step "baseline: OpenSSH client"
apt-get update -qq
apt-get install -y -qq openssh-client openssh-server >/dev/null
ssh -V 2>&1 | grep -q OpenSSH

step "install puressh-client"
apt-get install -y "$DEB"
ssh -V 2>&1 | grep -q puressh
/usr/bin/ssh.openssh -V 2>&1 | grep -q OpenSSH
for p in $PROGS; do
	[ -x "/usr/bin/$p" ] && [ -e "/usr/bin/$p.openssh" ] || { echo "$p not diverted"; exit 1; }
done
[ "$(diverted)" -eq 8 ]
dpkg-query -W -f='${Status}' openssh-client | grep -q 'install ok installed'

step "use the client programs"
# Ubuntu's stock /etc/ssh/ssh_config (GSSAPIAuthentication, SendEnv, ...).
ssh -G localhost | grep -q '^hostname localhost'
ssh-keygen -q -t ed25519 -N '' -f "$TMP/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$TMP/userkey"
id tester >/dev/null 2>&1 || useradd -m -s /bin/bash tester
install -d -m 700 -o tester -g tester /home/tester/.ssh
cat "$TMP/userkey.pub" >>/home/tester/.ssh/authorized_keys
chown tester:tester /home/tester/.ssh/authorized_keys
chmod 600 /home/tester/.ssh/authorized_keys
mkdir -p /run/sshd
cat >"$TMP/sshd_config" <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $TMP/hostkey
PidFile none
UsePAM yes
Subsystem sftp internal-sftp
EOF
/usr/sbin/sshd -D -e -f "$TMP/sshd_config" 2>"$TMP/sshd.log" &
SSHD_PID=$!
echo "[localhost]:2222 $(cut -d' ' -f1,2 "$TMP/hostkey.pub")" >"$TMP/known_hosts"
set -- -F /dev/null -i "$TMP/userkey" -o BatchMode=yes -o StrictHostKeyChecking=yes \
	-o UserKnownHostsFile="$TMP/known_hosts"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	out=$(ssh "$@" -p 2222 tester@localhost 'echo ok' 2>&1) && break
	sleep 1
done
echo "$out" | grep -qx ok
echo payload >"$TMP/file"
scp "$@" -P 2222 "$TMP/file" tester@localhost:/tmp/puressh-scp
printf 'get /tmp/puressh-scp %s/back\n' "$TMP" | sftp "$@" -P 2222 -b - tester@localhost
cmp "$TMP/file" "$TMP/back"
ssh-keyscan -p 2222 127.0.0.1 2>/dev/null | grep -q ssh-ed25519
kill "$SSHD_PID"
SSHD_PID=

step "remove puressh-client"
apt-get remove -y puressh-client
ssh -V 2>&1 | grep -q OpenSSH
[ ! -e /usr/bin/ssh.openssh ]
[ "$(diverted)" -eq 0 ]

step "install again, then purge"
apt-get install -y "$DEB"
ssh -V 2>&1 | grep -q puressh
apt-get purge -y puressh-client
ssh -V 2>&1 | grep -q OpenSSH
[ "$(diverted)" -eq 0 ]

echo "client lifecycle OK"
