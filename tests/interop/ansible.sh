#!/bin/sh
# Ansible against puressh at both ends: our sshd, and our ssh / scp / sftp
# first on PATH, with Ansible's own ssh arguments (ControlMaster auto,
# ControlPersist, PreferredAuthentications with gssapi methods, ...). The
# playbook runs once per file-transfer method (sftp, scp, piped, and
# pipelining), and the whole sftp run must use a single authentication.
#
# usage: ansible.sh <dir with ssh, scp, sftp, sshd> <dir with ansible-playbook>
set -eu
BIN=$(cd "$1" && pwd)
ANSIBLE=$(cd "$2" && pwd)
D=$(mktemp -d /tmp/pans.XXXXXX)
SSHD_PID=
cleanup() {
	status=$?
	[ -n "$SSHD_PID" ] && kill "$SSHD_PID" 2>/dev/null
	pkill -f "$D/cp/" 2>/dev/null || true
	if [ "$status" -ne 0 ]; then
		cat "$D/out.txt" 2>/dev/null || true
		echo "--- sshd log"
		cat "$D/sshd.log" 2>/dev/null || true
	fi
	rm -rf "$D"
	return "$status"
}
trap cleanup EXIT

mkdir "$D/bin" "$D/cp"
for b in ssh scp sftp; do ln -s "$BIN/$b" "$D/bin/$b"; done
ssh-keygen -q -t ed25519 -N '' -f "$D/host"
ssh-keygen -q -t ed25519 -N '' -f "$D/user"
cp "$D/user.pub" "$D/ak"
U=$(id -un)
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
"$BIN/sshd" -f /dev/null -b 127.0.0.1 -p "$PORT" -h "$D/host" -A "$D/ak" -u "$U" \
	--no-strict-modes -d 2>"$D/sshd.log" &
SSHD_PID=$!
sleep 1

cat >"$D/inv" <<EOF
t ansible_host=127.0.0.1 ansible_port=$PORT ansible_user=$U ansible_ssh_private_key_file=$D/user ansible_python_interpreter=$(command -v python3)
EOF
cat >"$D/pb.yml" <<EOF
- hosts: t
  gather_facts: true
  tasks:
    - ping:
    - command: uname -n
    - copy: {content: "hello from ansible\n", dest: $D/copied.txt}
    - fetch: {src: $D/copied.txt, dest: $D/fetched/, flat: true}
    - stat: {path: $D/copied.txt}
      register: st
    - assert: {that: [st.stat.exists, "st.stat.size == 19"]}
    - file: {path: $D/dir1, state: directory, mode: "0750"}
EOF

for mode in "transfer_method = sftp" "transfer_method = scp" "transfer_method = piped" "pipelining = True"; do
	cat >"$D/ansible.cfg" <<EOF
[defaults]
host_key_checking = False
[ssh_connection]
ssh_args = -C -o ControlMaster=auto -o ControlPersist=60s -o UserKnownHostsFile=/dev/null
control_path_dir = $D/cp
$mode
EOF
	rm -rf "$D/copied.txt" "$D/fetched"
	before=$(grep -c 'auth publickey: verified' "$D/sshd.log" || true)
	(cd "$D" && PATH="$D/bin:$PATH" ANSIBLE_CONFIG="$D/ansible.cfg" \
		"$ANSIBLE/ansible-playbook" -i inv pb.yml </dev/null >"$D/out.txt" 2>&1)
	grep -q 'failed=0' "$D/out.txt"
	grep -qx 'hello from ansible' "$D/fetched/copied.txt"
	after=$(grep -c 'auth publickey: verified' "$D/sshd.log")
	echo "$mode: ok ($((after - before)) authentication(s))"
	if [ "$mode" = "transfer_method = sftp" ] && [ $((after - before)) -ne 1 ]; then
		echo "expected the ControlMaster to carry the whole run"
		exit 1
	fi
	# The next method starts without a master (Ansible names its own
	# ControlPath, so end them by it).
	pkill -f "$D/cp/" 2>/dev/null || true
	sleep 0.5
done
echo "ansible interop OK"
