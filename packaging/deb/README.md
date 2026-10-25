# Ubuntu packages

## puressh-server

`build-deb.sh` builds `puressh-server`, a drop-in replacement for Ubuntu's
`openssh-server` on 20.04 (focal), 22.04 (jammy) and 24.04 (noble), amd64 and
arm64. The release workflow attaches the packages to every GitHub release.

```
sudo apt install ./puressh-server_<version>~ubuntu24.04_amd64.deb
```

What the package does:

- `Provides`/`Conflicts`/`Replaces: openssh-server`, so apt removes OpenSSH's
  server package but keeps everything that depends on it.
- Installs `/usr/sbin/sshd` and its own `ssh.service` (alias `sshd.service`,
  `Type=notify` like Ubuntu's, `KillMode=process` so restarts never drop
  open sessions). From 24.04 on the
  socket-activated `ssh.socket` is retired; the daemon listens itself. From
  26.04 on (the Launchpad packages) it also ships `sshd.service`,
  `sshd@.service` and `sshd-keygen.service`, as openssh-server does there.
- Takes over `/etc/pam.d/sshd`, `/etc/default/ssh` and the ufw `OpenSSH`
  profile, byte-identical to Ubuntu's copies.
- Keeps `/etc/ssh/sshd_config`, `sshd_config.d/` and the host keys. A backup
  in `/var/lib/puressh` (root-only) lets `ssh.service` restore them if
  `openssh-server` is later purged (its purge deletes them).
- The postinst checks the configuration with the new `sshd -t` before it
  touches the running daemon. If the configuration is rejected, the old
  daemon keeps running and the installation fails with the reason.

Going back: `sudo apt install openssh-server`.

`files/pam-sshd`, `files/default-ssh`, `files/ufw-openssh-server` and
`sshd_config/*` are copied unchanged from Ubuntu's `openssh-server` packages
(see `copyright`).

## puressh-client

`build-client-deb.sh` builds `puressh-client` (one package per architecture,
for every release from 20.04 on): `ssh`, `scp`, `sftp`, `ssh-add`,
`ssh-agent`, `ssh-keygen`, `ssh-keyscan` and `ssh-copy-id`.

```
sudo apt install ./puressh-client_<version>-1_amd64.deb
```

It does not replace `openssh-client`: it diverts its programs
(`dpkg-divert`), so OpenSSH's stay installed as `/usr/bin/<name>.openssh`.
Everything that depends on `openssh-client` (`openssh-server` included) stays
satisfied, `/etc/ssh/ssh_config` remains `openssh-client`'s conffile, and the
package works next to either SSH server. Removing `puressh-client` gives
OpenSSH's programs their names back.

## Tests

CI installs both packages on real 22.04, 24.04 and 26.04 machines (amd64,
arm64) and in a 26.10 container booting systemd, built as the Launchpad PPA
builds them (see [`../launchpad/README.md`](../launchpad/README.md)), and
the `build-deb.sh` packages in 20.04 containers: `test/lifecycle.sh` (server: replace OpenSSH,
reload, per-connection units, purge, back), `test/no-systemd.sh` (server without systemd) and
`test/client-lifecycle.sh` (client: divert, use, restore).
