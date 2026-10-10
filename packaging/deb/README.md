# Ubuntu packages

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
  `KillMode=process` so restarts never drop open sessions). On 24.04 the
  socket-activated `ssh.socket` is retired; the daemon listens itself.
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
