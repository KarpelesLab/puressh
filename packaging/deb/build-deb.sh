#!/bin/sh
# Build the puressh-server .deb for one Ubuntu release and architecture.
#
# usage: build-deb.sh RELEASE ARCH VERSION BINDIR OUTDIR
#
#   RELEASE  focal (20.04), jammy (22.04) or noble (24.04)
#   ARCH     amd64 or arm64 (Debian architecture names)
#   VERSION  upstream version, e.g. 0.1.9
#   BINDIR   directory holding `sshd` and `ssh-keygen` built for ARCH
#   OUTDIR   where the .deb is written
#
# One package per release because file locations must match the ones
# openssh-server uses there: the systemd unit is in /lib/systemd/system up to
# 22.04 and /usr/lib/systemd/system on 24.04. Taking over a file under its
# other /usr-merged alias would let dpkg delete ours when openssh-server's
# files are removed.
set -eu

[ $# -eq 5 ] || { sed -n '3,12p' "$0" >&2; exit 2; }
RELEASE=$1 ARCH=$2 VERSION=$3 BINDIR=$4 OUTDIR=$5
HERE=$(cd "$(dirname "$0")" && pwd)

case "$RELEASE" in
focal) NUM=20.04 UNITDIR=lib/systemd/system ;;
jammy) NUM=22.04 UNITDIR=lib/systemd/system ;;
noble) NUM=24.04 UNITDIR=usr/lib/systemd/system ;;
*) echo "unknown release: $RELEASE" >&2; exit 2 ;;
esac
case "$ARCH" in
amd64 | arm64) ;;
*) echo "unknown architecture: $ARCH" >&2; exit 2 ;;
esac

PKG=puressh-server
DEBVER="$VERSION-1~ubuntu$NUM"
ROOT=$(mktemp -d)
chmod 0755 "$ROOT"
chmod 0755 "$ROOT"
trap 'rm -rf "$ROOT"' EXIT

install -d -m 0755 "$ROOT/DEBIAN" "$ROOT/usr/sbin" "$ROOT/usr/lib/puressh" \
	"$ROOT/usr/share/puressh" "$ROOT/usr/share/doc/$PKG" "$ROOT/$UNITDIR" \
	"$ROOT/etc/pam.d" "$ROOT/etc/default" "$ROOT/etc/ufw/applications.d"

install -m 0755 "$BINDIR/sshd" "$ROOT/usr/sbin/sshd"
install -m 0755 "$BINDIR/ssh-keygen" "$ROOT/usr/lib/puressh/ssh-keygen"
install -m 0755 "$HERE/files/sshd-prepare" "$ROOT/usr/lib/puressh/sshd-prepare"
install -m 0644 "$HERE/sshd_config/$RELEASE" "$ROOT/usr/share/puressh/sshd_config"
install -m 0644 "$HERE/files/ssh.service" "$ROOT/$UNITDIR/ssh.service"
# Conffiles taken over from openssh-server, byte-identical to its copies on
# 20.04/22.04/24.04 so dpkg has nothing to ask about.
install -m 0644 "$HERE/files/pam-sshd" "$ROOT/etc/pam.d/sshd"
install -m 0644 "$HERE/files/default-ssh" "$ROOT/etc/default/ssh"
install -m 0644 "$HERE/files/ufw-openssh-server" "$ROOT/etc/ufw/applications.d/openssh-server"
install -m 0644 "$HERE/copyright" "$ROOT/usr/share/doc/$PKG/copyright"

for s in postinst prerm postrm; do
	install -m 0755 "$HERE/scripts/$s" "$ROOT/DEBIAN/$s"
done
cat >"$ROOT/DEBIAN/conffiles" <<CONF
/etc/default/ssh
/etc/pam.d/sshd
/etc/ufw/applications.d/openssh-server
CONF

SIZE=$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)
# `Provides: openssh-server` carries a version so versioned dependencies on
# it (walinuxagent, google-compute-engine-oslogin, the `ssh` metapackage)
# stay satisfied and apt does not remove those packages.
cat >"$ROOT/DEBIAN/control" <<CTRL
Package: $PKG
Version: $DEBVER
Architecture: $ARCH
Maintainer: Mark Karpeles <mark@klb.jp>
Installed-Size: $SIZE
Depends: libc6 (>= 2.31), libpam0g (>= 0.99.7.1), libpam-modules, libpam-runtime
Recommends: libpam-systemd, ncurses-term, xauth
Provides: openssh-server (= 1:9.9p1-0puressh1), ssh-server
Conflicts: openssh-server
Replaces: openssh-server
Section: net
Priority: optional
Homepage: https://github.com/KarpelesLab/puressh
Description: puressh secure shell (SSH) server, replacing OpenSSH's
 sshd from puressh, a pure-Rust SSH implementation, packaged as a drop-in
 replacement for openssh-server: it reads /etc/ssh/sshd_config, uses the
 existing host keys and PAM configuration, and runs as ssh.service.
 .
 Installing it removes openssh-server; the configuration and host keys are
 kept. Reinstalling openssh-server switches back.
CTRL

(cd "$ROOT" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' | sort -z |
	xargs -0 md5sum >DEBIAN/md5sums)

mkdir -p "$OUTDIR"
OUT="$OUTDIR/${PKG}_${DEBVER}_${ARCH}.deb"
# xz: 20.04's dpkg cannot read zstd-compressed packages.
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$OUT" >/dev/null
echo "$OUT"
