#!/bin/sh
# Build the puressh-client .deb for one architecture (any Ubuntu release from
# 20.04 on: the binaries need glibc 2.31 and the package touches no
# release-specific paths).
#
# usage: build-client-deb.sh ARCH VERSION BINDIR OUTDIR
#
#   ARCH     amd64 or arm64 (Debian architecture names)
#   VERSION  upstream version, e.g. 0.1.9
#   BINDIR   directory holding ssh, scp, sftp, ssh-add, ssh-agent,
#            ssh-keygen and ssh-keyscan built for ARCH
#   OUTDIR   where the .deb is written
#
# The package diverts OpenSSH's /usr/bin programs (dpkg-divert) instead of
# replacing openssh-client, so it works next to either SSH server package.
set -eu

[ $# -eq 4 ] || { sed -n '3,15p' "$0" >&2; exit 2; }
ARCH=$1 VERSION=$2 BINDIR=$3 OUTDIR=$4
HERE=$(cd "$(dirname "$0")" && pwd)
case "$ARCH" in
amd64 | arm64) ;;
*) echo "unknown architecture: $ARCH" >&2; exit 2 ;;
esac

PKG=puressh-client
DEBVER="$VERSION-1"
ROOT=$(mktemp -d)
chmod 0755 "$ROOT"
trap 'rm -rf "$ROOT"' EXIT

install -d -m 0755 "$ROOT/DEBIAN" "$ROOT/usr/bin" "$ROOT/usr/share/doc/$PKG"
for p in ssh scp sftp ssh-add ssh-agent ssh-keygen ssh-keyscan; do
	install -m 0755 "$BINDIR/$p" "$ROOT/usr/bin/$p"
done
install -m 0755 "$HERE/../../scripts/ssh-copy-id" "$ROOT/usr/bin/ssh-copy-id"
install -m 0644 "$HERE/copyright" "$ROOT/usr/share/doc/$PKG/copyright"
for s in preinst postrm; do
	install -m 0755 "$HERE/client/$s" "$ROOT/DEBIAN/$s"
done

SIZE=$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)
cat >"$ROOT/DEBIAN/control" <<CTRL
Package: $PKG
Version: $DEBVER
Architecture: $ARCH
Maintainer: Mark Karpeles <mark@klb.jp>
Installed-Size: $SIZE
Depends: libc6 (>= 2.31)
Recommends: openssh-client
Provides: ssh-client
Section: net
Priority: optional
Homepage: https://github.com/KarpelesLab/puressh
Description: puressh secure shell (SSH) client programs, in place of OpenSSH's
 ssh, scp, sftp, ssh-add, ssh-agent, ssh-keygen, ssh-keyscan and ssh-copy-id
 from puressh, a pure-Rust SSH implementation, as drop-in replacements for
 OpenSSH's: same options, configuration files (/etc/ssh/ssh_config,
 ~/.ssh) and keys.
 .
 OpenSSH's programs are kept as /usr/bin/<name>.openssh while this package
 is installed and get their names back when it is removed.
CTRL

(cd "$ROOT" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' | sort -z |
	xargs -0 md5sum >DEBIAN/md5sums)

mkdir -p "$OUTDIR"
OUT="$OUTDIR/${PKG}_${DEBVER}_${ARCH}.deb"
# xz: 20.04's dpkg cannot read zstd-compressed packages.
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$OUT" >/dev/null
echo "$OUT"
