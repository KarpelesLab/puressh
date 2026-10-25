#!/bin/sh
# Build Ubuntu source packages of puressh for Launchpad (ppa:karpeleslab/puressh).
#
# usage: build-source.sh VERSION OUTDIR SERIES...
#
#   VERSION  upstream version, e.g. 0.2.6; the source is the tag vVERSION,
#            or REF=<git ref> to package another commit
#   OUTDIR   where the orig tarball, .dsc, .debian.tar.xz and _source.changes
#            files are written
#   SERIES   jammy, noble, resolute or stonking
#
# environment: REV (default 1) the PPA revision, bumped to re-upload the same
# upstream version; DEBFULLNAME/DEBEMAIL for the changelog entry.
#
# The orig tarball (the git tree plus `cargo vendor`, since Launchpad builds
# offline) is made once and reused when OUTDIR already holds it: every
# series of one version must be uploaded with byte-identical origs.
#
# Needs git, cargo ($CARGO, with network access, for the vendoring), xz and
# dpkg-source/dpkg-genchanges (dpkg-dev); no build dependencies. The
# resulting changes files are unsigned: debsign, then dput, them.
set -eu

[ $# -ge 3 ] || { sed -n '3,21p' "$0" >&2; exit 2; }
VERSION=$1 OUTDIR=$(mkdir -p "$2" && cd "$2" && pwd)
shift 2
REV=${REV:-1}
REF=${REF:-v$VERSION}
HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
ORIG="$OUTDIR/puressh_$VERSION.orig.tar.xz"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [ ! -e "$ORIG" ]; then
	src="$WORK/puressh-$VERSION"
	mkdir "$src"
	git -C "$TOP" archive "$REF" | tar -x -C "$src"
	epoch=$(git -C "$TOP" log -1 --format=%ct "$REF")
	# Lock to versions within the declared rust-version where possible;
	# Cargo.lock is not committed, so this is where it is decided.
	(cd "$src" && CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback \
		${CARGO:-cargo} generate-lockfile &&
		${CARGO:-cargo} vendor --locked vendor >/dev/null)
	tar -C "$WORK" --sort=name --mtime="@$epoch" --owner=0 --group=0 \
		--numeric-owner --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
		-cf - "puressh-$VERSION" | xz -T1 -6 >"$ORIG.tmp"
	mv "$ORIG.tmp" "$ORIG"
	rm -rf "$src"
fi

for SERIES; do
	case "$SERIES" in
	# OPENSSH: the openssh-server version puressh-server provides, at
	# least what the series' packages depend on (the ssh metapackage
	# wants its own release's version or later; 26.10's openssh-client
	# Breaks anything below 1:10.3p1-6~), above any update of that
	# upstream release.
	jammy) NUM=22.04 SERVER=yes UNITDIR=lib/systemd/system TOOL=1.91 OPENSSH=1:9.9p1-0puressh1 ;;
	noble) NUM=24.04 SERVER=yes UNITDIR=usr/lib/systemd/system TOOL=1.91 OPENSSH=1:9.9p1-0puressh1 ;;
	resolute) NUM=26.04 SERVER=yes UNITDIR=usr/lib/systemd/system TOOL=1.91 OPENSSH=1:10.2p1-99puressh1 ;;
	stonking) NUM=26.10 SERVER=yes UNITDIR=usr/lib/systemd/system TOOL= OPENSSH=1:10.5p1-99puressh1 ;;
	*) echo "unknown series: $SERIES" >&2; exit 2 ;;
	esac
	if [ -n "$TOOL" ]; then
		BCARGO=cargo-$TOOL RUSTC=rustc-$TOOL DEPS="cargo-$TOOL, rustc-$TOOL"
	else
		BCARGO=cargo RUSTC=rustc DEPS="cargo (>= 1.91), rustc (>= 1.91)"
	fi
	DEBVER="$VERSION-1ppa$REV~ubuntu$NUM"

	dir="$WORK/$SERIES/puressh-$VERSION"
	mkdir -p "$WORK/$SERIES"
	tar -xJf "$ORIG" -C "$WORK/$SERIES"
	cp "$ORIG" "$WORK/$SERIES/"
	d="$dir/debian"
	mkdir -p "$d/source"
	cp "$HERE/debian/source/format" "$d/source/"
	sed "s/@CARGO_DEPS@/$DEPS/" "$HERE/debian/control.in" >"$d/control"
	sed -e "s|@CARGO@|$BCARGO|" -e "s|@RUSTC@|$RUSTC|" -e "s|@SERVER@|$SERVER|" \
		-e "s|@UNITDIR@|$UNITDIR|" -e "s|@SERIES@|$SERIES|" \
		"$HERE/debian/rules" >"$d/rules"
	chmod 0755 "$d/rules"
	cp "$HERE/debian/copyright" "$d/copyright"
	install -m 0755 "$TOP/packaging/deb/client/preinst" "$d/puressh-client.preinst"
	install -m 0755 "$TOP/packaging/deb/client/postrm" "$d/puressh-client.postrm"
	if [ "$SERVER" = yes ]; then
		sed "s/@OPENSSH_VERSION@/$OPENSSH/" "$HERE/debian/control-server.in" >>"$d/control"
		for s in postinst prerm postrm; do
			install -m 0755 "$TOP/packaging/deb/scripts/$s" "$d/puressh-server.$s"
		done
	fi
	cat >"$d/changelog" <<CL
puressh ($DEBVER) $SERIES; urgency=medium

  * puressh $VERSION: https://github.com/KarpelesLab/puressh/releases/tag/v$VERSION

 -- ${DEBFULLNAME:-Mark Karpeles} <${DEBEMAIL:-mark@klb.jp}>  $(date -R)
CL

	# Every upload carries the (identical) orig tarball, so none depends on
	# Launchpad having processed another series' upload first.
	(cd "$dir" && dpkg-source -b . >/dev/null &&
		dpkg-genchanges -S -sa >"../puressh_${DEBVER}_source.changes")
	cp "$WORK/$SERIES/puressh_$DEBVER.dsc" "$WORK/$SERIES/puressh_$DEBVER.debian.tar.xz" \
		"$WORK/$SERIES/puressh_${DEBVER}_source.changes" "$OUTDIR/"
	echo "$OUTDIR/puressh_${DEBVER}_source.changes"
done
