# Launchpad PPA

`ppa:karpeleslab/puressh` carries the Ubuntu packages described in
[`../deb/README.md`](../deb/README.md), built by Launchpad from source:

```
sudo add-apt-repository ppa:karpeleslab/puressh
sudo apt install puressh-server   # and/or puressh-client
```

| Series         | Packages                          | Toolchain                     |
|----------------|-----------------------------------|-------------------------------|
| jammy (22.04)  | `puressh-server`, `puressh-client` | `cargo-1.91`, `rustc-1.91`   |
| noble (24.04)  | `puressh-server`, `puressh-client` | `cargo-1.91`, `rustc-1.91`   |
| resolute (26.04) | `puressh-client`                | `cargo-1.91`, `rustc-1.91`   |
| stonking (26.10) | `puressh-client`                | `cargo`, `rustc` (1.97)      |

`puressh-server` is only built where its takeover of `openssh-server` has
been worked out and tested. From 26.04 on, openssh-server also ships
`sshd.service`, `sshd@.service`, `sshd-keygen.service`, sysusers and tmpfiles
snippets and a different `/etc/pam.d/sshd`, which the server package does
not handle yet. Focal (20.04) has no rustc that can build edition 2024 (its
newest is 1.80), so it is not on Launchpad.

## How it is built

`build-source.sh VERSION OUTDIR SERIES...` writes, from the tag `vVERSION`:

- `puressh_VERSION.orig.tar.xz`: the git tree plus `vendor/` (`cargo vendor`)
  and the `Cargo.lock` it was vendored from. Launchpad builders have no
  network, so every crate has to be in the tarball. The tarball is made once
  per version and reused, since all series must be uploaded with identical
  copies of it; the release workflow keeps it as a release asset.
- per series, a `debian/` made from the templates here plus the maintainer
  scripts and files in `../deb`, and the unsigned `.dsc` and
  `_source.changes`.

`debian/rules` builds the programs with Ubuntu's own Rust toolchain, the
same features as the release binaries (`server,pam,agent`), dynamically
linked against the series' glibc, and runs the library tests. That
toolchain is older than the `rust-version` puressh and its dependencies
declare (jammy and noble have 1.91), so cargo runs with
`--ignore-rust-version`. The `deb` and `deb-client` CI jobs build the
packages exactly this way on every push, then run the lifecycle tests on
them.

## Uploading

The `publish-launchpad` job of the release workflow builds, signs and
uploads the four source packages when a release is published. It signs with
the apt repository's key (`APT_GPG_PRIVATE_KEY`, and `APT_GPG_PASSPHRASE` if
it has one; see [`../apt/README.md`](../apt/README.md)), which must be
registered on a Launchpad account that may upload to the PPA.

The PPA must build for amd64 and arm64: enable arm64 under "Change details"
→ "Processors" on the PPA's page.

Without the secret the job skips itself. A failed upload can be retried
with "Run workflow" on the release workflow; Launchpad never accepts the
same version twice, so give a new `ppa_rev` to re-upload a version it has
already accepted (`0.2.7-1ppa2~ubuntu24.04` and so on).

By hand:

```
packaging/launchpad/build-source.sh 0.2.7 out jammy noble resolute stonking
debsign -k KEYID out/*_source.changes
dput ppa:karpeleslab/puressh out/*_source.changes
```

Versions are `VERSION-1ppaREV~ubuntuNN.NN`, which sort above both
`puressh-server` (`VERSION-1~ubuntuNN.NN`) and `puressh-client`
(`VERSION-1`) from the GitHub releases, so the PPA takes over from them.
