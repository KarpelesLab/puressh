# puressh apt repository

An apt repository served from this project's GitHub Pages site, so Ubuntu users
can install and upgrade puressh with `apt` instead of downloading a `.deb` by
hand. The `publish-apt` job in
[`.github/workflows/release-binaries.yml`](../../.github/workflows/release-binaries.yml)
rebuilds it from the `.deb`s of every published GitHub Release, using
[`reprepro`](https://wiki.debian.org/DebianRepository/SetupWithReprepro).

The repository lives on an orphan `gh-pages` branch:

```
/                              https://<owner>.github.io/<repo>/
├── dists/{focal,jammy,noble}/ signed InRelease + metadata (one suite per LTS)
├── pool/main/                 the .deb files
├── conf/distributions         reprepro config (public, harmless)
├── db/                        reprepro state, persisted across runs
├── puressh-archive-keyring.asc  the public signing key users import
└── index.html                 install instructions
```

Server packages are suite-specific (their `~ubuntuNN` version pins file
locations), so each goes into its matching suite; the client package is
suite-agnostic and is published into all three.

## One-time setup

Done once by a maintainer; after that, every release updates the repo on its
own.

### 1. Create the signing key

A dedicated, **passphrase-less** key whose only job is signing this repository
(reprepro signs non-interactively in CI, so it cannot type a passphrase).
Protect the exported secret as a GitHub secret and nothing else.

```sh
gpg --batch --quick-gen-key "puressh apt repository <mark@klb.jp>" ed25519 sign never
# Export the SECRET half for CI (store it in the APT_GPG_PRIVATE_KEY secret):
gpg --armor --export-secret-keys mark@klb.jp > apt-signing-key.asc
```

The public half is published automatically as `puressh-archive-keyring.asc`;
you do not need to commit it.

### 2. Add the CI secret

In the GitHub repo: **Settings → Secrets and variables → Actions → New
repository secret**

- `APT_GPG_PRIVATE_KEY` — the full contents of `apt-signing-key.asc`.

Then delete your local `apt-signing-key.asc`. If the secret is absent the
`publish-apt` job skips itself, so releases keep working until you set it.

### 3. Enable GitHub Pages

**Settings → Pages → Build and deployment → Source: Deploy from a branch**,
branch `gh-pages`, folder `/ (root)`. The branch is created by the first
`publish-apt` run; if Pages complains it does not exist yet, run that job once
(publish a release, or trigger the workflow manually) and set the source
afterwards.

## How users install

```sh
curl -fsSL https://<owner>.github.io/<repo>/puressh-archive-keyring.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/puressh.gpg
echo "deb [signed-by=/usr/share/keyrings/puressh.gpg] https://<owner>.github.io/<repo> $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/puressh.list
sudo apt update
sudo apt install puressh-server   # or puressh-client
```

`$(lsb_release -cs)` resolves to `focal` / `jammy` / `noble`, so the same lines
work on every supported release. The live `index.html` shows the same snippet
with the real URL filled in.

## Notes

- **Latest version only.** Each run removes the previous `puressh-server` /
  `puressh-client` entries from each suite before adding the release's, so the
  repo always offers exactly the newest version (and re-runs are idempotent).
  It is not an archive of every past version.
- **Custom domain.** If you later point a CNAME at the Pages site, replace the
  `https://<owner>.github.io/<repo>` base in the instructions with it; nothing
  in the repo metadata hard-codes the host.
- **Key rotation.** Generate a new key, update `APT_GPG_PRIVATE_KEY`, and
  re-run the job. Existing users must re-import the new
  `puressh-archive-keyring.asc`.
