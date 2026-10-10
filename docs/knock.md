# puressh knock: stealth SSH rendezvous over UDP

Status: **v1, implemented** (`puressh::knock`, the `ssh` and `sshd`
binaries; see §10). Not compatible with SSH or any existing port-knocking
tool; it only works between puressh clients and puressh servers.

## 1. Goal and overview

The server keeps no TCP port visibly open. A client that is allowed to log in
sends one signed UDP datagram (a *KNOCK*). If it is valid, the server opens a
short-lived TCP listener that accepts only that client and replies with a
host-key-signed *ACCEPT*. The client then connects and runs a **normal,
complete SSH session**, including full user authentication. The knock only
decides who can reach the server. It never grants a login.

```
client                                         server
  |  TCP SYN :22  ── refused / no answer ──▶     |
  |  UDP :22  KNOCK(user, key_fp, sig1,          |
  |                 nonce, eph_c, sig2) ──────▶  |  cheap filter → verify → open listener
  |  ◀────── ACCEPT(knock_hash, eph_s, port,     |
  |                 hostkey, sig_host)           |
  |  TCP :port  open_token ─────────────────▶    |  token check (peer IP + HMAC)
  |  ◀═══════════ standard SSH ═══════════▶      |  full KEX + userauth
```

Design properties:

- **Silent on failure.** The server never answers an invalid, unknown,
  replayed, or rate-limited knock. It sends no NACK, no error, and no ICMP.
- **Cheap rejection first.** Most bogus traffic is dropped by a hash lookup or
  a byte comparison before any public-key operation.
- **No amplification.** The ACCEPT is never larger than the KNOCK it answers.
- **Bound end to end.** ACCEPT is bound to the KNOCK, the TCP open token is
  bound to both (through ephemeral X25519), and the SSH host key is bound to
  the key that signed the ACCEPT.

## 2. Notation and encoding

- All integers are unsigned big-endian.
- `str8`: `u8 len` followed by `len` bytes. `str16`: `u16 len` followed by
  `len` bytes. These are shorter than SSH's `u32` string prefix, to save space.
- `sigblob`: an SSH signature blob as defined for userauth (RFC 4253 §6.6,
  `string alg || string sig`, plus the flags and counter fields for `sk-*`),
  carried as a `str16`.
- `key_fp(K)`: `SHA-256(K)`, where `K` is the public key blob in SSH wire
  format (the same input as an OpenSSH `SHA256:` fingerprint).
- `H`: SHA-256.
- Maximum datagram size: **1232 bytes** (IPv6 minimum MTU 1280 − 40 − 8). A
  knock that would exceed this cannot be sent. This rules out RSA keys larger
  than 4096 bits.

### 2.1 Signed data (domain separation)

Every signature in this protocol covers an SSHSIG-style wrapper (OpenSSH
`PROTOCOL.sshsig`), not the raw message:

```
byte[6]  "SSHSIG"
string   namespace          (u32-length SSH string)
string   ""                 (reserved)
string   "sha512"
string   SHA-512(message)
```

This is exactly what `ssh-keygen -Y sign` produces before signing, so any
ssh-agent can sign it. SSH userauth signed data starts with
`string session_id`, so it can never collide with this wrapper. Only the
`sigblob` is sent on the wire, never the full SSHSIG envelope (that envelope
embeds the public key).

| Use        | Namespace               | Signer          |
|------------|-------------------------|-----------------|
| sig1       | `knock-id@puressh`      | client user key |
| sig2       | `knock@puressh`         | client user key |
| sig_host   | `knock-accept@puressh`  | server host key |

Allowed signature algorithms: `ssh-ed25519`,
`ecdsa-sha2-nistp{256,384,521}`, `rsa-sha2-256`, `rsa-sha2-512`,
`sk-ssh-ed25519@openssh.com`, and `sk-ecdsa-sha2-nistp256@openssh.com`.
`ssh-rsa` (SHA-1) is not allowed.

## 3. Messages

Every datagram starts with `u8 version = 0x01` and `u8 type`. A receiver
drops any datagram with an unknown version or type, a malformed field, or
trailing bytes.

### 3.1 KNOCK (type `0x01`, client → server UDP)

| Field     | Encoding  | Notes |
|-----------|-----------|-------|
| version   | u8        | `0x01` |
| type      | u8        | `0x01` |
| flags     | u8        | bit0 `NEED_HOSTKEY`; other bits MUST be 0 |
| user      | str8      | login name, UTF-8, 1–64 bytes |
| key_fp    | byte[32]  | `key_fp(client public key)` |
| sig1      | sigblob   | signature over `str8 user ‖ key_fp`, namespace `knock-id@puressh` |
| nonce     | u64       | client wall clock, ms since the Unix epoch |
| eph_c     | byte[32]  | client ephemeral X25519 public key, fresh per knock |
| host_fp   | byte[32]  | `key_fp(expected host key)`, or all zeros if `NEED_HOSTKEY` |
| padding   | str16     | zero bytes, see §3.3 |
| sig2      | sigblob   | signature over every preceding byte of the datagram, namespace `knock@puressh` |

`knock_hash = H(entire KNOCK datagram)`.

**sig1** is a static per-(user, key) token. The client computes it once and
caches it (§6.5), so a FIDO key needs a touch only for sig2.
Deterministic schemes (Ed25519, RSA PKCS#1 v1.5) always produce the same sig1.
Randomized schemes (ECDSA, `sk-*`) produce a different one each time, which the
server handles with a small cache of accepted values (§5.2).

Typical size with an Ed25519 key and an 8-byte username: **288 bytes**. With
RSA-4096: about **1190 bytes**.

### 3.2 ACCEPT (type `0x02`, server → client UDP)

Sent from the same local address and port the KNOCK arrived on, to the KNOCK's
source address and port.

| Field      | Encoding  | Notes |
|------------|-----------|-------|
| version    | u8        | `0x01` |
| type       | u8        | `0x02` |
| flags      | u8        | bit0 `HOSTKEY_FULL` |
| knock_hash | byte[32]  | binds this reply to one KNOCK |
| eph_s      | byte[32]  | server ephemeral X25519 public key |
| port       | u16       | TCP port of the listener |
| window     | u16       | seconds the listener stays open |
| hostkey    | str16     | present only if `HOSTKEY_FULL`: the full host public key blob |
| sig_host   | sigblob   | host-key signature over every preceding byte, namespace `knock-accept@puressh` |

When `HOSTKEY_FULL` is clear, the signing host key is the one the KNOCK
identified with `host_fp`.

### 3.3 Size rule (anti-amplification)

The server MUST NOT send an ACCEPT larger than the KNOCK it answers. If no
eligible host key yields a small enough ACCEPT, it drops the KNOCK.

- If the client knows the host key (normal case), the ACCEPT is small and its
  exact size is predictable: 156 bytes for an Ed25519 host key, 605 bytes for
  RSA-4096. The client MUST pad the KNOCK to at least that size. In practice
  this matters only with an RSA host key, because an Ed25519 KNOCK is 288
  bytes or more.
- If the client sets `NEED_HOSTKEY`, it MUST pad the KNOCK to **1232 bytes**,
  which leaves room for a full RSA-4096 ACCEPT (about 1150 bytes).

## 4. Key derivation and the TCP open token

```
shared  = X25519(eph_c_priv, eph_s)      // reject the all-zero result
prk     = HKDF-Extract(salt = knock_hash, ikm = shared)        // SHA-256
token   = HKDF-Expand(prk, "puressh knock open v1" ‖ eph_s ‖ u16 port, 32)
```

An on-path observer sees both datagrams but cannot compute `token`. An
attacker cannot substitute `eph_c` (it is covered by sig2) or `eph_s` (it is
covered by sig_host, which the client checks against a known or TOFU-accepted
host key).

## 5. Server behaviour

### 5.1 State

The *key table* maps `user → { key_fp → entry }`. It is built from the
authorized keys of users enabled for knock, reloaded when those files change.
Unknown users and keys never allocate state.

Per entry (user, key):

| Field | Purpose |
|-------|---------|
| `pubkey` | for verification |
| `sig1_cache` | accepted sig1 values (LRU, max 4) |
| `newsig1_bucket` | token bucket for verifying a sig1 that is not cached |
| `last_nonce` | highest accepted nonce |
| `last_knock_hash`, `last_accept`, `accept_expiry` | used to resend for retransmitted knocks |
| `knock_buckets` | per source prefix (/32 IPv4, /64 IPv6), LRU max 64 |
| `pending` | listeners currently open |

Global: `verify_bucket` (all public-key verifications) and `nonce_floor`
(§5.3).

### 5.2 Processing order

Every *drop* is silent. Every step is cheaper than the next one.

1. Datagram length is between the minimum and 1232 bytes, version and type
   match, and the strict parse succeeds. Otherwise drop.
2. Look up `user`, then `key_fp`, in the key table. If either is missing, drop.
3. If `|nonce − now| > ClockSkew`, drop.
4. **sig1:** if it is byte-equal to an entry in `sig1_cache`, continue.
   Otherwise take one token from `newsig1_bucket` and one from
   `verify_bucket` (drop if either is empty), verify sig1, add it to the
   cache on success, and drop on failure.
5. **Retransmit:** if `nonce == last_nonce`, `H(datagram) == last_knock_hash`,
   and the stored accept has not expired, take one token from the source
   prefix's knock bucket and resend `last_accept` unchanged. Stop here.
6. If `nonce ≤ last_nonce` or `nonce < nonce_floor`, drop.
7. Take one token from the source prefix's knock bucket and one from
   `verify_bucket`. If either is empty, drop.
8. Verify sig2. On failure, drop.
9. Set `last_nonce = nonce`.
10. If `pending ≥ MaxPending`, drop.
11. Choose the host key: the one matching `host_fp`, or with `NEED_HOSTKEY`
    the server's preferred key (Ed25519 > ECDSA > RSA) that satisfies §3.3.
    If none fits, drop.
12. Generate `eph_s`, open the listener (§5.4), derive `token`, build and sign
    the ACCEPT, store it in `last_accept`, and send it.

Note on malleable signatures (ECDSA): a modified copy of a valid KNOCK hashes
differently, so step 5 does not resend for it and step 6 drops it. An on-path
attacker who races the original can at most get it rejected, which they could
do anyway by dropping it.

### 5.3 Replay protection across restarts

`last_nonce` is either persisted, or `nonce_floor` is set to the process start
time. With the floor, a knock captured before a restart cannot be replayed
after it. The cost is that, during the first `ClockSkew` after a restart, a
client whose clock is behind the server's may have one knock dropped, and its
retransmits recover.

### 5.4 The rendezvous listener

- Bind a TCP socket on the local address the KNOCK was received on (use
  `IP_PKTINFO` / `IPV6_RECVPKTINFO`). The port is 0 (ephemeral) or comes from
  `KnockPorts`.
- The only allowed peer is the KNOCK's source IP (any source port). Close
  other peers immediately with RST (`SO_LINGER 0`); they do not use up the
  listener.
- An allowed peer must send exactly 32 bytes within `TokenTimeout`, and they
  must equal `token` (constant-time comparison). On mismatch, close the
  connection and count a strike. After 3 strikes, close the listener.
- On a match, close the listener (it accepts **exactly one** session),
  decrement `pending`, and hand the socket to the normal SSH server path with
  the knock context `(user, key_fp, host key)`. The server then sends its SSH
  identification string as usual.
- When `window` expires, close the listener and decrement `pending`.
- `KnockBindUser` (default **yes**): SSH userauth must use the knock's `user`.
  `KnockBindKey` (default no): userauth must use the knock's key.
- Implementation choice (fork, thread, or event loop) is not part of the
  protocol. Privilege separation should follow the regular server path.

## 6. Client behaviour

### 6.1 Trigger

Setting `KnockMode`:

- `auto` (default): connect TCP to `host:22` (or the configured port) as
  usual. If that attempt is **refused**, gets ICMP unreachable, or does not
  complete within `KnockFallbackDelay` (default **1500 ms**), start the knock
  (§6.2) to the **same IP**. The TCP attempt keeps running. Whichever path
  first produces a usable connection wins, and the other is abandoned.
- `always`: knock immediately and skip TCP 22. The client may also switch to
  this for a host it has in its knock-hosts cache (§6.5), which skips the
  fallback delay.
- `never`: never knock.

With several resolved addresses, the client knocks each address it falls back
on, following the normal address order.

### 6.2 Sending

- Identities: send one KNOCK per candidate key, all at once, in
  IdentityFile/agent order, up to `KnockMaxIdentities` (default 4). FIDO keys
  are used only if named in `KnockIdentity`, because each knock needs a touch.
  Each KNOCK has its own `eph_c` and nonce.
- `NEED_HOSTKEY` is set, with padding to 1232 bytes, only if `known_hosts`
  has no entry for the host. Otherwise `host_fp` is the known key. If several
  keys are known, use the one the client prefers most.
- Retransmit the **byte-identical** datagram at +500 ms and +1500 ms, and give
  up at +3000 ms. The server's retransmit handling (§5.2 step 5) makes this
  safe whether the knock or the reply was lost.
- If nothing comes back, report the original TCP error. Never say a knock was
  attempted unless running verbose.

### 6.3 Receiving ACCEPT

Ignore any datagram that does not come from the knocked IP and port, does
not parse, has a `knock_hash` that matches none of the outstanding knocks, or
has an invalid `sig_host`. Then:

- **Known host:** the signing key must be the `host_fp` key. Otherwise ignore
  the datagram.
- **Unknown host (`HOSTKEY_FULL`):** the key is new. Connect (§6.4) and let
  the SSH key exchange run the normal TOFU decision, keyed by the **original
  host name and port** (not the rendezvous port). The pin makes that decision
  about the same key that signed the ACCEPT. Because the listener is consumed
  by the connect, the prompt is not limited by `window`.

### 6.4 Connecting

- The TCP connection should leave from the **same local IP** as the knock.
  Kernels choose the same source address for the same destination
  (RFC 6724), so the implementation does not bind explicitly.
- Connect to `knocked IP : port` and send `token` (32 bytes), then run normal
  SSH.
- Restrict the host key algorithms to the one of the ACCEPT key. The host key
  presented in KEX MUST be byte-equal to it; otherwise abort with a host-key
  mismatch error.
- Authenticate fully, as on any SSH connection.

### 6.5 Client caches

- `~/.ssh/puressh/knock_ids`: `(user, key_fp) → sig1`.
- `~/.ssh/puressh/knock_hosts`: hosts that answered a knock, used by `auto`
  to knock immediately next time. Entries expire after 30 days without use.

## 7. Defaults

| Setting | Default |
|---------|---------|
| UDP listen | `*:22` (when knock is enabled) |
| `KnockPorts` | `0` (kernel ephemeral), or a range such as `40000-40999` |
| `ClockSkew` | 30 s |
| `window` | 60 s |
| `TokenTimeout` | 5 s |
| `MaxPending` | 2 per (user, key) |
| knock bucket | burst 5, +1 / 10 s, per (user, key, source prefix) |
| `newsig1_bucket` | burst 3, +1 / 60 s, per (user, key) |
| `verify_bucket` | 1000 / s, global |
| client `KnockFallbackDelay` | 1500 ms |
| client retransmits | +500 ms, +1500 ms, give up at +3000 ms |

## 8. Security considerations

- **Leaked sig1.** sig1 is a bearer token visible on the wire, and it is valid
  on every server where the key is authorized for that user. Anyone who has it
  passes the cheap filter, but each further attempt costs a rate-limited
  verification, and they still cannot forge sig2. To keep the token from
  locking out the real user, rate limits are per source prefix. An attacker
  who can spoof the victim's exact prefix can still exhaust that prefix's
  bucket, but such an attacker is effectively on-path and could drop the
  victim's packets anyway.
- **Address binding.** The client cannot sign its own address because of NAT.
  The listener therefore relies on the source-IP check plus the DH token. An
  on-path observer can read the port but cannot complete the token step, and
  cannot take the single-use slot by scanning.
- **Metadata.** `user` and `key_fp` are sent in cleartext, so passive
  observers can link knocks to identities, and the format can be
  fingerprinted. A future version could encrypt the KNOCK to a server static
  key when the client already knows it.
- **Stealth depends on the firewall.** A silent UDP socket looks
  "open|filtered", while closed ports answer with ICMP unreachable. Deploy
  with UDP that is not answered, or that is silently dropped, host-wide.
- **Not a login.** The knock is defence in depth only. SSH authentication and
  host key checking are unchanged and mandatory.
- **Resource bounds.** All per-key state is bounded by the key table.
  Per-prefix buckets are LRU-capped, and listeners are capped per key and
  short-lived.

## 9. Open questions

- **Certificate users.** `key_fp` lookup needs a key table, and
  certificate-authenticated users or `AuthorizedKeysCommand` have no static
  list. Options: a separate knock-key list, or learning keys from successful
  cert logins. v1 only knocks with plain keys.
- **ProxyJump.** Whether a jump host should knock on behalf of the client.
  v1 knocks only on the direct-TCP path; jump hops connect normally.

## 10. Implementation notes (puressh)

Library: `puressh::knock` (feature `knock`, on by default).
`KnockState` is the sans-IO server filter of §5.2, `KnockServer` adds the
sockets (poll-friendly: `poll_fds()`, `next_wakeup()`, `process()`), and
`connect_or_knock` / `connect_or_knock_addrs` implement §6.1. On the client,
`KnockAccepted::pin` sets `client::Config::pinned_host_key`, which both
restricts the advertised host-key algorithms and makes KEX fail unless the
server presents exactly that key.

Differences from the text above:

- `sk-*` keys are part of the protocol but puressh has no FIDO support yet,
  so neither side can use them.
- The rendezvous listener binds to the knock socket's own address (the
  wildcard if the socket is bound to the wildcard), not to the specific
  destination address of the knock (that would need `IP_PKTINFO`, which
  `std` does not expose). The peer-IP check of §5.4 is unchanged.
- The knock goes to the UDP port with the same number as the SSH TCP port
  unless `KnockPort` says otherwise.

### `sshd`

Global-only `sshd_config` keywords (refused inside `Match`):

| Keyword | Meaning |
|---------|---------|
| `KnockListen addr[:port]` | UDP address to listen on (repeatable). Port defaults to `Port`. Enables knock. |
| `KnockUsers user…` | Users allowed to knock (repeatable). Required with `KnockListen`. |
| `KnockPorts lo-hi` | Rendezvous TCP port range (default: kernel ephemeral). |
| `KnockWindow secs` | Rendezvous listener lifetime (default 60). |
| `KnockClockSkew secs` | Accepted client clock offset (default 30). |
| `KnockMaxPending n` | Open listeners per (user, key) (default 2). |

The key table is each knock user's plain keys from `AuthorizedKeysFile` (or
the global `-A` file). It is read as root at startup and every 60 s
afterwards. A knocked connection may only authenticate as the knock's user
(`KnockBindUser` is always on). It goes through the same `MaxStartups` /
per-source limits and the same forked-child path as any other connection.

To actually hide the server, keep TCP `Port` off the public interface
(`ListenAddress 127.0.0.1`, or a firewall that drops it), drop or ignore
other UDP, and open `KnockPorts` in the firewall.

### `ssh`

| `ssh_config` keyword | Meaning |
|----------------------|---------|
| `KnockMode no\|auto\|always` | Default `auto` (§6.1). |
| `KnockFallbackDelay ms` | Default 1500. |
| `KnockPort port` | UDP port to knock (default: the SSH port). |

Up to four plain publickey identities (agent and `IdentityFile`, in offer
order) knock at once. The caches of §6.5 live in `~/.ssh/puressh/` (mode
0600). A host in `knock_hosts` gets its knock sent immediately, alongside the
TCP attempt. `-v` reports `knock: accepted, rendezvous at …`.
