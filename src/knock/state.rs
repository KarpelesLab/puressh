//! Sans-IO server half of the knock protocol (`docs/knock.md` §5.1–§5.3).
//!
//! [`KnockState`] takes one datagram plus the current time and source address
//! and answers with a [`Verdict`]; it never touches a socket. Opening the
//! rendezvous listener is left to the caller (see
//! [`KnockServer`](super::KnockServer)), which then calls
//! [`KnockState::complete`] with the bound port to sign the ACCEPT.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;
use std::collections::HashMap;
use std::sync::Arc;

use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::rng::OsRng;
use purecrypto::zeroize::Zeroizing;

use super::wire::{self, Knock};
use crate::error::{Error, Result};
use crate::hostkey::HostKey;

/// Tunables of the server side. Defaults follow `docs/knock.md` §7.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KnockServerConfig {
    /// Largest accepted `|nonce − now|`, in ms.
    pub clock_skew_ms: u64,
    /// Seconds a rendezvous listener stays open.
    pub window_secs: u16,
    /// Seconds an accepted rendezvous connection has to send its token.
    pub token_timeout_secs: u16,
    /// Open rendezvous listeners allowed per (user, key).
    pub max_pending: u32,
    /// Knock bucket per (user, key, source prefix): burst size.
    pub knock_burst: u32,
    /// Knock bucket: ms per refilled token.
    pub knock_refill_ms: u64,
    /// Uncached-sig1 bucket per (user, key): burst size.
    pub newsig1_burst: u32,
    /// Uncached-sig1 bucket: ms per refilled token.
    pub newsig1_refill_ms: u64,
    /// Global public-key verifications per second.
    pub verify_per_sec: u32,
    /// Source prefixes tracked per (user, key) before LRU eviction. Once
    /// full, a new prefix evicts the least recently used one that never sent
    /// a valid knock (if any) and starts with a near-empty bucket, so
    /// rotating (spoofed) source addresses earns no fresh bursts.
    pub max_prefixes_per_key: usize,
    /// sig2 verifications per (user, key) for knocks from source prefixes
    /// that have not yet sent a valid knock for it: burst size. Bounds the
    /// share of [`Self::verify_per_sec`] one leaked sig1 can consume,
    /// whatever source addresses it is sent from.
    pub newprefix_burst: u32,
    /// New-prefix sig2 bucket: ms per refilled token.
    pub newprefix_refill_ms: u64,
    /// Accepted sig1 values cached per (user, key).
    pub sig1_cache_size: usize,
    /// How long a user's keys from the [`KnockKeySource`] are reused before
    /// the next knock for that user asks again, in ms. Covers users with no
    /// keys too.
    pub key_cache_ttl_ms: u64,
    /// Users whose keys are cached at once. When full, users without keys
    /// are evicted first (oldest first), then the oldest user with keys.
    pub key_cache_users: usize,
    /// Key-source lookups per second, globally (also the burst). A knock
    /// that needs a lookup beyond it is dropped, or served from an expired
    /// cache entry if there is one. Bounds the disk / passwd work a flood of
    /// made-up user names can cause.
    pub key_lookups_per_sec: u32,
    /// Key-source lookups per source prefix (/32 IPv4, /64 IPv6): burst
    /// size. Checked before the global limit, so one source cannot drain it.
    pub key_lookups_prefix_burst: u32,
    /// Per-prefix lookup bucket: ms per refilled token.
    pub key_lookups_prefix_refill_ms: u64,
    /// Source prefixes tracked for the per-prefix lookup limit before LRU
    /// eviction (a new prefix then starts with a single token).
    pub key_lookup_prefixes: usize,
}

impl Default for KnockServerConfig {
    fn default() -> Self {
        Self {
            clock_skew_ms: 30_000,
            window_secs: 60,
            token_timeout_secs: 5,
            max_pending: 2,
            knock_burst: 5,
            knock_refill_ms: 10_000,
            newsig1_burst: 3,
            newsig1_refill_ms: 60_000,
            verify_per_sec: 1000,
            max_prefixes_per_key: 64,
            newprefix_burst: 10,
            newprefix_refill_ms: 1000,
            sig1_cache_size: 4,
            key_cache_ttl_ms: 60_000,
            key_cache_users: 4096,
            key_lookups_per_sec: 50,
            key_lookups_prefix_burst: 10,
            key_lookups_prefix_refill_ms: 200,
            key_lookup_prefixes: 1024,
        }
    }
}

/// Where [`KnockState`] gets the public keys a user may knock with.
///
/// Queried lazily: only when a well-formed, in-time KNOCK names `user`, and
/// at most once per user per [`KnockServerConfig::key_cache_ttl_ms`]
/// (an empty answer is cached the same way). An implementation reading
/// `authorized_keys` files should refuse users it does not serve without
/// touching the disk, since the user name comes from an unauthenticated
/// datagram.
pub trait KnockKeySource: Send {
    /// SSH wire blobs of the plain public keys `user` may knock with.
    /// Unsupported key types and certificates are ignored.
    fn keys_for(&mut self, user: &str) -> Vec<Vec<u8>>;

    /// Cheap pre-check, asked before a lookup is charged to the lookup rate
    /// limits: `false` means `user` can never knock (not a configured or
    /// existing user), so the knock is dropped without calling
    /// [`Self::keys_for`] and without caching anything. It is called for
    /// every knock naming a user whose keys are not cached, so it should be
    /// much cheaper than `keys_for`. The default admits everyone.
    fn may_knock(&self, user: &str) -> bool {
        let _ = user;
        true
    }
}

/// The users and public keys allowed to knock: `user → {key_fp → key blob}`.
/// A static [`KnockKeySource`].
#[derive(Debug, Clone, Default)]
pub struct KnockKeyTable {
    users: HashMap<String, HashMap<[u8; 32], Vec<u8>>>,
}

impl KnockKeyTable {
    /// Empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow `user` to knock with the public key `key_blob` (SSH wire
    /// format). Certificates and unsupported key types are ignored; returns
    /// whether the key was added.
    pub fn insert(&mut self, user: &str, key_blob: Vec<u8>) -> bool {
        if user.is_empty() || user.len() > wire::MAX_USER_LEN {
            return false;
        }
        if wire::max_sig_blob_len(&key_blob).is_none() {
            return false;
        }
        self.users
            .entry(user.to_string())
            .or_default()
            .insert(wire::key_fp(&key_blob), key_blob);
        true
    }

    /// Number of (user, key) pairs.
    pub fn len(&self) -> usize {
        self.users.values().map(|k| k.len()).sum()
    }

    /// `true` when no key is allowed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl KnockKeySource for KnockKeyTable {
    fn keys_for(&mut self, user: &str) -> Vec<Vec<u8>> {
        self.users
            .get(user)
            .map(|k| k.values().cloned().collect())
            .unwrap_or_default()
    }

    fn may_knock(&self, user: &str) -> bool {
        self.users.contains_key(user)
    }
}

/// One user's keys as last returned by the [`KnockKeySource`].
struct CachedKeys {
    loaded_ms: u64,
    keys: HashMap<[u8; 32], Vec<u8>>,
}

/// Token bucket with integer millisecond refill.
#[derive(Debug, Clone)]
struct Bucket {
    tokens: u32,
    burst: u32,
    refill_ms: u64,
    last_ms: u64,
}

impl Bucket {
    fn new(burst: u32, refill_ms: u64, now_ms: u64) -> Self {
        Self {
            tokens: burst,
            burst,
            refill_ms: refill_ms.max(1),
            last_ms: now_ms,
        }
    }

    /// Like [`Self::new`] but starting with at most `tokens` tokens.
    fn with_tokens(burst: u32, refill_ms: u64, now_ms: u64, tokens: u32) -> Self {
        let mut b = Self::new(burst, refill_ms, now_ms);
        b.tokens = tokens.min(burst);
        b
    }

    fn take(&mut self, now_ms: u64) -> bool {
        if now_ms > self.last_ms {
            let gained = (now_ms - self.last_ms) / self.refill_ms;
            if gained > 0 {
                self.tokens = (self.tokens as u64 + gained).min(self.burst as u64) as u32;
                self.last_ms += gained * self.refill_ms;
            }
            if self.tokens == self.burst {
                self.last_ms = now_ms;
            }
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Source prefix used for rate limiting: /32 for IPv4, /64 for IPv6.
fn source_prefix(ip: IpAddr) -> [u8; 8] {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [4, 0, 0, 0, o[0], o[1], o[2], o[3]]
        }
        IpAddr::V6(v6) => {
            let mut p = [0u8; 8];
            p.copy_from_slice(&v6.octets()[..8]);
            p
        }
    }
}

/// Knock bucket of one source prefix of a (user, key).
#[derive(Debug)]
struct PrefixSlot {
    prefix: [u8; 8],
    bucket: Bucket,
    last_used: u64,
    /// A knock from this prefix passed sig2: exempt from the new-prefix
    /// bucket, and evicted last.
    good: bool,
}

#[derive(Debug)]
struct Entry {
    sig1_cache: Vec<Vec<u8>>,
    newsig1: Bucket,
    /// sig2 verifications for knocks from prefixes that are not `good`.
    newprefix: Bucket,
    last_nonce: u64,
    last_knock_hash: [u8; 32],
    last_accept: Option<(Vec<u8>, u64)>,
    /// LRU by last use, slots that are not `good` evicted first.
    knock_buckets: Vec<PrefixSlot>,
    pending: u32,
}

/// Why a datagram was dropped. Never sent on the wire; for debug logs only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropReason {
    /// Not a well-formed KNOCK.
    Malformed,
    /// User or key not in the table.
    UnknownKey,
    /// Nonce outside the clock-skew window.
    Clock,
    /// sig1 failed verification.
    BadSig1,
    /// sig2 failed verification.
    BadSig2,
    /// Nonce not newer than the last accepted one.
    Replay,
    /// A rate limit bucket was empty.
    RateLimited,
    /// Too many open rendezvous listeners for this key.
    TooManyPending,
    /// No host key yields an ACCEPT that fits the size rule.
    NoHostKey,
}

/// Outcome of [`KnockState::handle`].
#[derive(Debug)]
pub enum Verdict {
    /// Silently drop the datagram.
    Drop(DropReason),
    /// Retransmitted KNOCK: send these bytes (the cached ACCEPT) back.
    Resend(Vec<u8>),
    /// Valid KNOCK: open a listener, then call [`KnockState::complete`].
    Accept(PendingAccept),
}

/// A validated KNOCK waiting for its rendezvous listener.
#[derive(Debug)]
pub struct PendingAccept {
    /// Login name from the KNOCK.
    pub user: String,
    /// Fingerprint of the client key.
    pub key_fp: [u8; 32],
    /// Hash of the KNOCK datagram.
    pub knock_hash: [u8; 32],
    /// Index into the state's host keys of the key that will sign.
    host_key: usize,
    full_hostkey: bool,
    eph_c: [u8; 32],
    knock_len: usize,
}

/// Result of [`KnockState::complete`].
pub struct CompletedAccept {
    /// ACCEPT datagram to send to the knock's source.
    pub datagram: Vec<u8>,
    /// Open token the rendezvous peer must send.
    pub token: Zeroizing<[u8; 32]>,
    /// Wire blob of the host key that signed the ACCEPT; the SSH session on
    /// the rendezvous connection must present this key.
    pub host_key_blob: Vec<u8>,
}

impl core::fmt::Debug for CompletedAccept {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompletedAccept")
            .field("datagram_len", &self.datagram.len())
            .finish_non_exhaustive()
    }
}

/// A host key usable to sign ACCEPTs.
pub type KnockHostKey = Arc<dyn HostKey + Send + Sync>;

/// Server knock state: key source and cache, per-key replay / rate-limit
/// state, host keys.
pub struct KnockState {
    cfg: KnockServerConfig,
    source: Box<dyn KnockKeySource>,
    key_cache: HashMap<String, CachedKeys>,
    entries: HashMap<(String, [u8; 32]), Entry>,
    host_keys: Vec<(KnockHostKey, Vec<u8>, [u8; 32])>,
    verify: Bucket,
    lookups: Bucket,
    /// Per-source-prefix lookup buckets: prefix → (bucket, last use).
    prefix_lookups: HashMap<[u8; 8], (Bucket, u64)>,
    nonce_floor: u64,
}

fn host_key_rank(blob: &[u8]) -> u8 {
    match crate::format::Reader::new(blob).read_string() {
        Ok(b"ssh-ed25519") => 0,
        Ok(n) if n.starts_with(b"ecdsa-") => 1,
        _ => 2,
    }
}

impl KnockState {
    /// Build the state. `now_ms` (wall clock, ms since the Unix epoch) is
    /// the nonce floor: knocks made before this instant are refused, so a
    /// knock captured before a restart cannot be replayed after it.
    pub fn new(
        cfg: KnockServerConfig,
        source: impl KnockKeySource + 'static,
        host_keys: Vec<KnockHostKey>,
        now_ms: u64,
    ) -> Self {
        let mut hk: Vec<_> = host_keys
            .into_iter()
            .filter_map(|k| {
                let blob = k.public_blob();
                wire::max_sig_blob_len(&blob)?;
                let fp = wire::key_fp(&blob);
                Some((k, blob, fp))
            })
            .collect();
        hk.sort_by_key(|(_, blob, _)| host_key_rank(blob));
        let verify = Bucket::new(
            cfg.verify_per_sec.max(1),
            (1000 / cfg.verify_per_sec.max(1) as u64).max(1),
            now_ms,
        );
        let lookups = Bucket::new(
            cfg.key_lookups_per_sec.max(1),
            (1000 / cfg.key_lookups_per_sec.max(1) as u64).max(1),
            now_ms,
        );
        Self {
            cfg,
            source: Box::new(source),
            key_cache: HashMap::new(),
            entries: HashMap::new(),
            host_keys: hk,
            verify,
            lookups,
            prefix_lookups: HashMap::new(),
            nonce_floor: now_ms,
        }
    }

    /// The configuration in force.
    pub fn config(&self) -> &KnockServerConfig {
        &self.cfg
    }

    /// Replace the key source. Cached keys are forgotten, so the next knock
    /// for each user asks the new source; replay and rate-limit state of
    /// keys the new source still returns is kept.
    pub fn set_key_source(&mut self, source: impl KnockKeySource + 'static) {
        self.source = Box::new(source);
        self.key_cache.clear();
    }

    /// Forget the cached keys of `user` (all users if `None`), so the next
    /// knock asks the source again.
    pub fn invalidate_keys(&mut self, user: Option<&str>) {
        match user {
            Some(u) => {
                self.key_cache.remove(u);
            }
            None => self.key_cache.clear(),
        }
    }

    /// Make sure `user`'s keys are cached and fresh, asking the source if
    /// not. Drops per-key state of keys the source no longer returns.
    /// Returns `false` when a lookup was needed but a lookup rate limit (per
    /// source prefix, then global) refused it and no expired entry is left
    /// to fall back on. A user the source's
    /// [`may_knock`](KnockKeySource::may_knock) refuses costs no lookup
    /// token and is not cached.
    fn load_user_keys(&mut self, user: &str, src: IpAddr, now_ms: u64) -> bool {
        let ttl = self.cfg.key_cache_ttl_ms;
        if let Some(c) = self.key_cache.get(user)
            && now_ms >= c.loaded_ms
            && now_ms - c.loaded_ms < ttl
        {
            return true;
        }
        if !self.source.may_knock(user) {
            if self.key_cache.remove(user).is_some() {
                self.entries.retain(|(u, _), _| u != user);
            }
            return true;
        }
        let cached = self.key_cache.contains_key(user);
        if !self.take_prefix_lookup(src, now_ms) || !self.lookups.take(now_ms) {
            return cached;
        }
        if !cached && self.key_cache.len() >= self.cfg.key_cache_users.max(1) {
            // Made-up names cost an entry each; evict those before real users.
            let victim = self
                .key_cache
                .iter()
                .min_by_key(|(_, c)| (!c.keys.is_empty(), c.loaded_ms))
                .map(|(u, _)| u.clone());
            if let Some(v) = victim {
                self.key_cache.remove(&v);
            }
        }
        let keys: HashMap<[u8; 32], Vec<u8>> = self
            .source
            .keys_for(user)
            .into_iter()
            .filter(|b| wire::max_sig_blob_len(b).is_some())
            .map(|b| (wire::key_fp(&b), b))
            .collect();
        self.entries
            .retain(|(u, fp), _| u != user || keys.contains_key(fp));
        self.key_cache.insert(
            user.to_string(),
            CachedKeys {
                loaded_ms: now_ms,
                keys,
            },
        );
        true
    }

    /// One token from the lookup bucket of `src`'s prefix.
    fn take_prefix_lookup(&mut self, src: IpAddr, now_ms: u64) -> bool {
        let prefix = source_prefix(src);
        let cfg = &self.cfg;
        let (bucket, used) = match self.prefix_lookups.get_mut(&prefix) {
            Some(slot) => slot,
            None => {
                let mut tokens = cfg.key_lookups_prefix_burst;
                if self.prefix_lookups.len() >= cfg.key_lookup_prefixes.max(1) {
                    let lru = self
                        .prefix_lookups
                        .iter()
                        .min_by_key(|(_, (_, used))| *used)
                        .map(|(p, _)| *p);
                    if let Some(p) = lru {
                        self.prefix_lookups.remove(&p);
                    }
                    // A full table means many sources: no fresh burst each.
                    tokens = 1;
                }
                let b = Bucket::with_tokens(
                    cfg.key_lookups_prefix_burst,
                    cfg.key_lookups_prefix_refill_ms,
                    now_ms,
                    tokens,
                );
                self.prefix_lookups.entry(prefix).or_insert((b, now_ms))
            }
        };
        *used = now_ms;
        bucket.take(now_ms)
    }

    /// A rendezvous listener of (user, key) closed, by use or expiry — or a
    /// [`Verdict::Accept`] was abandoned before [`Self::complete`].
    pub fn release_pending(&mut self, user: &str, key_fp: &[u8; 32]) {
        if let Some(e) = self.entries.get_mut(&(user.to_string(), *key_fp)) {
            e.pending = e.pending.saturating_sub(1);
        }
    }

    /// Process one datagram received at `now_ms` from `src`.
    pub fn handle(&mut self, now_ms: u64, src: IpAddr, datagram: &[u8]) -> Verdict {
        // 1. strict parse
        let Ok(k) = Knock::parse(datagram) else {
            return Verdict::Drop(DropReason::Malformed);
        };
        // 2. clock window (before the key lookup, which may touch the disk)
        if k.nonce.abs_diff(now_ms) > self.cfg.clock_skew_ms {
            return Verdict::Drop(DropReason::Clock);
        }
        // 3. user's keys, loaded lazily and cached
        if !self.load_user_keys(k.user, src, now_ms) {
            return Verdict::Drop(DropReason::RateLimited);
        }
        let Some(key_blob) = self
            .key_cache
            .get(k.user)
            .and_then(|c| c.keys.get(&k.key_fp))
        else {
            return Verdict::Drop(DropReason::UnknownKey);
        };
        let cfg = &self.cfg;
        let entry = self
            .entries
            .entry((k.user.to_string(), k.key_fp))
            .or_insert_with(|| Entry {
                sig1_cache: Vec::new(),
                newsig1: Bucket::new(cfg.newsig1_burst, cfg.newsig1_refill_ms, now_ms),
                newprefix: Bucket::new(cfg.newprefix_burst, cfg.newprefix_refill_ms, now_ms),
                last_nonce: 0,
                last_knock_hash: [0u8; 32],
                last_accept: None,
                knock_buckets: Vec::new(),
                pending: 0,
            });
        // 4. sig1: byte compare against the cache, verify only on a miss
        if let Some(pos) = entry.sig1_cache.iter().position(|s| s == k.sig1) {
            let hit = entry.sig1_cache.remove(pos);
            entry.sig1_cache.insert(0, hit);
        } else {
            if !entry.newsig1.take(now_ms) || !self.verify.take(now_ms) {
                return Verdict::Drop(DropReason::RateLimited);
            }
            let msg = wire::knock_id_message(k.user, &k.key_fp);
            if wire::verify(key_blob, wire::NS_KNOCK_ID, &msg, k.sig1).is_err() {
                return Verdict::Drop(DropReason::BadSig1);
            }
            entry.sig1_cache.insert(0, k.sig1.to_vec());
            entry.sig1_cache.truncate(self.cfg.sig1_cache_size.max(1));
        }
        let hash = wire::knock_hash(datagram);
        // 5. retransmitted knock → resend the cached ACCEPT
        if k.nonce == entry.last_nonce && hash == entry.last_knock_hash {
            if let Some((accept, expiry)) = &entry.last_accept
                && now_ms < *expiry
            {
                let accept = accept.clone();
                if !Self::take_knock_bucket(&self.cfg, entry, src, now_ms).0 {
                    return Verdict::Drop(DropReason::RateLimited);
                }
                return Verdict::Resend(accept);
            }
            return Verdict::Drop(DropReason::Replay);
        }
        // 6. freshness
        if k.nonce <= entry.last_nonce || k.nonce < self.nonce_floor {
            return Verdict::Drop(DropReason::Replay);
        }
        // 7. rate limits: the prefix's bucket, then the key's new-prefix
        // bucket unless this prefix already sent a valid knock, then global
        let (ok, slot) = Self::take_knock_bucket(&self.cfg, entry, src, now_ms);
        let good = entry.knock_buckets[slot].good;
        if !ok || (!good && !entry.newprefix.take(now_ms)) || !self.verify.take(now_ms) {
            return Verdict::Drop(DropReason::RateLimited);
        }
        // 8. sig2
        if wire::verify(key_blob, wire::NS_KNOCK, k.signed, k.sig2).is_err() {
            return Verdict::Drop(DropReason::BadSig2);
        }
        entry.knock_buckets[slot].good = true;
        // 9. consume the nonce
        entry.last_nonce = k.nonce;
        entry.last_knock_hash = hash;
        entry.last_accept = None;
        // 10. pending cap
        if entry.pending >= self.cfg.max_pending {
            return Verdict::Drop(DropReason::TooManyPending);
        }
        // 11. host key selection under the size rule
        let need_full = k.flags & wire::FLAG_NEED_HOSTKEY != 0;
        let fits = |blob: &[u8]| {
            wire::accept_len_bound(blob, need_full).is_some_and(|n| n <= datagram.len())
        };
        let chosen = if need_full {
            self.host_keys.iter().position(|(_, blob, _)| fits(blob))
        } else {
            self.host_keys
                .iter()
                .position(|(_, blob, fp)| *fp == k.host_fp && fits(blob))
        };
        let Some(host_key) = chosen else {
            return Verdict::Drop(DropReason::NoHostKey);
        };
        entry.pending += 1;
        Verdict::Accept(PendingAccept {
            user: k.user.to_string(),
            key_fp: k.key_fp,
            knock_hash: hash,
            host_key,
            full_hostkey: need_full,
            eph_c: k.eph_c,
            knock_len: datagram.len(),
        })
    }

    /// One token from the knock bucket of `src`'s prefix, and the index of
    /// that prefix's slot.
    fn take_knock_bucket(
        cfg: &KnockServerConfig,
        e: &mut Entry,
        src: IpAddr,
        now_ms: u64,
    ) -> (bool, usize) {
        let prefix = source_prefix(src);
        let idx = match e.knock_buckets.iter().position(|s| s.prefix == prefix) {
            Some(i) => i,
            None => {
                let mut tokens = cfg.knock_burst;
                if e.knock_buckets.len() >= cfg.max_prefixes_per_key.max(1) {
                    let lru = e
                        .knock_buckets
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, s)| (s.good, s.last_used))
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    e.knock_buckets.swap_remove(lru);
                    // A full table means many sources: no fresh burst each,
                    // just enough for one knock and a retransmit.
                    tokens = 2;
                }
                e.knock_buckets.push(PrefixSlot {
                    prefix,
                    bucket: Bucket::with_tokens(
                        cfg.knock_burst,
                        cfg.knock_refill_ms,
                        now_ms,
                        tokens,
                    ),
                    last_used: now_ms,
                    good: false,
                });
                e.knock_buckets.len() - 1
            }
        };
        let slot = &mut e.knock_buckets[idx];
        slot.last_used = now_ms;
        (slot.bucket.take(now_ms), idx)
    }

    /// Finish an [`Verdict::Accept`]: the caller has bound a listener on
    /// `port`. Generates the server ephemeral, signs the ACCEPT, derives the
    /// open token and caches the ACCEPT for retransmits.
    ///
    /// On error the pending slot is released.
    pub fn complete(
        &mut self,
        pending: &PendingAccept,
        port: u16,
        now_ms: u64,
    ) -> Result<CompletedAccept> {
        let res = self.complete_inner(pending, port, now_ms);
        if res.is_err() {
            self.release_pending(&pending.user, &pending.key_fp);
        }
        res
    }

    fn complete_inner(
        &mut self,
        pending: &PendingAccept,
        port: u16,
        now_ms: u64,
    ) -> Result<CompletedAccept> {
        let (host_key, blob, _) = self
            .host_keys
            .get(pending.host_key)
            .ok_or(Error::Config("knock: host key index"))?;
        let eph = X25519PrivateKey::generate(&mut OsRng);
        let eph_s = eph.public_key();
        let shared = Zeroizing::new(
            eph.diffie_hellman(&pending.eph_c)
                .map_err(|_| Error::Crypto("knock: small-order client ephemeral"))?,
        );
        let window = self.cfg.window_secs.max(1);
        let datagram = wire::build_accept(
            host_key.as_ref(),
            &pending.knock_hash,
            &eph_s,
            port,
            window,
            pending.full_hostkey,
        )?;
        if datagram.len() > pending.knock_len {
            return Err(Error::Protocol("knock: ACCEPT larger than KNOCK"));
        }
        let token = wire::open_token(&shared, &pending.knock_hash, &eph_s, port);
        if let Some(e) = self
            .entries
            .get_mut(&(pending.user.clone(), pending.key_fp))
            && e.last_knock_hash == pending.knock_hash
        {
            e.last_accept = Some((datagram.clone(), now_ms + window as u64 * 1000));
        }
        Ok(CompletedAccept {
            datagram,
            token,
            host_key_blob: blob.clone(),
        })
    }
}

impl core::fmt::Debug for KnockState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KnockState")
            .field("cached_users", &self.key_cache.len())
            .field("host_keys", &self.host_keys.len())
            .finish_non_exhaustive()
    }
}
