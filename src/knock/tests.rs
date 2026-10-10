use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::rng::{OsRng, RngCore};

use super::wire::{self, Accept, Knock, KnockFields, MAX_DATAGRAM};
use super::*;
use crate::hostkey::{Ed25519HostKey, HostKey};

const NOW: u64 = 1_800_000_000_000;
const USER: &str = "alice";

fn ed25519() -> Ed25519HostKey {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    Ed25519HostKey::from_seed(seed)
}

fn fixture(name: &str) -> Box<dyn HostKey + Send + Sync> {
    let path = format!("{}/tests/fixtures/cert/{name}", env!("CARGO_MANIFEST_DIR"));
    let pem = std::fs::read_to_string(&path).unwrap();
    crate::key::PrivateKey::parse_openssh_pem(&pem, None)
        .unwrap()
        .into_host_key_sync()
        .unwrap()
}

fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

struct Fixture {
    state: KnockState,
    user_key: Box<dyn HostKey + Send + Sync>,
    host_blob: Vec<u8>,
}

fn setup_with(
    cfg: KnockServerConfig,
    user_key: Box<dyn HostKey + Send + Sync>,
    host: KnockHostKey,
) -> Fixture {
    let mut table = KnockKeyTable::new();
    assert!(table.insert(USER, user_key.public_blob()));
    let host_blob = host.public_blob();
    Fixture {
        state: KnockState::new(cfg, table, vec![host], NOW - 60_000),
        user_key,
        host_blob,
    }
}

fn setup() -> Fixture {
    setup_with(
        KnockServerConfig::default(),
        Box::new(ed25519()),
        Arc::new(ed25519()),
    )
}

fn sig1(key: &dyn HostKey, user: &str) -> Vec<u8> {
    let fp = wire::key_fp(&key.public_blob());
    wire::sign(key, wire::NS_KNOCK_ID, &wire::knock_id_message(user, &fp)).unwrap()
}

fn make_knock(
    key: &dyn HostKey,
    user: &str,
    nonce: u64,
    host_fp: Option<[u8; 32]>,
    min_len: usize,
) -> (Vec<u8>, X25519PrivateKey) {
    let eph = X25519PrivateKey::generate(&mut OsRng);
    let s1 = sig1(key, user);
    let d = KnockFields {
        user,
        key_fp: wire::key_fp(&key.public_blob()),
        sig1: &s1,
        nonce,
        eph_c: eph.public_key(),
        host_fp,
    }
    .build(key, min_len)
    .unwrap();
    (d, eph)
}

impl Fixture {
    fn knock(&self, nonce: u64) -> Vec<u8> {
        let fp = wire::key_fp(&self.host_blob);
        make_knock(self.user_key.as_ref(), USER, nonce, Some(fp), 0).0
    }
}

fn expect_accept(v: Verdict) -> PendingAccept {
    match v {
        Verdict::Accept(p) => p,
        other => panic!("expected Accept, got {other:?}"),
    }
}

fn expect_drop(v: Verdict, reason: DropReason) {
    match v {
        Verdict::Drop(r) => assert_eq!(r, reason),
        other => panic!("expected Drop({reason:?}), got {other:?}"),
    }
}

#[test]
fn knock_roundtrip_parses() {
    let f = setup();
    let d = f.knock(NOW);
    let k = Knock::parse(&d).unwrap();
    assert_eq!(k.user, USER);
    assert_eq!(k.nonce, NOW);
    assert_eq!(k.key_fp, wire::key_fp(&f.user_key.public_blob()));
    assert_eq!(k.host_fp, wire::key_fp(&f.host_blob));
    assert_eq!(k.flags, 0);
    // Ed25519 knock, 5-byte user: 3 + 6 + 32 + 85 + 8 + 32 + 32 + 2 + 85.
    assert_eq!(d.len(), 285);
}

#[test]
fn parse_rejects_malformed() {
    let f = setup();
    let d = f.knock(NOW);
    let mut trailing = d.clone();
    trailing.push(0);
    assert!(Knock::parse(&trailing).is_err());
    let mut flags = d.clone();
    flags[2] = 0x80;
    assert!(Knock::parse(&flags).is_err());
    let mut version = d.clone();
    version[0] = 2;
    assert!(Knock::parse(&version).is_err());
    assert!(Knock::parse(&d[..d.len() - 1]).is_err());
    // Non-zero padding.
    let (padded, _) = make_knock(f.user_key.as_ref(), USER, NOW, None, 600);
    let k = Knock::parse(&padded).unwrap();
    let pad_at = k.signed.len() - 1;
    let mut bad = padded.clone();
    bad[pad_at] = 1;
    assert!(Knock::parse(&bad).is_err());
}

#[test]
fn valid_knock_is_accepted_and_tokens_agree() {
    let mut f = setup();
    let fp = wire::key_fp(&f.host_blob);
    let (d, eph) = make_knock(f.user_key.as_ref(), USER, NOW, Some(fp), 0);
    let p = expect_accept(f.state.handle(NOW, ip(1), &d));
    assert_eq!(p.user, USER);
    let done = f.state.complete(&p, 40_000, NOW).unwrap();
    assert!(done.datagram.len() <= d.len(), "anti-amplification");
    assert_eq!(done.host_key_blob, f.host_blob);

    let a = Accept::parse(&done.datagram).unwrap();
    assert_eq!(a.knock_hash, wire::knock_hash(&d));
    assert_eq!(a.port, 40_000);
    assert_eq!(a.window, 60);
    assert!(a.hostkey.is_none());
    wire::verify(&f.host_blob, wire::NS_ACCEPT, a.signed, a.sig_host).unwrap();
    // A signature under another namespace must not verify.
    assert!(wire::verify(&f.host_blob, wire::NS_KNOCK, a.signed, a.sig_host).is_err());

    let shared = eph.diffie_hellman(&a.eph_s).unwrap();
    let token = wire::open_token(&shared, &a.knock_hash, &a.eph_s, a.port);
    assert_eq!(*token, *done.token);
}

#[test]
fn retransmit_resends_cached_accept_and_replay_is_dropped() {
    let mut f = setup();
    let d = f.knock(NOW);
    // Before the ACCEPT exists, a duplicate is a plain replay.
    let p = expect_accept(f.state.handle(NOW, ip(1), &d));
    expect_drop(f.state.handle(NOW + 1, ip(1), &d), DropReason::Replay);
    let done = f.state.complete(&p, 40_001, NOW).unwrap();
    match f.state.handle(NOW + 2, ip(1), &d) {
        Verdict::Resend(b) => assert_eq!(b, done.datagram),
        other => panic!("expected Resend, got {other:?}"),
    }
    // After the window the cached ACCEPT is gone.
    expect_drop(f.state.handle(NOW + 61_000, ip(1), &d), DropReason::Clock);
    // An older nonce never passes.
    let old = f.knock(NOW - 5);
    expect_drop(f.state.handle(NOW + 3, ip(1), &old), DropReason::Replay);
}

#[test]
fn nonce_floor_refuses_pre_restart_knocks() {
    let mut f = setup();
    // The state was built with floor NOW - 60s; this knock predates it but
    // is within the clock-skew window of `now`.
    let d = f.knock(NOW - 61_000);
    expect_drop(f.state.handle(NOW - 50_000, ip(1), &d), DropReason::Replay);
}

#[test]
fn unknown_user_or_key_is_dropped() {
    let mut f = setup();
    let fp = wire::key_fp(&f.host_blob);
    let (d, _) = make_knock(f.user_key.as_ref(), "bob", NOW, Some(fp), 0);
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::UnknownKey);
    let other = ed25519();
    let (d, _) = make_knock(&other, USER, NOW, Some(fp), 0);
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::UnknownKey);
    expect_drop(
        f.state.handle(NOW, ip(1), b"garbage"),
        DropReason::Malformed,
    );
}

#[test]
fn clock_skew_is_enforced() {
    let mut f = setup();
    let d = f.knock(NOW + 31_000);
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::Clock);
    let d = f.knock(NOW + 29_000);
    expect_accept(f.state.handle(NOW, ip(1), &d));
}

#[test]
fn forged_signatures_are_dropped() {
    let mut f = setup();
    let attacker = ed25519();
    let fp = wire::key_fp(&f.host_blob);
    // Attacker knows user + public key but signs with another key.
    let s1 = sig1(&attacker, USER);
    let eph = X25519PrivateKey::generate(&mut OsRng);
    let fields = KnockFields {
        user: USER,
        key_fp: wire::key_fp(&f.user_key.public_blob()),
        sig1: &s1,
        nonce: NOW,
        eph_c: eph.public_key(),
        host_fp: Some(fp),
    };
    let d = fields.build(&attacker, 0).unwrap();
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::BadSig1);

    // Replayed (valid) sig1 with a forged sig2.
    let good = sig1(f.user_key.as_ref(), USER);
    let fields = KnockFields {
        sig1: &good,
        ..fields
    };
    let d = fields.build(&attacker, 0).unwrap();
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::BadSig2);

    // Tampering with any signed field breaks sig2.
    let mut d = f.knock(NOW + 1);
    let k = Knock::parse(&d).unwrap();
    let eph_at = k.signed.len() - 2 - 32 - 32;
    d[eph_at] ^= 1;
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::BadSig2);
}

#[test]
fn uncached_sig1_verification_is_rate_limited() {
    let mut f = setup();
    let attacker = ed25519();
    let fp = wire::key_fp(&f.host_blob);
    let s1 = sig1(&attacker, USER);
    let eph = X25519PrivateKey::generate(&mut OsRng);
    for i in 0..5u64 {
        let d = KnockFields {
            user: USER,
            key_fp: wire::key_fp(&f.user_key.public_blob()),
            sig1: &s1,
            nonce: NOW + i,
            eph_c: eph.public_key(),
            host_fp: Some(fp),
        }
        .build(&attacker, 0)
        .unwrap();
        let expected = if i < 3 {
            DropReason::BadSig1
        } else {
            DropReason::RateLimited
        };
        expect_drop(f.state.handle(NOW, ip(1), &d), expected);
    }
    // The real key's cached sig1 is unaffected once cached... but the
    // bucket is empty, so a first-ever sig1 must wait for a refill.
    let d = f.knock(NOW + 10);
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::RateLimited);
    let d = f.knock(NOW + 60_000);
    expect_accept(f.state.handle(NOW + 60_000, ip(1), &d));
}

#[test]
fn knock_bucket_is_per_source_prefix() {
    let mut f = setup();
    // Warm the sig1 cache so only the knock bucket matters.
    for i in 0..5u64 {
        let d = f.knock(NOW + i);
        let v = f.state.handle(NOW, ip(1), &d);
        if let Verdict::Accept(p) = v {
            f.state.release_pending(&p.user, &p.key_fp);
        } else {
            panic!("knock {i} not accepted: {v:?}");
        }
    }
    let d = f.knock(NOW + 10);
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::RateLimited);
    // Another source still gets through.
    expect_accept(f.state.handle(NOW, ip(2), &d));
}

#[test]
fn pending_listeners_are_capped() {
    let mut f = setup();
    let a = expect_accept(f.state.handle(NOW, ip(1), &f.knock(NOW)));
    expect_accept(f.state.handle(NOW, ip(1), &f.knock(NOW + 1)));
    expect_drop(
        f.state.handle(NOW, ip(1), &f.knock(NOW + 2)),
        DropReason::TooManyPending,
    );
    f.state.release_pending(&a.user, &a.key_fp);
    expect_accept(f.state.handle(NOW, ip(1), &f.knock(NOW + 3)));
}

#[test]
fn need_hostkey_returns_full_key_within_size_rule() {
    let rsa_host: KnockHostKey = Arc::from(fixture("u_rsa"));
    let mut f = setup_with(KnockServerConfig::default(), Box::new(ed25519()), rsa_host);
    // Unpadded: the RSA ACCEPT would amplify, so it is dropped.
    let (d, _) = make_knock(f.user_key.as_ref(), USER, NOW, None, 0);
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::NoHostKey);
    // Padded to the maximum: accepted, full key included.
    let (d, eph) = make_knock(f.user_key.as_ref(), USER, NOW + 1, None, MAX_DATAGRAM);
    assert_eq!(d.len(), MAX_DATAGRAM);
    let p = expect_accept(f.state.handle(NOW, ip(1), &d));
    let done = f.state.complete(&p, 40_002, NOW).unwrap();
    assert!(done.datagram.len() <= d.len());
    let a = Accept::parse(&done.datagram).unwrap();
    assert_eq!(a.hostkey, Some(f.host_blob.as_slice()));
    wire::verify(&f.host_blob, wire::NS_ACCEPT, a.signed, a.sig_host).unwrap();
    eph.diffie_hellman(&a.eph_s).unwrap();
}

#[test]
fn known_rsa_host_key_needs_padding_to_predicted_size() {
    let rsa_host: KnockHostKey = Arc::from(fixture("u_rsa"));
    let mut f = setup_with(KnockServerConfig::default(), Box::new(ed25519()), rsa_host);
    let fp = wire::key_fp(&f.host_blob);
    let min = wire::accept_len_bound(&f.host_blob, false).unwrap();
    let (d, _) = make_knock(f.user_key.as_ref(), USER, NOW, Some(fp), min);
    assert!(d.len() >= min);
    let p = expect_accept(f.state.handle(NOW, ip(1), &d));
    let done = f.state.complete(&p, 40_003, NOW).unwrap();
    assert!(done.datagram.len() <= d.len());
}

#[test]
fn rsa_and_ecdsa_user_keys_can_knock() {
    for name in ["u_rsa", "u_ecdsa", "u_ecdsa384", "u_ecdsa521"] {
        let mut f = setup_with(
            KnockServerConfig::default(),
            fixture(name),
            Arc::new(ed25519()),
        );
        let fp = wire::key_fp(&f.host_blob);
        let (d, _) = make_knock(f.user_key.as_ref(), USER, NOW, Some(fp), 0);
        assert!(d.len() <= MAX_DATAGRAM, "{name}: {} bytes", d.len());
        expect_accept(f.state.handle(NOW, ip(1), &d));
        // Randomised ECDSA sig1 values are each verified once, then cached.
        let (d, _) = make_knock(f.user_key.as_ref(), USER, NOW + 1, Some(fp), 0);
        expect_accept(f.state.handle(NOW, ip(1), &d));
    }
}

#[test]
fn key_source_swap_keeps_and_drops_state() {
    let mut f = setup();
    let d = f.knock(NOW);
    expect_accept(f.state.handle(NOW, ip(1), &d));
    let mut table = KnockKeyTable::new();
    table.insert(USER, f.user_key.public_blob());
    f.state.set_key_source(table);
    // Same key kept its last nonce.
    expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::Replay);
    f.state.set_key_source(KnockKeyTable::new());
    expect_drop(
        f.state.handle(NOW, ip(1), &f.knock(NOW + 1)),
        DropReason::UnknownKey,
    );
}

/// A key source that records every lookup.
struct CountingSource {
    keys: Vec<(String, Vec<u8>)>,
    calls: Arc<std::sync::Mutex<Vec<String>>>,
}

impl KnockKeySource for CountingSource {
    fn keys_for(&mut self, user: &str) -> Vec<Vec<u8>> {
        self.calls.lock().unwrap().push(user.to_string());
        self.keys
            .iter()
            .filter(|(u, _)| u == user)
            .map(|(_, b)| b.clone())
            .collect()
    }
}

fn counting_setup() -> (Fixture, Arc<std::sync::Mutex<Vec<String>>>) {
    let user_key: Box<dyn HostKey + Send + Sync> = Box::new(ed25519());
    let host: KnockHostKey = Arc::new(ed25519());
    let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let source = CountingSource {
        keys: vec![(USER.to_string(), user_key.public_blob())],
        calls: calls.clone(),
    };
    let host_blob = host.public_blob();
    let f = Fixture {
        state: KnockState::new(
            KnockServerConfig::default(),
            source,
            vec![host],
            NOW - 60_000,
        ),
        user_key,
        host_blob,
    };
    (f, calls)
}

#[test]
fn keys_are_loaded_lazily_and_cached() {
    let (mut f, calls) = counting_setup();
    // Building the state reads nothing.
    assert!(calls.lock().unwrap().is_empty());
    // Garbage and out-of-window knocks read nothing either.
    expect_drop(f.state.handle(NOW, ip(1), b"junk"), DropReason::Malformed);
    expect_drop(
        f.state.handle(NOW, ip(1), &f.knock(NOW - 31_000)),
        DropReason::Clock,
    );
    assert!(calls.lock().unwrap().is_empty());

    // First valid knock loads the user once; later knocks reuse the cache.
    for t in [NOW, NOW + 10] {
        let p = expect_accept(f.state.handle(t, ip(1), &f.knock(t)));
        f.state.release_pending(&p.user, &p.key_fp);
    }
    assert_eq!(*calls.lock().unwrap(), vec![USER.to_string()]);

    // After the TTL the next knock reloads.
    let later = NOW + 61_000;
    let p = expect_accept(f.state.handle(later, ip(2), &f.knock(later)));
    f.state.release_pending(&p.user, &p.key_fp);
    assert_eq!(calls.lock().unwrap().len(), 2);
    // State survived the reload: the old nonce is still refused.
    expect_drop(
        f.state.handle(later, ip(2), &f.knock(later - 1)),
        DropReason::Replay,
    );

    // invalidate_keys forces a reload on the next knock.
    f.state.invalidate_keys(Some(USER));
    let p = expect_accept(f.state.handle(later + 1, ip(2), &f.knock(later + 1)));
    f.state.release_pending(&p.user, &p.key_fp);
    assert_eq!(calls.lock().unwrap().len(), 3);
}

#[test]
fn unknown_users_are_negatively_cached() {
    let (mut f, calls) = counting_setup();
    let fp = wire::key_fp(&f.host_blob);
    for i in 0..5 {
        let (d, _) = make_knock(f.user_key.as_ref(), "mallory", NOW + i, Some(fp), 0);
        expect_drop(f.state.handle(NOW, ip(1), &d), DropReason::UnknownKey);
    }
    assert_eq!(*calls.lock().unwrap(), vec!["mallory".to_string()]);
}

#[test]
fn key_cache_is_bounded() {
    let (mut f, calls) = counting_setup();
    let cfg = KnockServerConfig {
        key_cache_users: 2,
        ..Default::default()
    };
    let source = CountingSource {
        keys: Vec::new(),
        calls: calls.clone(),
    };
    f.state = KnockState::new(cfg, source, Vec::new(), NOW - 60_000);
    let fp = wire::key_fp(&f.host_blob);
    for (i, user) in ["u1", "u2", "u3", "u1"].into_iter().enumerate() {
        let t = NOW + i as u64;
        let (d, _) = make_knock(f.user_key.as_ref(), user, t, Some(fp), 0);
        f.state.handle(t, ip(1), &d);
    }
    // u1 was evicted by u3, so it is asked for again.
    assert_eq!(calls.lock().unwrap().len(), 4);
}

#[test]
fn key_lookups_are_rate_limited_and_real_users_survive_eviction() {
    let (mut f, calls) = counting_setup();
    let cfg = KnockServerConfig {
        key_cache_users: 3,
        key_lookups_per_sec: 4,
        ..Default::default()
    };
    let source = CountingSource {
        keys: vec![(USER.to_string(), f.user_key.public_blob())],
        calls: calls.clone(),
    };
    let host: KnockHostKey = Arc::new(ed25519());
    f.host_blob = host.public_blob();
    f.state = KnockState::new(cfg, source, vec![host], NOW - 60_000);
    let fp = wire::key_fp(&f.host_blob);

    // The real user gets cached first.
    let p = expect_accept(f.state.handle(NOW, ip(1), &f.knock(NOW)));
    f.state.release_pending(&p.user, &p.key_fp);
    // A flood of made-up names: 3 more lookups fit the burst, then drops.
    for i in 0..10u64 {
        let user = format!("fake{i}");
        let (d, _) = make_knock(f.user_key.as_ref(), &user, NOW + i, Some(fp), 0);
        let v = f.state.handle(NOW + 1, ip(9), &d);
        let want = if i < 3 {
            DropReason::UnknownKey
        } else {
            DropReason::RateLimited
        };
        expect_drop(v, want);
    }
    assert_eq!(calls.lock().unwrap().len(), 4);
    // The cache (3 users) evicted fake entries, not the real user: its next
    // knock needs no lookup even though the lookup bucket is empty.
    let p = expect_accept(f.state.handle(NOW + 2, ip(1), &f.knock(NOW + 2)));
    f.state.release_pending(&p.user, &p.key_fp);
    assert_eq!(calls.lock().unwrap().len(), 4);
}

/// Full loopback: UDP knock → ACCEPT → rendezvous connect → token check.
#[test]
fn loopback_knock_and_rendezvous() {
    let user_key = ed25519();
    let host: KnockHostKey = Arc::new(ed25519());
    let host_blob = host.public_blob();
    let mut table = KnockKeyTable::new();
    table.insert(USER, user_key.public_blob());
    let state = KnockState::new(
        KnockServerConfig::default(),
        table,
        vec![host],
        unix_ms() - 1000,
    );
    let mut server = KnockServer::bind("127.0.0.1:0", state).unwrap();
    let addr = server.local_addr().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let srv = std::thread::spawn(move || {
        let mut got = Vec::new();
        while !stop2.load(Ordering::Relaxed) && got.is_empty() {
            got.extend(server.process());
            std::thread::sleep(Duration::from_millis(5));
        }
        (got, server)
    });

    let mut req = KnockRequest {
        user: USER,
        identities: vec![KnockIdentity {
            signer: &user_key,
            sig1: None,
        }],
        known_host_keys: Vec::new(),
    };
    let acc = knock(addr, &mut req, &KnockClientConfig::default(), &|| false)
        .unwrap()
        .expect("accepted");
    assert!(req.identities[0].sig1.is_some(), "sig1 filled for caching");
    assert!(!acc.host_key_known);
    assert_eq!(acc.host_key_blob, host_blob);

    // A connection that sends the wrong token is refused…
    {
        let mut bad = std::net::TcpStream::connect(acc.target).unwrap();
        use std::io::Write;
        bad.write_all(&[0u8; 32]).unwrap();
        let mut b = [0u8; 1];
        bad.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(bad.read(&mut b).unwrap_or(0), 0, "closed after bad token");
    }
    // …and the real one gets through.
    let mut s = acc.connect(Some(Duration::from_secs(5))).unwrap();
    use std::io::Write;
    s.write_all(b"hello").unwrap();
    let (mut got, mut server) = srv.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    assert_eq!(got.len(), 1);
    let c = got.pop().unwrap();
    assert_eq!(c.user, USER);
    assert_eq!(c.host_key_blob, host_blob);
    let mut buf = [0u8; 5];
    let mut cs = c.stream;
    cs.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello");
    // The listener is single-use.
    assert_eq!(server.open_rendezvous(), 0);
    assert!(std::net::TcpStream::connect(acc.target).is_err());
    let _ = server.process();
}

#[test]
fn knock_without_answer_times_out_quickly_on_closed_port() {
    // Grab a free UDP port, then close it: the knock gets ICMP unreachable.
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let key = ed25519();
    let mut req = KnockRequest {
        user: USER,
        identities: vec![KnockIdentity {
            signer: &key,
            sig1: None,
        }],
        known_host_keys: Vec::new(),
    };
    let start = std::time::Instant::now();
    let r = knock(
        (Ipv4Addr::LOCALHOST, port).into(),
        &mut req,
        &KnockClientConfig::default(),
        &|| false,
    )
    .unwrap();
    assert!(r.is_none());
    assert!(start.elapsed() < Duration::from_millis(3500));
}

#[test]
fn connect_or_knock_falls_back_when_tcp_is_refused() {
    let user_key = ed25519();
    let host: KnockHostKey = Arc::new(ed25519());
    let host_blob = host.public_blob();
    let mut table = KnockKeyTable::new();
    table.insert(USER, user_key.public_blob());
    let state = KnockState::new(
        KnockServerConfig::default(),
        table,
        vec![host],
        unix_ms() - 1000,
    );
    let mut server = KnockServer::bind("127.0.0.1:0", state).unwrap();
    let port = server.local_addr().unwrap().port();
    // Nothing listens on TCP at that port number (best effort: the UDP port
    // is ours, the TCP one is very likely free).
    if TcpListener::bind(("127.0.0.1", port)).is_err() {
        return;
    }
    let srv = std::thread::spawn(move || {
        loop {
            let got = server.process();
            if !got.is_empty() {
                return got;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let mut req = KnockRequest {
        user: USER,
        identities: vec![KnockIdentity {
            signer: &user_key,
            sig1: None,
        }],
        known_host_keys: vec![host_blob.clone()],
    };
    let c = connect_or_knock("127.0.0.1", port, &mut req, &KnockConnectOptions::default()).unwrap();
    match c {
        Connected::Knocked { accepted, .. } => {
            assert!(accepted.host_key_known);
            assert_eq!(accepted.host_key_blob, host_blob);
        }
        Connected::Direct(_) => panic!("expected a knock"),
    }
    let got = srv.join().unwrap();
    assert_eq!(got.len(), 1);
}
