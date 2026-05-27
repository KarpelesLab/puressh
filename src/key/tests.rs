use super::*;

// Generated with:
//   ssh-keygen -t ed25519 -f /tmp/k -N "" -C "test@puressh"
const ED25519_PUB_LINE: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILlxF+s0ktFl1xHsUrt7F0Z0wRAWTiAD1wnH+b5NKoSI test@puressh";

const ED25519_PEM_UNENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC5cRfrNJLRZdcR7FK7exdGdMEQFk4gA9cJx/m+TSqEiAAAAJAkzSrIJM0q
yAAAAAtzc2gtZWQyNTUxOQAAACC5cRfrNJLRZdcR7FK7exdGdMEQFk4gA9cJx/m+TSqEiA
AAAEBVcog7R273wnkgguPcJpFC6gHsOZ5UKX/tvSh8D1ifa7lxF+s0ktFl1xHsUrt7F0Z0
wRAWTiAD1wnH+b5NKoSIAAAADHRlc3RAcHVyZXNzaAE=
-----END OPENSSH PRIVATE KEY-----
";

// Generated with:
//   ssh-keygen -t ed25519 -f /tmp/k_enc -N "secret123" -C "encrypted@puressh" -a 16
const ED25519_PEM_ENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCmejsun4
79mcsCr4laGrbLAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINVyomq59MFud+Ra
S/SLBR4tkpasJEJNgQTo4ulQxZBRAAAAoPDTnnisOJrALbSVB2woz+E8pP7xy29z5aY84a
bj3/L8ZPCgICAbv8m7m8qsCxu2g2ObLl7Qn4tEMONia+/hrB4dKKsWbFbpdidGABK2N7Ba
tP2kFwhS0ODzclNDY3jEZmcXiBJUL5Z9DcQF/IS4kBqMaW70xs4ClLd8Ggl0vRnAXehL/x
j+T0eEOle+/gVye0ZXtvgoNvRrUdZbNryH9p8=
-----END OPENSSH PRIVATE KEY-----
";

const ED25519_PEM_ENC_PUB: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVyomq59MFud+RaS/SLBR4tkpasJEJNgQTo4ulQxZBR encrypted@puressh";

const RSA_PUB_LINE: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDD/7KO4oupLNNoKTzuRocimPgb47nlbGy7DBpbPTuKWWakkSAWfIhQ/a4e1Zye6YafK+UKz3lv1kTH/XkPI1K3KZTBJRQeHABmT+O513/rzqABWR0/gRLC7CfI3IyAxZn8VcEukV2+UoSQ1huuFQxVCH8AjDxCVDYftXjTidD+IQBHUNuXvKWpLDrFD7305VgHkfzPPFHAtZ+9w2JypRe6GCdXT0F6bqBfjBYOGHkNAWXl5/nC042GITRE98FNBlnWt9S1oSTS85Ri/0cPvk/DmDIZoWH+fz2fQGMYW4D2TuaMLZSc70WTZF7cw6ROjTfLKyNuO1AlX/DIiO1z0tJ/ rsa@puressh";

const RSA_PEM_UNENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAw/+yjuKLqSzTaCk87kaHIpj4G+O55WxsuwwaWz07illmpJEgFnyI
UP2uHtWcnumGnyvlCs95b9ZEx/15DyNStymUwSUUHhwAZk/judd/686gAVkdP4ESwuwnyN
yMgMWZ/FXBLpFdvlKEkNYbrhUMVQh/AIw8QlQ2H7V404nQ/iEAR1Dbl7ylqSw6xQ+99OVY
B5H8zzxRwLWfvcNicqUXuhgnV09Bem6gX4wWDhh5DQFl5ef5wtONhiE0RPfBTQZZ1rfUta
Ek0vOUYv9HD75Pw5gyGaFh/n89n0BjGFuA9k7mjC2UnO9Fk2Re3MOkTo03yysjbjtQJV/w
yIjtc9LSfwAAA8Bg8yzGYPMsxgAAAAdzc2gtcnNhAAABAQDD/7KO4oupLNNoKTzuRocimP
gb47nlbGy7DBpbPTuKWWakkSAWfIhQ/a4e1Zye6YafK+UKz3lv1kTH/XkPI1K3KZTBJRQe
HABmT+O513/rzqABWR0/gRLC7CfI3IyAxZn8VcEukV2+UoSQ1huuFQxVCH8AjDxCVDYftX
jTidD+IQBHUNuXvKWpLDrFD7305VgHkfzPPFHAtZ+9w2JypRe6GCdXT0F6bqBfjBYOGHkN
AWXl5/nC042GITRE98FNBlnWt9S1oSTS85Ri/0cPvk/DmDIZoWH+fz2fQGMYW4D2TuaMLZ
Sc70WTZF7cw6ROjTfLKyNuO1AlX/DIiO1z0tJ/AAAAAwEAAQAAAP82yJcgPKQiM4HHYqL6
oZ+V0yv4LefH/9u5weEqSiwhYxSi6woNBhdM/dQfPAenf9d2bUBCqNe6atRdEgqLhf61M5
TSZ8OpimMD/Rep9ssgAb2bFKLfVhghRzZJYD+sojmEwDqUV9SGs2121X48f6WddFC2D2Ad
1MFMG6Yb7Gmanj0fcUsht1WA0fId0hrbIF23yy6e9IcXSHOMMQi2b4/wOHEtDLC7EJhcJb
Au10bjpU1za2WRpY1Ixb4M3GJ6Dmvp/28vRjpTOo2Nedlo50rKxO5jVAInvEju+4jCJioQ
wIMYvcAGQN9QfxpoivVtny+SNwL4PVDTjKzl9GHBh4EAAACALgcL6Pz77CAJH2yoR/U3Qu
jULAain7Eoz/Drn/ajEG7wED3CnZR2b1SUn5tf81yT9DlSbX4O3EYBm4pZ5Rri7APM95jo
FRtB3a2m3YCIfVNdB/jBk9mtbbSGw1jb/EtclT5DA+533/xK8Z8GhSKrwuol67qYQDM3YK
g+G17+DrYAAACBAPxkt+l7sSKKteP3YX4qsufBhxq9NPjQaLZbTbUb42AVM0ERVJx/d7Nd
JMxDfJEaBmP7JpKEirU/bVW+4V6Y9z2IbBOmpobTncRUcVaoFxf/WeXRiupB8g05TwI8+I
xERGcLAoUk3yd1HVoR/vP0WDKvfRYQ2Sz6gtXolaBl55oRAAAAgQDGzK6DIsStqdYfxpDW
A83eJatwfN3fIkUCPS2iJ1yPWVkz9ejWQ2SqsdWgEETLf5SOsIUg7KNxkRH8LUVTlRCquO
uAZ99NitHgV5gHeNX/nREtHDpqeq9kERw6CD8O9YVAcY3LiYqGOS54A6/luR++Drfkjiyk
61iG/LPjjjyTjwAAAAtyc2FAcHVyZXNzaAE=
-----END OPENSSH PRIVATE KEY-----
";

const ECDSA_P256_PUB_LINE: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL8cARH4L1jr2e/bFvNdOIcoOnEAkYez3CC0R9XPLBuU/q5uk4gD8MtRkQMS59jNX42ZDXq9DNM1MODm7iwGfO8= ecdsa@puressh";

const ECDSA_P256_PEM_UNENCRYPTED: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS/HAER+C9Y69nv2xbzXTiHKDpxAJGH
s9wgtEfVzywblP6ubpOIA/DLUZEDEufYzV+NmQ16vQzTNTDg5u4sBnzvAAAAqHmPW3N5j1
tzAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL8cARH4L1jr2e/b
FvNdOIcoOnEAkYez3CC0R9XPLBuU/q5uk4gD8MtRkQMS59jNX42ZDXq9DNM1MODm7iwGfO
8AAAAhAK3hEtZjg/CUD9kdq/RntzqG10/PQWWiQxP+pRbja/uqAAAADWVjZHNhQHB1cmVz
c2gBAg==
-----END OPENSSH PRIVATE KEY-----
";

#[test]
fn parse_ed25519_authorized_keys_line() {
    let pk = PublicKey::parse_authorized_keys_line(ED25519_PUB_LINE).unwrap();
    match &pk {
        PublicKey::Ed25519 { raw, comment } => {
            assert_eq!(raw.len(), 32);
            assert_eq!(comment, "test@puressh");
        }
        _ => panic!("expected ed25519"),
    }
    assert_eq!(pk.algorithm(), "ssh-ed25519");
    assert_eq!(pk.to_authorized_keys_line(), ED25519_PUB_LINE);
}

#[test]
fn parse_rsa_authorized_keys_line() {
    let pk = PublicKey::parse_authorized_keys_line(RSA_PUB_LINE).unwrap();
    match &pk {
        PublicKey::Rsa { e, n, comment } => {
            assert_eq!(e, &[0x01, 0x00, 0x01]);
            assert!(n.len() >= 256);
            assert_eq!(comment, "rsa@puressh");
        }
        _ => panic!("expected rsa"),
    }
    assert_eq!(pk.to_authorized_keys_line(), RSA_PUB_LINE);
}

#[test]
fn parse_ecdsa_p256_authorized_keys_line() {
    let pk = PublicKey::parse_authorized_keys_line(ECDSA_P256_PUB_LINE).unwrap();
    match &pk {
        PublicKey::EcdsaP256 { point, comment } => {
            assert_eq!(point.len(), 65);
            assert_eq!(point[0], 0x04);
            assert_eq!(comment, "ecdsa@puressh");
        }
        _ => panic!("expected ecdsa-p256"),
    }
    assert_eq!(pk.to_authorized_keys_line(), ECDSA_P256_PUB_LINE);
}

#[test]
fn parse_unencrypted_ed25519_pem() {
    let sk = PrivateKey::parse_openssh_pem(ED25519_PEM_UNENCRYPTED, None).unwrap();
    match &sk {
        PrivateKey::Ed25519 {
            seed,
            public,
            comment,
        } => {
            assert_eq!(comment, "test@puressh");
            assert_eq!(seed.len(), 32);
            assert_eq!(public.len(), 32);
        }
        _ => panic!("expected ed25519"),
    }
    let derived_pub = sk.public_key();
    let pub_from_line = PublicKey::parse_authorized_keys_line(ED25519_PUB_LINE).unwrap();
    match (&derived_pub, &pub_from_line) {
        (PublicKey::Ed25519 { raw: a, .. }, PublicKey::Ed25519 { raw: b, .. }) => {
            assert_eq!(a, b);
        }
        _ => unreachable!(),
    }
}

#[test]
fn parse_unencrypted_rsa_pem() {
    let sk = PrivateKey::parse_openssh_pem(RSA_PEM_UNENCRYPTED, None).unwrap();
    match &sk {
        PrivateKey::Rsa {
            n,
            e,
            d,
            p,
            q,
            iqmp,
            comment,
        } => {
            assert_eq!(comment, "rsa@puressh");
            assert!(n.len() >= 256);
            assert_eq!(e, &[0x01, 0x00, 0x01]);
            assert!(!d.is_empty());
            assert!(!p.is_empty());
            assert!(!q.is_empty());
            assert!(!iqmp.is_empty());
        }
        _ => panic!("expected rsa"),
    }
    // Derived public key should match the .pub line.
    let derived_pub_blob = sk.public_key().wire_blob();
    let from_line = PublicKey::parse_authorized_keys_line(RSA_PUB_LINE).unwrap();
    assert_eq!(derived_pub_blob, from_line.wire_blob());
}

#[test]
fn parse_unencrypted_ecdsa_p256_pem() {
    let sk = PrivateKey::parse_openssh_pem(ECDSA_P256_PEM_UNENCRYPTED, None).unwrap();
    match &sk {
        PrivateKey::EcdsaP256 { d, point, comment } => {
            assert_eq!(comment, "ecdsa@puressh");
            assert_eq!(point.len(), 65);
            assert!(!d.is_empty());
        }
        _ => panic!("expected ecdsa-p256"),
    }
    let from_line = PublicKey::parse_authorized_keys_line(ECDSA_P256_PUB_LINE).unwrap();
    assert_eq!(sk.public_key().wire_blob(), from_line.wire_blob());
}

#[test]
fn parse_encrypted_ed25519_pem_with_passphrase() {
    let sk = PrivateKey::parse_openssh_pem(ED25519_PEM_ENCRYPTED, Some(b"secret123")).unwrap();
    match &sk {
        PrivateKey::Ed25519 { comment, .. } => {
            assert_eq!(comment, "encrypted@puressh");
        }
        _ => panic!("expected ed25519"),
    }
    let from_line = PublicKey::parse_authorized_keys_line(ED25519_PEM_ENC_PUB).unwrap();
    assert_eq!(sk.public_key().wire_blob(), from_line.wire_blob());
}

#[test]
fn encrypted_pem_wrong_passphrase_fails() {
    let err = PrivateKey::parse_openssh_pem(ED25519_PEM_ENCRYPTED, Some(b"wrong"))
        .expect_err("should reject wrong passphrase");
    match err {
        Error::Crypto(msg) => assert!(msg.contains("passphrase"), "{}", msg),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn encrypted_pem_missing_passphrase_fails() {
    let err = PrivateKey::parse_openssh_pem(ED25519_PEM_ENCRYPTED, None)
        .expect_err("should require passphrase");
    assert!(matches!(err, Error::Crypto(_)));
}

#[test]
fn rejects_bad_pem_marker() {
    let bad = "no markers here";
    assert!(PrivateKey::parse_openssh_pem(bad, None).is_err());
}

#[test]
fn authorized_keys_line_roundtrip_no_comment() {
    let pk = PublicKey::Ed25519 {
        raw: [7u8; 32],
        comment: String::new(),
    };
    let line = pk.to_authorized_keys_line();
    assert!(!line.ends_with(' '));
    let parsed = PublicKey::parse_authorized_keys_line(&line).unwrap();
    assert_eq!(parsed, pk);
}

#[test]
fn wire_blob_ed25519_matches_known_layout() {
    let pk = PublicKey::Ed25519 {
        raw: [0xab; 32],
        comment: String::new(),
    };
    let blob = pk.wire_blob();
    // string "ssh-ed25519" (4 + 11) + string raw32 (4 + 32) = 51 bytes
    assert_eq!(blob.len(), 51);
    assert_eq!(&blob[0..4], &[0, 0, 0, 11]);
    assert_eq!(&blob[4..15], b"ssh-ed25519");
    assert_eq!(&blob[15..19], &[0, 0, 0, 32]);
    assert_eq!(&blob[19..], &[0xab; 32]);
}
