//! Just enough X.509 for a token's certificates: the public key, and the
//! subject as OpenSSL's `X509_NAME_oneline` prints it (OpenSSH labels
//! certificate keys with it).

use alloc::string::String;
use purecrypto::der::Reader;

const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_VERSION: u8 = 0xa0;

/// The DER `SubjectPublicKeyInfo` of a DER certificate.
pub(super) fn subject_public_key_info(cert: &[u8]) -> Option<&[u8]> {
    let mut r = Reader::new(cert);
    let mut c = r.read_sequence().ok()?;
    let mut tbs = c.read_sequence().ok()?;
    if tbs.peek_tag() == Some(TAG_VERSION) {
        tbs.read_any().ok()?;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        tbs.read_any().ok()?;
    }
    tbs.read_element().ok()
}

/// OpenSSL's short name for an attribute type (its `OBJ_nid2sn`), for the
/// usual ones; the dotted OID otherwise.
fn short_name(oid: &[u8]) -> String {
    let name = match oid {
        [0x55, 0x04, n] => match n {
            3 => "CN",
            4 => "SN",
            5 => "serialNumber",
            6 => "C",
            7 => "L",
            8 => "ST",
            9 => "street",
            10 => "O",
            11 => "OU",
            12 => "title",
            42 => "GN",
            43 => "initials",
            46 => "dnQualifier",
            65 => "pseudonym",
            _ => "",
        },
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01] => "UID",
        _ => "",
    };
    if name.is_empty() {
        purecrypto::der::oid_to_string(oid).unwrap_or_default()
    } else {
        name.into()
    }
}

/// `/C=US/O=Example/CN=Name` for a DER `Name` (the certificate's
/// `CKA_SUBJECT`), bytes outside printable ASCII as `\xHH` as OpenSSL does.
pub(super) fn name_oneline(name: &[u8]) -> Option<String> {
    let mut r = Reader::new(name);
    let mut rdns = r.read_sequence().ok()?;
    let mut out = String::new();
    while !rdns.is_empty() {
        let (tag, set) = rdns.read_any().ok()?;
        if tag != TAG_SET {
            return None;
        }
        let mut set = Reader::new(set);
        while !set.is_empty() {
            let (tag, atv) = set.read_any().ok()?;
            if tag != TAG_SEQUENCE {
                return None;
            }
            let mut atv = Reader::new(atv);
            let oid = atv.read_oid().ok()?;
            let (_, value) = atv.read_any().ok()?;
            out.push('/');
            out.push_str(&short_name(oid));
            out.push('=');
            for &b in value {
                if (0x20..0x7f).contains(&b) {
                    out.push(b as char);
                } else {
                    out.push_str(&alloc::format!("\\x{b:02X}"));
                }
            }
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    Some(out)
}
