//! Key fingerprints as OpenSSH shows them (`FingerprintHash`, `ssh-keygen
//! -E`) and its "drunken bishop" randomart (`VisualHostKey`, `ssh-keygen
//! -lv`); included by `ssh` and `ssh-keygen` via `#[path]`.

use puressh::key::PublicKey;

/// The digest of `blob` with the hash OpenSSH names `hash` (any case:
/// `MD5`, `SHA1`, `SHA256`, `SHA384`, `SHA512`), `None` for another name.
pub fn digest(blob: &[u8], hash: &str) -> Option<Vec<u8>> {
    use purecrypto::hash::{Digest, Md5, Sha1, Sha256, Sha384, Sha512};
    Some(match hash.to_ascii_uppercase().as_str() {
        "MD5" => Md5::digest(blob).as_ref().to_vec(),
        "SHA1" => Sha1::digest(blob).as_ref().to_vec(),
        "SHA256" => Sha256::digest(blob).as_ref().to_vec(),
        "SHA384" => Sha384::digest(blob).as_ref().to_vec(),
        "SHA512" => Sha512::digest(blob).as_ref().to_vec(),
        _ => return None,
    })
}

/// `blob`'s fingerprint as OpenSSH prints it: `MD5:` and colon-separated
/// hex for MD5, else `<HASH>:` and unpadded base64. SHA-256 for a hash
/// name this does not know.
pub fn fingerprint(blob: &[u8], hash: &str) -> String {
    let (name, d) = match digest(blob, hash) {
        Some(d) => (hash.to_ascii_uppercase(), d),
        None => (
            "SHA256".to_string(),
            digest(blob, "SHA256").unwrap_or_default(),
        ),
    };
    if name == "MD5" {
        let hex: Vec<String> = d.iter().map(|b| format!("{b:02x}")).collect();
        return format!("MD5:{}", hex.join(":"));
    }
    format!("{name}:{}", base64_unpadded(&d))
}

fn base64_unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

/// The key type as OpenSSH's randomart header and `ssh-keygen -l` name it.
pub fn key_label(pk: &PublicKey) -> &'static str {
    match pk {
        PublicKey::Ed25519 { .. } => "ED25519",
        PublicKey::EcdsaP256 { .. } => "ECDSA",
        PublicKey::EcdsaP384 { .. } => "ECDSA",
        PublicKey::EcdsaP521 { .. } => "ECDSA",
        PublicKey::Rsa { .. } => "RSA",
        PublicKey::MlDsa44Ed25519 { .. } => "MLDSA44-ED25519",
        // A key family added to the library after this binary was written.
        _ => "UNKNOWN",
    }
}

/// The randomart of the key in wire `blob` with `hash` (as OpenSSH's
/// `SSH_FP_RANDOMART`), `None` when the blob is not a key.
pub fn randomart_of_blob(blob: &[u8], hash: &str) -> Option<String> {
    let pk = PublicKey::parse_wire_blob(blob).ok()?;
    let hash = if digest(blob, hash).is_some() {
        hash.to_ascii_uppercase()
    } else {
        "SHA256".to_string()
    };
    let d = digest(blob, &hash)?;
    Some(randomart(
        key_label(&pk),
        pk.bit_length() as usize,
        &d,
        &hash,
    ))
}

/// OpenSSH's "drunken bishop" randomart for a key's digest: `label` and
/// `bits` head the frame, `hash_name` closes it.
pub fn randomart(label: &str, bits: usize, digest: &[u8], hash_name: &str) -> String {
    const AUG: &[u8] = b" .o+=*BOX@%&#/^SE";
    const W: usize = 17;
    const H: usize = 9;
    // As in OpenSSH: the last two symbols mark the start and end.
    let len = AUG.len() - 1;
    let mut field = [[0usize; H]; W];
    let (mut x, mut y) = (W as isize / 2, H as isize / 2);
    for byte in digest {
        let mut input = *byte;
        for _ in 0..4 {
            x += if input & 1 != 0 { 1 } else { -1 };
            y += if input & 2 != 0 { 1 } else { -1 };
            x = x.clamp(0, W as isize - 1);
            y = y.clamp(0, H as isize - 1);
            let cell = &mut field[x as usize][y as usize];
            if *cell < len - 2 {
                *cell += 1;
            }
            input >>= 2;
        }
    }
    field[W / 2][H / 2] = len - 1;
    field[x as usize][y as usize] = len;
    let border = |label: &str| {
        let mut line = String::from("+");
        let pad = W.saturating_sub(label.len()) / 2;
        line.push_str(&"-".repeat(pad));
        line.push_str(label);
        line.push_str(&"-".repeat(W.saturating_sub(pad + label.len())));
        line.push('+');
        line
    };
    let mut out = border(&format!("[{label} {bits}]"));
    out.push('\n');
    for row in 0..H {
        out.push('|');
        for col in field.iter() {
            out.push(AUG[col[row].min(len)] as char);
        }
        out.push_str("|\n");
    }
    out.push_str(&border(&format!("[{hash_name}]")));
    out
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    #[test]
    fn fingerprints_as_openssh() {
        // What OpenSSH's `ssh-keygen -l -E md5` / `-lv -E sha512` print.
        let pk = PublicKey::parse_authorized_keys_line(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILlxF+s0ktFl1xHsUrt7F0Z0wRAWTiAD1wnH+b5NKoSI t",
        )
        .unwrap();
        let blob = pk.wire_blob();
        assert_eq!(fingerprint(&blob, "sha256"), pk.sha256_fingerprint());
        assert_eq!(
            fingerprint(&blob, "md5"),
            "MD5:ea:87:de:32:10:ab:3b:c6:fb:a2:60:54:37:ac:48:81"
        );
        assert_eq!(
            fingerprint(&blob, "SHA512"),
            "SHA512:f7z7o83SNGH6kUR+drkJD6zte7RBCtqysrrNTlG+W6Plmrh3DLwBMYfv6GMpPYV1eADVsU/Gko2qpbd6TA/dQw"
        );
        assert_eq!(
            randomart_of_blob(&blob, "sha512").unwrap(),
            "+--[ED25519 256]--+\n\
             |       .+....    |\n\
             |       + o .* .  |\n\
             |        =.o=.B  .|\n\
             |       .o+.+=E=o+|\n\
             |       .S+* *=*=+|\n\
             |       o=%.=.==* |\n\
             |      o+=o@+++ooo|\n\
             |     .+Oo*O=o=+o |\n\
             |     o*OX*o.+**. |\n\
             +----[SHA512]-----+"
        );
    }
}
