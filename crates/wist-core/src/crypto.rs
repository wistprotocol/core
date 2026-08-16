use crate::error::Error;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, VerifyingKey};

pub fn b64u_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn b64u_decode(s: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| Error::Encoding(format!("base64url: {e}")))
}

pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, Error> {
    if !s.len().is_multiple_of(2) || s.bytes().any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Error::Encoding("invalid lowercase hex".into()));
    }
    Ok(s.as_bytes()
        .chunks(2)
        .map(|c| {
            let hi = (c[0] as char).to_digit(16).unwrap() as u8;
            let lo = (c[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect())
}

pub struct PublicKey(VerifyingKey);

/// WIST-1 §4: the encoded `y` must be below `p = 2^255 - 19`. Decoders that
/// reduce mod p instead read a second encoding of a point already encodable.
fn canonically_encoded(point: &[u8; 32]) -> bool {
    const P: [u8; 32] = {
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        p
    };
    let mut y = *point;
    y[31] &= 0x7f;
    for i in (0..32).rev() {
        match y[i].cmp(&P[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

impl PublicKey {
    pub fn from_b64u(s: &str) -> Result<Self, Error> {
        let raw = b64u_decode(s)?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| Error::Encoding("public key must be 32 octets".into()))?;
        if !canonically_encoded(&arr) {
            return Err(Error::Encoding(
                "Ed25519 public key is not canonically encoded".into(),
            ));
        }
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|_| Error::Encoding("invalid Ed25519 public key".into()))?;
        if key.is_weak() {
            return Err(Error::Encoding(
                "Ed25519 public key is of small order".into(),
            ));
        }
        Ok(PublicKey(key))
    }
}

pub fn verify(key: &PublicKey, msg: &[u8], sig_b64u: &str) -> Result<(), Error> {
    let raw = b64u_decode(sig_b64u)?;
    let arr: [u8; 64] = raw
        .try_into()
        .map_err(|_| Error::Encoding("signature must be 64 octets".into()))?;
    let r: [u8; 32] = arr[..32].try_into().unwrap();
    if !canonically_encoded(&r) {
        return Err(Error::Signature);
    }
    key.0
        .verify_strict(msg, &Signature::from_bytes(&arr))
        .map_err(|_| Error::Signature)
}

pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(seed))
    }
    pub fn sign(&self, msg: &[u8]) -> String {
        b64u_encode(&self.0.sign(msg).to_bytes())
    }
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64u_roundtrip_and_rejects_padding() {
        assert_eq!(b64u_encode(b"\xff\x00"), "_wA");
        assert_eq!(b64u_decode("_wA").unwrap(), b"\xff\x00");
        assert!(b64u_decode("_wA=").is_err());
        assert!(b64u_decode("+/").is_err());
    }

    #[test]
    fn hex_roundtrip_lowercase_only() {
        assert_eq!(hex_encode(b"\x00\xab"), "00ab");
        assert_eq!(hex_decode("00ab").unwrap(), b"\x00\xab");
        assert!(hex_decode("00AB").is_err());
        assert!(hex_decode("0").is_err());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::from_seed(&[7u8; 32]);
        let sig = sk.sign(b"msg");
        assert!(verify(&sk.public(), b"msg", &sig).is_ok());
        assert!(verify(&sk.public(), b"other", &sig).is_err());
    }
}
