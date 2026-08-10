use crate::error::Error;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};

pub const PROOF_LEN: usize = 80;
pub const OUTPUT_LEN: usize = 64;
const SUITE: u8 = 0x03;

struct ExpandedKey {
    x: Scalar,
    nonce_key: [u8; 32],
    pk: [u8; 32],
}

fn expand(sk_seed: &[u8; 32]) -> ExpandedKey {
    let h = Sha512::digest(sk_seed);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&h[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let x = Scalar::from_bytes_mod_order(scalar_bytes);
    let mut nonce_key = [0u8; 32];
    nonce_key.copy_from_slice(&h[32..]);
    let pk = EdwardsPoint::mul_base(&x).compress().to_bytes();
    ExpandedKey { x, nonce_key, pk }
}

pub fn public_key(sk_seed: &[u8; 32]) -> [u8; 32] {
    expand(sk_seed).pk
}

fn encode_to_curve(pk: &[u8; 32], alpha: &[u8]) -> Result<(EdwardsPoint, [u8; 32]), Error> {
    for ctr in 0u8..=255 {
        let mut h = Sha512::new();
        h.update([SUITE, 0x01]);
        h.update(pk);
        h.update(alpha);
        h.update([ctr, 0x00]);
        let digest = h.finalize();
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&digest[..32]);
        if let Some(p) = CompressedEdwardsY(candidate).decompress() {
            let cleared = p.mul_by_cofactor();
            if !cleared.is_identity() {
                return Ok((cleared, cleared.compress().to_bytes()));
            }
        }
    }
    Err(Error::Vrf("encode_to_curve: no valid point in 256 attempts".into()))
}

fn challenge(points: [&[u8; 32]; 5]) -> Scalar {
    let mut h = Sha512::new();
    h.update([SUITE, 0x02]);
    for p in points {
        h.update(p);
    }
    h.update([0x00]);
    let digest = h.finalize();
    let mut c = [0u8; 32];
    c[..16].copy_from_slice(&digest[..16]);
    Scalar::from_bytes_mod_order(c)
}

pub fn prove(sk_seed: &[u8; 32], alpha: &[u8]) -> Result<[u8; PROOF_LEN], Error> {
    let key = expand(sk_seed);
    let (h_point, h_string) = encode_to_curve(&key.pk, alpha)?;
    let gamma = h_point * key.x;
    let mut nh = Sha512::new();
    nh.update(key.nonce_key);
    nh.update(h_string);
    let k = Scalar::from_bytes_mod_order_wide(&nh.finalize().into());
    let u = EdwardsPoint::mul_base(&k);
    let v = h_point * k;
    let gamma_string = gamma.compress().to_bytes();
    let c = challenge([
        &key.pk,
        &h_string,
        &gamma_string,
        &u.compress().to_bytes(),
        &v.compress().to_bytes(),
    ]);
    let s = k + c * key.x;
    let mut pi = [0u8; PROOF_LEN];
    pi[..32].copy_from_slice(&gamma_string);
    pi[32..48].copy_from_slice(&c.to_bytes()[..16]);
    pi[48..].copy_from_slice(&s.to_bytes());
    Ok(pi)
}

fn decode_proof(pi: &[u8; PROOF_LEN]) -> Result<(EdwardsPoint, [u8; 32], Scalar, Scalar), Error> {
    let mut gamma_bytes = [0u8; 32];
    gamma_bytes.copy_from_slice(&pi[..32]);
    let gamma = CompressedEdwardsY(gamma_bytes)
        .decompress()
        .ok_or_else(|| Error::Vrf("gamma: invalid point".into()))?;
    if gamma.compress().to_bytes() != gamma_bytes {
        return Err(Error::Vrf("gamma: non-canonical encoding".into()));
    }
    let mut c_bytes = [0u8; 32];
    c_bytes[..16].copy_from_slice(&pi[32..48]);
    let c = Scalar::from_bytes_mod_order(c_bytes);
    let s_bytes: [u8; 32] = pi[48..].try_into().unwrap();
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or_else(|| Error::Vrf("s: non-canonical scalar".into()))?;
    Ok((gamma, gamma_bytes, c, s))
}

pub fn proof_to_hash(pi: &[u8; PROOF_LEN]) -> Result<[u8; OUTPUT_LEN], Error> {
    let (gamma, _, _, _) = decode_proof(pi)?;
    let mut h = Sha512::new();
    h.update([SUITE, 0x03]);
    h.update(gamma.mul_by_cofactor().compress().to_bytes());
    h.update([0x00]);
    Ok(h.finalize().into())
}

pub fn verify(pk: &[u8; 32], alpha: &[u8], pi: &[u8; PROOF_LEN]) -> Result<[u8; OUTPUT_LEN], Error> {
    let y = CompressedEdwardsY(*pk)
        .decompress()
        .ok_or_else(|| Error::Vrf("pk: invalid point".into()))?;
    if y.compress().to_bytes() != *pk {
        return Err(Error::Vrf("pk: non-canonical encoding".into()));
    }
    if y.is_small_order() {
        return Err(Error::Vrf("pk: small-order point".into()));
    }
    let (gamma, gamma_bytes, c, s) = decode_proof(pi)?;
    let (h_point, h_string) = encode_to_curve(pk, alpha)?;
    let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(&-c, &y, &s);
    let v = h_point * s - gamma * c;
    let c2 = challenge([
        pk,
        &h_string,
        &gamma_bytes,
        &u.compress().to_bytes(),
        &v.compress().to_bytes(),
    ]);
    if c2 != c {
        return Err(Error::Vrf("challenge mismatch".into()));
    }
    proof_to_hash(pi)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        crate::crypto::hex_decode(s).unwrap()
    }
    fn hx32(s: &str) -> [u8; 32] {
        hx(s).try_into().unwrap()
    }

    struct Tv {
        sk: &'static str,
        pk: &'static str,
        alpha: &'static str,
        h: &'static str,
        pi: &'static str,
        beta: &'static str,
    }

    const TVS: [Tv; 3] = [
        Tv {
            sk: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            pk: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            alpha: "",
            h: "91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318",
            pi: "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
            beta: "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
        },
        Tv {
            sk: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            pk: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            alpha: "72",
            h: "5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551",
            pi: "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
            beta: "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
        },
        Tv {
            sk: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            pk: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            alpha: "af82",
            h: "bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a",
            pi: "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e",
            beta: "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
        },
    ];

    #[test]
    fn rfc9381_appendix_b3_vectors() {
        for tv in &TVS {
            let sk = hx32(tv.sk);
            let pk = hx32(tv.pk);
            let alpha = hx(tv.alpha);
            assert_eq!(public_key(&sk), pk);
            let (_, h_string) = encode_to_curve(&pk, &alpha).unwrap();
            assert_eq!(crate::crypto::hex_encode(&h_string), tv.h);
            let pi = prove(&sk, &alpha).unwrap();
            assert_eq!(crate::crypto::hex_encode(&pi), tv.pi);
            let beta = verify(&pk, &alpha, &pi).unwrap();
            assert_eq!(crate::crypto::hex_encode(&beta), tv.beta);
            assert_eq!(proof_to_hash(&pi).unwrap(), beta);
        }
    }
}
