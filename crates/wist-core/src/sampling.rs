use crate::crypto::hex_decode;
use crate::error::Error;
use sha2::{Digest, Sha256};

pub const SAMPLING_FLOOR_1E7: u64 = 200_000;
pub const SAMPLING_CEILING_1E7: u64 = 5_000_000;
pub const SAMPLING_SLOPE_PER_MICRO: u64 = 3;

pub fn alpha_from_block_hash(block_hash: &str) -> Result<[u8; 32], Error> {
    let hex = block_hash
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Encoding("block hash must carry sha256: prefix".into()))?;
    hex_decode(hex)?
        .try_into()
        .map_err(|_| Error::Encoding("block hash digest must be 32 octets".into()))
}

pub fn draw(beta: &[u8; 64], delta_id: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(beta);
    h.update(delta_id.as_bytes());
    let digest = h.finalize();
    u64::from_be_bytes(digest[..8].try_into().unwrap())
}

pub fn p_1e7(reputation_u: u64, level1_sanction: bool) -> u64 {
    if level1_sanction {
        return SAMPLING_CEILING_1E7;
    }
    let rep = reputation_u.min(1_000_000);
    (SAMPLING_FLOOR_1E7 + SAMPLING_SLOPE_PER_MICRO * (1_000_000 - rep))
        .clamp(SAMPLING_FLOOR_1E7, SAMPLING_CEILING_1E7)
}

pub fn selected(d: u64, p_1e7: u64) -> bool {
    (d as u128) * 10_000_000 < (p_1e7 as u128) << 64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_1e7_endpoints_and_sanction() {
        assert_eq!(p_1e7(1_000_000, false), 200_000);
        assert_eq!(p_1e7(100_000, false), 2_900_000);
        assert_eq!(p_1e7(0, false), 3_200_000);
        assert_eq!(p_1e7(500_000, true), 5_000_000);
        assert_eq!(p_1e7(u64::MAX, false), 200_000);
    }

    #[test]
    fn selection_is_wide_integer_comparison() {
        assert!(!selected(10444806108023957337, 2_900_000));
        assert!(selected(5049267597483020063, 2_900_000));
        assert!(!selected(5049267597483020063, 500_000));
        assert!(selected(0, 200_000));
        assert!(!selected(u64::MAX, 5_000_000));
    }

    #[test]
    fn alpha_rejects_bad_prefix_and_length() {
        assert!(alpha_from_block_hash("f6a3").is_err());
        assert!(alpha_from_block_hash("sha256:f6a3").is_err());
    }
}
