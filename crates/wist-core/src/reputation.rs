use crate::crypto::hex_encode;
use crate::error::Error;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const DECAY_TABLE_BYTES: &[u8] = include_bytes!("decay-table.json");
pub const DECAY_TABLE_SHA256: &str =
    "f0cd1eb48cbfb1647a083b4ba06e7f69e6c42d5b5f4bf8e4f42b97c6bfdf7dc1";
pub const DECAY_MAX_DAYS: u64 = 1825;

pub struct DecayTable(Vec<u32>);

impl DecayTable {
    pub fn from_bytes(bytes: &[u8]) -> Result<DecayTable, Error> {
        let digest = Sha256::digest(bytes);
        if hex_encode(&digest) != DECAY_TABLE_SHA256 {
            return Err(Error::DecayTable("SHA-256 mismatch".into()));
        }
        #[derive(serde::Deserialize)]
        struct File {
            values: Vec<u32>,
        }
        let f: File =
            serde_json::from_slice(bytes).map_err(|e| Error::DecayTable(e.to_string()))?;
        if f.values.len() != (DECAY_MAX_DAYS + 1) as usize {
            return Err(Error::DecayTable(format!(
                "expected 1826 values, got {}",
                f.values.len()
            )));
        }
        Ok(DecayTable(f.values))
    }

    pub fn builtin() -> &'static DecayTable {
        static TABLE: OnceLock<DecayTable> = OnceLock::new();
        TABLE.get_or_init(|| {
            DecayTable::from_bytes(DECAY_TABLE_BYTES).expect("vendored decay table corrupt")
        })
    }

    pub fn decay(&self, t_days: u64) -> u64 {
        if t_days > DECAY_MAX_DAYS {
            0
        } else {
            self.0[t_days as usize] as u64
        }
    }
}

pub const MICRO_SCALE: u64 = 1_000_000;
pub const DECAY_SCALE: u128 = 1_000_000_000;
pub const BASE_AT_AGE_0: u64 = 100_000;
pub const AGE_NORMALIZATION_DAYS: u64 = 730;
pub const C_CAP: u64 = 500;
pub const PENALTY_WEIGHT: u128 = 5;
pub const GATE_AGE_DAYS: u64 = 30;
pub const GATE_C: u64 = 10;
pub const PROVISIONAL_CAP_U: u64 = 100_000;
pub const QUOTA_BASE: u64 = 100;
pub const QUOTA_SLOPE: u64 = 10_000;
pub const INCLUSION_LATENCY_THRESHOLD_U: u64 = 500_000;

pub fn whole_days(seconds_x: i64, seconds_y: i64) -> Result<u64, Error> {
    if seconds_y < seconds_x {
        return Err(Error::Reputation("whole_days: y precedes x".into()));
    }
    Ok(((seconds_y - seconds_x) / 86_400) as u64)
}

pub fn base_u(a_days: u64) -> u64 {
    BASE_AT_AGE_0 + ((900_000 * a_days.min(AGE_NORMALIZATION_DAYS)) / AGE_NORMALIZATION_DAYS)
}

pub fn penalty_n(confirmed: &[(u8, u64)], table: &DecayTable) -> u128 {
    confirmed
        .iter()
        .map(|&(severity, t_days)| (severity as u128) * (table.decay(t_days) as u128))
        .sum()
}

pub fn reputation_formula_u(base_u: u64, c: u64, penalty_n: u128) -> u64 {
    let c1 = (c.min(C_CAP) + 1) as u128;
    let numerator = base_u as u128 * c1 * DECAY_SCALE;
    let denominator = c1 * DECAY_SCALE + PENALTY_WEIGHT.saturating_mul(penalty_n);
    ((numerator / denominator).min(MICRO_SCALE as u128)) as u64
}

pub fn is_provisional(a_days: u64, c: u64) -> bool {
    a_days < GATE_AGE_DAYS || c < GATE_C
}

pub fn apply_provisional_cap(rep_u: u64, a_days: u64, c: u64) -> u64 {
    if is_provisional(a_days, c) {
        rep_u.min(PROVISIONAL_CAP_U)
    } else {
        rep_u
    }
}

pub fn quota_q(reputation_u: u64) -> u64 {
    QUOTA_BASE + ((QUOTA_SLOPE * reputation_u) / MICRO_SCALE)
}

pub fn next_block_eligible(reputation_u: u64) -> bool {
    reputation_u >= INCLUSION_LATENCY_THRESHOLD_U
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn from_bytes_rejects_wrong_hash() {
        assert!(DecayTable::from_bytes(b"not json").is_err());
    }

    #[test]
    fn decay_boundary_values() {
        let t = DecayTable::builtin();
        assert_eq!(t.decay(0), 1_000_000_000);
        assert_eq!(t.decay(DECAY_MAX_DAYS), 39_512);
        assert_eq!(t.decay(DECAY_MAX_DAYS + 1), 0);
    }

    #[test]
    fn builtin_returns_same_reference() {
        let a = DecayTable::builtin();
        let b = DecayTable::builtin();
        assert!(std::ptr::eq(a, b));
    }

    #[test]
    fn base_u_parenthesization_at_age_zero() {
        assert_eq!(base_u(0), 100_000);
        assert_eq!(base_u(730), 1_000_000);
        assert_eq!(base_u(10_000), 1_000_000);
    }

    #[test]
    fn quota_parenthesization_at_sub_unit_reputation() {
        assert_eq!(quota_q(359_236), 3_692);
        assert_eq!(quota_q(100_000), 1_100);
        assert_eq!(quota_q(1_000_000), 10_100);
    }

    #[test]
    fn provisional_cap_is_ceiling_never_floor() {
        assert_eq!(apply_provisional_cap(135_753, 29, 10), 100_000);
        assert_eq!(apply_provisional_cap(76_717, 29, 10), 76_717);
        assert_eq!(apply_provisional_cap(135_753, 30, 10), 135_753);
    }

    #[test]
    fn c_cap_applies_inside_formula() {
        assert_eq!(
            reputation_formula_u(1_000_000, 500, 0),
            reputation_formula_u(1_000_000, 5_000, 0)
        );
    }

    proptest! {
        #[test]
        fn reputation_monotone_in_a_and_c(
            a in 0u64..2_000,
            c in 0u64..600,
            pen in 0u128..100_000_000_000,
        ) {
            let r = reputation_formula_u(base_u(a), c, pen);
            prop_assert!(reputation_formula_u(base_u(a + 1), c, pen) >= r);
            prop_assert!(reputation_formula_u(base_u(a), c + 1, pen) >= r);
            prop_assert!(r <= 1_000_000);
        }
    }
}
