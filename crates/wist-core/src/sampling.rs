use crate::confirmation::independent;
use crate::crypto::hex_decode;
use crate::error::Error;
use sha2::{Digest, Sha256};

pub const SAMPLING_FLOOR_1E7: u64 = 200_000;
pub const SAMPLING_CEILING_1E7: u64 = 5_000_000;
pub const SAMPLING_SLOPE_PER_MICRO: i64 = 3;

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

/// The §9 sampling constants in force at the audited Block's `sealed_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingConstants {
    pub floor_1e7: u64,
    pub ceiling_1e7: u64,
    pub slope_per_micro: i64,
}

pub const DEFAULT_SAMPLING: SamplingConstants = SamplingConstants {
    floor_1e7: SAMPLING_FLOOR_1E7,
    ceiling_1e7: SAMPLING_CEILING_1E7,
    slope_per_micro: SAMPLING_SLOPE_PER_MICRO,
};

impl Default for SamplingConstants {
    fn default() -> Self {
        DEFAULT_SAMPLING
    }
}

pub fn p_1e7(
    reputation_u: u64,
    level1_sanction: bool,
    escalated_sampling: bool,
    c: &SamplingConstants,
) -> u64 {
    if level1_sanction || escalated_sampling {
        return c.ceiling_1e7;
    }
    let rep = reputation_u.min(1_000_000);
    let rate =
        i128::from(c.floor_1e7) + i128::from(c.slope_per_micro) * i128::from(1_000_000 - rep);
    rate.max(i128::from(c.floor_1e7))
        .min(i128::from(c.ceiling_1e7)) as u64
}

pub fn selected(d: u64, p_1e7: u64) -> bool {
    (d as u128) * 10_000_000 < (p_1e7 as u128) << 64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainDelta<'a> {
    pub publisher: &'a str,
    pub url_host: &'a str,
}

/// `host_seq0_height` is the height sealing the URL host's own seq-0
/// Declaration Entry, when the Log holds one.
pub fn in_selection_domain(
    block_height: u64,
    delta: DomainDelta<'_>,
    host_seq0_height: Option<u64>,
) -> bool {
    delta.url_host == delta.publisher || host_seq0_height.is_none_or(|h| h > block_height)
}

pub fn selection_domain_excluded(
    block_height: u64,
    seq0_declarations: &[(&str, u64)],
    deltas: &[DomainDelta<'_>],
) -> Vec<usize> {
    deltas
        .iter()
        .enumerate()
        .filter(|(_, delta)| {
            let seq0 = seq0_declarations
                .iter()
                .filter(|(host, _)| *host == delta.url_host)
                .map(|(_, height)| *height)
                .min();
            !in_selection_domain(block_height, **delta, seq0)
        })
        .map(|(i, _)| i)
        .collect()
}

pub fn self_audit_barred(auditor_id: &str, publisher: &str) -> bool {
    !independent(auditor_id, publisher)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_1e7_endpoints_and_sanction() {
        assert_eq!(p_1e7(1_000_000, false, false, &DEFAULT_SAMPLING), 200_000);
        assert_eq!(p_1e7(100_000, false, false, &DEFAULT_SAMPLING), 2_900_000);
        assert_eq!(p_1e7(0, false, false, &DEFAULT_SAMPLING), 3_200_000);
        assert_eq!(p_1e7(500_000, true, false, &DEFAULT_SAMPLING), 5_000_000);
        assert_eq!(p_1e7(u64::MAX, false, false, &DEFAULT_SAMPLING), 200_000);
    }

    #[test]
    fn amended_constants_replace_the_compiled_defaults() {
        let amended = SamplingConstants {
            floor_1e7: 400_000,
            ceiling_1e7: 6_000_000,
            slope_per_micro: 5,
        };
        assert_eq!(p_1e7(1_000_000, false, false, &amended), 400_000);
        assert_eq!(p_1e7(0, false, false, &amended), 5_400_000);
        assert_eq!(p_1e7(900_000, false, false, &amended), 900_000);
        assert_eq!(p_1e7(500_000, true, false, &amended), 6_000_000);
        assert_eq!(p_1e7(1_000_000, false, true, &amended), 6_000_000);
        assert_eq!(p_1e7(1_000_000, true, true, &amended), 6_000_000);
    }

    #[test]
    fn an_unbounded_slope_saturates_at_the_ceiling_instead_of_overflowing() {
        let amended = SamplingConstants {
            floor_1e7: 200_000,
            ceiling_1e7: 5_000_000,
            slope_per_micro: i64::MAX,
        };
        assert_eq!(p_1e7(999_999, false, false, &amended), 5_000_000);
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

    const PARENT: DomainDelta<'static> = DomainDelta {
        publisher: "example.com",
        url_host: "blog.example.com",
    };

    #[test]
    fn a_parent_delta_leaves_the_domain_from_the_declaration_height_on() {
        assert!(in_selection_domain(4, PARENT, Some(5)));
        assert!(!in_selection_domain(5, PARENT, Some(5)));
        assert!(!in_selection_domain(u64::MAX, PARENT, Some(5)));
        assert!(in_selection_domain(9, PARENT, None));
    }

    #[test]
    fn a_hosts_own_delta_is_never_excluded() {
        let own = DomainDelta {
            publisher: "blog.example.com",
            url_host: "blog.example.com",
        };
        assert!(in_selection_domain(9, own, Some(5)));
        assert!(in_selection_domain(9, own, Some(0)));
    }

    #[test]
    fn the_earliest_seq0_declaration_for_a_host_decides() {
        let declarations = [("blog.example.com", 12), ("blog.example.com", 5)];
        assert_eq!(
            selection_domain_excluded(9, &declarations, &[PARENT]),
            vec![0]
        );
        assert_eq!(
            selection_domain_excluded(4, &declarations, &[PARENT]),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn exclusion_reads_the_delta_host_not_the_publisher() {
        let declarations = [("example.com", 1)];
        assert_eq!(
            selection_domain_excluded(9, &declarations, &[PARENT]),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn self_audit_bar_is_the_independence_test() {
        assert!(!self_audit_barred("audit.example.org", "shop.example.net"));
        assert!(self_audit_barred("audit.example.net", "blog.example.net"));
        assert!(self_audit_barred("audit.example.net", "audit.example.net"));
        assert!(self_audit_barred("audit.example.net", "example.net"));
    }
}
