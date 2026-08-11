use crate::scenario::{band_p_1e7, Band, MixEntry, Scenario};
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use wist_core::sampling;
use wist_core::vrf;

#[derive(Debug, Serialize)]
pub struct SimResult {
    pub selected: Vec<Vec<u64>>,
    pub mean_per_day: f64,
    pub min_day: u64,
    pub max_day: u64,
    pub stddev: f64,
    pub expected_per_day: f64,
    pub rel_deviation: f64,
}

fn h32(seed: &str, label: &str, indices: &[u64]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
    h.update(b"/");
    h.update(label.as_bytes());
    for i in indices {
        h.update(b"/");
        h.update(i.to_be_bytes());
    }
    h.finalize().into()
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

pub fn band_counts(total: u64, mix: &[MixEntry]) -> Vec<(Band, u64)> {
    let mut counts: Vec<(Band, u64)> = mix
        .iter()
        .map(|m| (m.band, total * m.share_bp as u64 / 10_000))
        .collect();
    let assigned: u64 = counts.iter().map(|(_, n)| n).sum();
    let largest = mix
        .iter()
        .enumerate()
        .max_by_key(|(_, m)| m.share_bp)
        .map(|(i, _)| i)
        .unwrap();
    counts[largest].1 += total - assigned;
    counts
}

fn block_sizes(total: u64, blocks: u32) -> Vec<u64> {
    let base = total / blocks as u64;
    let extra = total % blocks as u64;
    (0..blocks as u64)
        .map(|b| base + u64::from(b < extra))
        .collect()
}

pub fn expected_selected_per_day(sc: &Scenario) -> f64 {
    block_sizes(sc.deltas_per_day(), sc.blocks_per_day)
        .iter()
        .flat_map(|&n| band_counts(n, &sc.mix))
        .map(|(b, n)| n as f64 * band_p_1e7(b) as f64 / 1e7)
        .sum()
}

pub fn run(sc: &Scenario) -> SimResult {
    sc.validate().expect("invalid scenario");
    let auditor_seeds: Vec<[u8; 32]> = (0..sc.auditors as u64)
        .map(|k| h32(&sc.seed, "auditor", &[k]))
        .collect();
    let mut selected = vec![vec![0u64; sc.days as usize]; sc.auditors as usize];
    for day in 0..sc.days as u64 {
        let sizes = block_sizes(sc.deltas_per_day(), sc.blocks_per_day);
        let day_counts: Vec<Vec<u64>> = (0..sc.blocks_per_day as u64)
            .into_par_iter()
            .map(|b| {
                let n = sizes[b as usize];
                let block_hash = format!("sha256:{}", hex(&h32(&sc.seed, "block", &[day, b])));
                let alpha = sampling::alpha_from_block_hash(&block_hash).unwrap();
                let betas: Vec<[u8; 64]> = auditor_seeds
                    .iter()
                    .map(|sk| {
                        let pi = vrf::prove(sk, &alpha).unwrap();
                        vrf::proof_to_hash(&pi).unwrap()
                    })
                    .collect();
                let counts = band_counts(n, &sc.mix);
                let mut per_auditor = vec![0u64; sc.auditors as usize];
                let mut i = 0u64;
                for (band, m) in counts {
                    let p = band_p_1e7(band);
                    for _ in 0..m {
                        let id = format!("sha256:{}", hex(&h32(&sc.seed, "delta", &[day, b, i])));
                        for (k, beta) in betas.iter().enumerate() {
                            let d = sampling::draw(beta, &id);
                            if sampling::selected(d, p) {
                                per_auditor[k] += 1;
                            }
                        }
                        i += 1;
                    }
                }
                per_auditor
            })
            .collect();
        for per_auditor in day_counts {
            for (k, c) in per_auditor.iter().enumerate() {
                selected[k][day as usize] += c;
            }
        }
    }
    let expected = expected_selected_per_day(sc);
    let all: Vec<u64> = selected.iter().flatten().copied().collect();
    let mean = all.iter().sum::<u64>() as f64 / all.len() as f64;
    let stddev =
        (all.iter().map(|&v| (v as f64 - mean).powi(2)).sum::<f64>() / all.len() as f64).sqrt();
    SimResult {
        min_day: *all.iter().min().unwrap(),
        max_day: *all.iter().max().unwrap(),
        mean_per_day: mean,
        stddev,
        expected_per_day: expected,
        rel_deviation: (mean - expected) / expected,
        selected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{band_p_1e7, Band, Scenario};

    fn tiny() -> Scenario {
        let mut sc = Scenario::tier("small").unwrap();
        sc.pages = 1_000_000;
        sc.churn_bp = 10;
        sc.blocks_per_day = 2;
        sc.days = 2;
        sc.auditors = 2;
        sc.seed = "tiny".into();
        sc
    }

    #[test]
    fn deterministic_same_seed_same_result() {
        let sc = tiny();
        let a = run(&sc);
        let b = run(&sc);
        assert_eq!(a.selected, b.selected);
    }

    #[test]
    fn different_seed_different_selection() {
        let sc = tiny();
        let mut sc2 = tiny();
        sc2.seed = "tiny-2".into();
        assert_ne!(run(&sc).selected, run(&sc2).selected);
    }

    #[test]
    fn band_counts_partition_exactly() {
        let mix = Scenario::tier("large").unwrap().mix;
        let counts = band_counts(1_000_003, &mix);
        assert_eq!(counts.iter().map(|(_, n)| n).sum::<u64>(), 1_000_003);
        let mature = counts.iter().find(|(b, _)| *b == Band::Mature).unwrap().1;
        assert!((mature as i64 - 600_002).abs() <= 2);
    }

    #[test]
    fn expectation_formula() {
        let sc = Scenario::tier("small").unwrap();
        let sizes = block_sizes(sc.deltas_per_day(), sc.blocks_per_day);
        let mature: u64 = sizes
            .iter()
            .map(|&n| {
                band_counts(n, &sc.mix)
                    .into_iter()
                    .find(|(b, _)| *b == Band::Mature)
                    .unwrap()
                    .1
            })
            .sum();
        let provisional: u64 = sizes
            .iter()
            .map(|&n| {
                band_counts(n, &sc.mix)
                    .into_iter()
                    .find(|(b, _)| *b == Band::Provisional)
                    .unwrap()
                    .1
            })
            .sum();
        assert_eq!(mature, 18_008);
        assert_eq!(provisional, 1_992);
        let expect = mature as f64 * band_p_1e7(Band::Mature) as f64 / 1e7
            + provisional as f64 * band_p_1e7(Band::Provisional) as f64 / 1e7;
        assert!((expect - 937.84).abs() < 1e-6);
        assert!((expected_selected_per_day(&sc) - expect).abs() < 1e-6);
    }

    #[test]
    fn simulated_within_three_sigma_of_expected() {
        let mut sc = Scenario::tier("small").unwrap();
        sc.pages = 1_000_000;
        sc.churn_bp = 1_000;
        sc.days = 1;
        sc.auditors = 1;
        sc.seed = "sigma".into();
        let counts = band_counts(sc.deltas_per_day(), &sc.mix);
        let variance: f64 = counts
            .iter()
            .map(|(b, m)| {
                let p = band_p_1e7(*b) as f64 / 1e7;
                *m as f64 * p * (1.0 - p)
            })
            .sum();
        let r = run(&sc);
        let dev = (r.selected[0][0] as f64 - r.expected_per_day).abs();
        assert!(
            dev <= 3.0 * variance.sqrt(),
            "dev {dev} sigma {}",
            variance.sqrt()
        );
    }
}
