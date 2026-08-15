use crate::error::Error;
use crate::reputation::{whole_days, C_CAP};
use crate::verdict::ChangeType;

#[derive(Debug, Clone)]
pub struct DeltaEvent {
    pub height: u64,
    pub sealed_at_s: i64,
}

#[derive(Debug, Clone)]
pub struct ConsistentAudit<'a> {
    pub height: u64,
    pub url: &'a str,
    pub change: ChangeType,
}

#[derive(Debug, Clone)]
pub struct ConfirmedFinding<'a> {
    pub confirming_height: u64,
    pub confirming_sealed_at_s: i64,
    pub delta_id: &'a str,
    pub severity: u8,
}

pub fn most_recent_reset(reset_heights: &[u64], n: u64) -> Option<u64> {
    reset_heights.iter().copied().filter(|&h| h <= n).max()
}

fn in_scope(height: u64, reset: Option<u64>, n: u64) -> bool {
    height <= n && reset.is_none_or(|r| height > r)
}

pub fn age_days(
    accepted: &[DeltaEvent],
    reset: Option<u64>,
    n_height: u64,
    n_sealed_at_s: i64,
) -> Result<u64, Error> {
    let first = accepted
        .iter()
        .filter(|d| in_scope(d.height, reset, n_height))
        .min_by_key(|d| d.height);
    match first {
        Some(d) => whole_days(d.sealed_at_s, n_sealed_at_s),
        None => Ok(0),
    }
}

pub fn c_count(audits: &[ConsistentAudit], reset: Option<u64>, n_height: u64) -> u64 {
    let urls: std::collections::HashSet<&str> = audits
        .iter()
        .filter(|a| {
            in_scope(a.height, reset, n_height)
                && matches!(a.change, ChangeType::New | ChangeType::Update)
        })
        .map(|a| a.url)
        .collect();
    (urls.len() as u64).min(C_CAP)
}

pub fn penalty_inputs(
    findings: &[ConfirmedFinding],
    reset: Option<u64>,
    n_height: u64,
    n_sealed_at_s: i64,
) -> Result<Vec<(u8, u64)>, Error> {
    let mut entries = Vec::new();
    for f in findings {
        if !in_scope(f.confirming_height, reset, n_height) {
            continue;
        }
        let t = whole_days(f.confirming_sealed_at_s, n_sealed_at_s)?;
        entries.push((t, f.delta_id.as_bytes(), f.severity));
    }
    entries.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    Ok(entries.into_iter().map(|(t, _, s)| (s, t)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    #[test]
    fn no_resets_no_bound() {
        assert_eq!(most_recent_reset(&[], 100), None);
    }

    #[test]
    fn latest_reset_at_or_below_n_wins() {
        assert_eq!(most_recent_reset(&[3, 40, 90], 100), Some(90));
        assert_eq!(most_recent_reset(&[3, 40, 90], 89), Some(40));
        assert_eq!(most_recent_reset(&[3, 40, 90], 90), Some(90));
    }

    #[test]
    fn resets_above_n_are_invisible() {
        assert_eq!(most_recent_reset(&[150], 100), None);
    }

    #[test]
    fn age_is_zero_without_an_accepted_delta() {
        assert_eq!(age_days(&[], None, 100, 1000 * DAY).unwrap(), 0);
    }

    #[test]
    fn age_reads_the_first_accepted_delta() {
        let deltas = [
            DeltaEvent {
                height: 10,
                sealed_at_s: 100 * DAY,
            },
            DeltaEvent {
                height: 20,
                sealed_at_s: 200 * DAY,
            },
        ];
        assert_eq!(age_days(&deltas, None, 100, 130 * DAY).unwrap(), 30);
    }

    #[test]
    fn age_counts_whole_days_by_integer_division() {
        let deltas = [DeltaEvent {
            height: 1,
            sealed_at_s: 0,
        }];
        assert_eq!(age_days(&deltas, None, 100, 100 * 3_600).unwrap(), 4);
    }

    #[test]
    fn age_restarts_above_a_reset() {
        let deltas = [
            DeltaEvent {
                height: 10,
                sealed_at_s: 100 * DAY,
            },
            DeltaEvent {
                height: 60,
                sealed_at_s: 300 * DAY,
            },
        ];
        assert_eq!(age_days(&deltas, Some(50), 100, 310 * DAY).unwrap(), 10);
        assert_eq!(age_days(&deltas, Some(60), 100, 310 * DAY).unwrap(), 0);
    }

    #[test]
    fn age_ignores_deltas_above_n() {
        let deltas = [DeltaEvent {
            height: 200,
            sealed_at_s: 100 * DAY,
        }];
        assert_eq!(age_days(&deltas, None, 100, 300 * DAY).unwrap(), 0);
    }

    fn audit(height: u64, url: &str, change: ChangeType) -> ConsistentAudit<'_> {
        ConsistentAudit {
            height,
            url,
            change,
        }
    }

    #[test]
    fn distinct_urls_count_once() {
        let audits = [
            audit(1, "https://a.example/x", ChangeType::New),
            audit(2, "https://a.example/x", ChangeType::Update),
            audit(3, "https://a.example/y", ChangeType::New),
        ];
        assert_eq!(c_count(&audits, None, 100), 2);
    }

    #[test]
    fn attest_and_delete_audits_never_contribute() {
        let audits = [
            audit(1, "https://a.example/x", ChangeType::Attest),
            audit(2, "https://a.example/y", ChangeType::Delete),
        ];
        assert_eq!(c_count(&audits, None, 100), 0);
    }

    #[test]
    fn c_scope_excludes_at_reset_and_above_n() {
        let audits = [
            audit(50, "https://a.example/x", ChangeType::New),
            audit(51, "https://a.example/y", ChangeType::New),
            audit(101, "https://a.example/z", ChangeType::New),
        ];
        assert_eq!(c_count(&audits, Some(50), 100), 1);
    }

    #[test]
    fn c_is_capped() {
        let urls: Vec<String> = (0..C_CAP + 10)
            .map(|i| format!("https://a.example/{i}"))
            .collect();
        let audits: Vec<ConsistentAudit> = urls
            .iter()
            .enumerate()
            .map(|(i, url)| audit(i as u64 + 1, url, ChangeType::New))
            .collect();
        assert_eq!(c_count(&audits, None, 100_000), C_CAP);
    }

    fn finding<'a>(
        height: u64,
        sealed_days: i64,
        delta_id: &'a str,
        severity: u8,
    ) -> ConfirmedFinding<'a> {
        ConfirmedFinding {
            confirming_height: height,
            confirming_sealed_at_s: sealed_days * DAY,
            delta_id,
            severity,
        }
    }

    #[test]
    fn penalties_scoped_above_reset_and_at_most_n() {
        let findings = [
            finding(50, 10, "sha256:aa", 3),
            finding(51, 20, "sha256:bb", 1),
            finding(101, 30, "sha256:cc", 2),
        ];
        let got = penalty_inputs(&findings, Some(50), 100, 40 * DAY).unwrap();
        assert_eq!(got, vec![(1, 20)]);
    }

    #[test]
    fn penalties_ordered_ascending_t_then_delta_id_bytes() {
        let findings = [
            finding(10, 5, "sha256:bb", 1),
            finding(20, 30, "sha256:zz", 2),
            finding(11, 5, "sha256:aa", 3),
        ];
        let got = penalty_inputs(&findings, None, 100, 35 * DAY).unwrap();
        assert_eq!(got, vec![(2, 5), (3, 30), (1, 30)]);
    }

    #[test]
    fn penalty_t_is_whole_days_from_the_confirming_block() {
        let findings = [ConfirmedFinding {
            confirming_height: 1,
            confirming_sealed_at_s: 0,
            delta_id: "sha256:aa",
            severity: 1,
        }];
        let got = penalty_inputs(&findings, None, 100, 100 * 3_600).unwrap();
        assert_eq!(got, vec![(1, 4)]);
    }

    #[test]
    fn confirming_block_after_n_is_an_error() {
        let findings = [finding(50, 100, "sha256:aa", 1)];
        assert!(penalty_inputs(&findings, None, 100, 50 * DAY).is_err());
    }
}
