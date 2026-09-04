use crate::confirmation::independent;
use crate::coverage::within_days_ending_at;
use crate::objects::audit::Verdict;

pub const UNAUDITABLE_HORIZON_DAYS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedBy<'a> {
    pub auditor_id: &'a str,
    pub sealed_at_s: i64,
}

#[derive(Debug, Clone)]
pub struct VerdictRecord<'a> {
    pub sealed_by: SealedBy<'a>,
    pub verdict: Verdict,
}

pub fn clears(verdict: &Verdict) -> bool {
    matches!(
        verdict,
        Verdict::Consistent
            | Verdict::Inconsistent
            | Verdict::DynamicVariance
            | Verdict::LinkVariance
            | Verdict::LinkInconsistent
    )
}

pub fn unauditable_at(
    blocking: &[SealedBy<'_>],
    records: &[VerdictRecord<'_>],
    n_sealed_at_s: i64,
    horizon_days: u64,
) -> bool {
    let live: Vec<&SealedBy<'_>> = blocking
        .iter()
        .filter(|b| within_days_ending_at(b.sealed_at_s, n_sealed_at_s, horizon_days))
        .collect();
    live.iter().enumerate().any(|(i, first)| {
        live[i + 1..].iter().any(|second| {
            independent(first.auditor_id, second.auditor_id)
                && !cleared(first, second, records, n_sealed_at_s)
        })
    })
}

fn cleared(
    first: &SealedBy<'_>,
    second: &SealedBy<'_>,
    records: &[VerdictRecord<'_>],
    n_sealed_at_s: i64,
) -> bool {
    let later = first.sealed_at_s.max(second.sealed_at_s);
    records.iter().any(|r| {
        clears(&r.verdict)
            && r.sealed_by.sealed_at_s > later
            && r.sealed_by.sealed_at_s <= n_sealed_at_s
            && independent(r.sealed_by.auditor_id, first.auditor_id)
            && independent(r.sealed_by.auditor_id, second.auditor_id)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;
    const N: i64 = 100 * DAY;

    fn at(auditor_id: &str, sealed_at_s: i64) -> SealedBy<'_> {
        SealedBy {
            auditor_id,
            sealed_at_s,
        }
    }

    fn consistent(auditor_id: &str, sealed_at_s: i64) -> VerdictRecord<'_> {
        VerdictRecord {
            sealed_by: at(auditor_id, sealed_at_s),
            verdict: Verdict::Consistent,
        }
    }

    #[test]
    fn one_blocking_record_never_suffices() {
        assert!(!unauditable_at(&[], &[], N, UNAUDITABLE_HORIZON_DAYS));
        assert!(!unauditable_at(
            &[at("audit.example.org", N - DAY)],
            &[],
            N,
            UNAUDITABLE_HORIZON_DAYS
        ));
    }

    #[test]
    fn a_blocking_record_sealed_at_n_counts_one_above_does_not() {
        let earlier = at("audit.example.org", N - DAY);
        assert!(unauditable_at(
            &[earlier, at("checker.sample.net", N)],
            &[],
            N,
            UNAUDITABLE_HORIZON_DAYS
        ));
        assert!(!unauditable_at(
            &[earlier, at("checker.sample.net", N + 1)],
            &[],
            N,
            UNAUDITABLE_HORIZON_DAYS
        ));
    }

    #[test]
    fn clearing_must_be_strictly_after_the_later_blocking_record() {
        let blocking = [
            at("audit.example.org", N - 10 * DAY),
            at("checker.sample.net", N - 5 * DAY),
        ];
        assert!(unauditable_at(
            &blocking,
            &[consistent("verify.other.com", N - 5 * DAY)],
            N,
            UNAUDITABLE_HORIZON_DAYS
        ));
        assert!(!unauditable_at(
            &blocking,
            &[consistent("verify.other.com", N - 5 * DAY + 1)],
            N,
            UNAUDITABLE_HORIZON_DAYS
        ));
    }

    #[test]
    fn a_clearing_record_sealed_at_n_clears() {
        let blocking = [
            at("audit.example.org", N - 10 * DAY),
            at("checker.sample.net", N - 5 * DAY),
        ];
        assert!(!unauditable_at(
            &blocking,
            &[consistent("verify.other.com", N)],
            N,
            UNAUDITABLE_HORIZON_DAYS
        ));
    }

    #[test]
    fn every_independent_pair_must_be_cleared() {
        let blocking = [
            at("audit.example.org", N - 10 * DAY),
            at("checker.sample.net", N - 8 * DAY),
            at("eye.other.com", N - 5 * DAY),
        ];
        let clears_two_pairs = [consistent("verify.other.com", N - DAY)];
        assert!(unauditable_at(
            &blocking,
            &clears_two_pairs,
            N,
            UNAUDITABLE_HORIZON_DAYS
        ));
        let clears_all = [
            consistent("verify.other.com", N - DAY),
            consistent("watch.fourth.io", N - DAY),
        ];
        assert!(!unauditable_at(
            &blocking,
            &clears_all,
            N,
            UNAUDITABLE_HORIZON_DAYS
        ));
    }

    #[test]
    fn a_smaller_horizon_ages_blocking_records_out_sooner() {
        let blocking = [
            at("audit.example.org", N - 10 * DAY),
            at("checker.sample.net", N - 5 * DAY),
        ];
        assert!(unauditable_at(&blocking, &[], N, 11));
        assert!(!unauditable_at(&blocking, &[], N, 10));
    }
}
