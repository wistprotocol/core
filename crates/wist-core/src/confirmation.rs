use crate::error::Error;

pub const CONFIRM_WINDOW_HOURS: u64 = 72;
pub const INCONSISTENT_EFFECTIVE_BELOW: u64 = 300_000;
pub const SEVERITY_MINOR_FLOOR: u64 = 150_000;
pub const SEVERITY_MISLEADING_FLOOR: u64 = 50_000;

#[derive(Debug, Clone)]
pub struct CandidateRecord<'a> {
    pub block_height: u64,
    pub entry_index: u64,
    pub block_sealed_at_s: i64,
    pub auditor_id: &'a str,
    pub effective_similarity: u64,
}

pub fn independent(a: &str, b: &str) -> bool {
    fn suffix(host: &str) -> Option<(&str, &str)> {
        let mut labels = host.rsplit('.');
        Some((labels.next()?, labels.next()?))
    }
    match (suffix(a), suffix(b)) {
        (Some(sa), Some(sb)) => sa != sb,
        _ => true,
    }
}

pub fn validate_log_order(records: &[CandidateRecord]) -> Result<(), Error> {
    for pair in records.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if (next.block_height, next.entry_index) <= (prev.block_height, prev.entry_index) {
            return Err(Error::Confirmation("records are not in Log order".into()));
        }
        if next.block_sealed_at_s < prev.block_sealed_at_s {
            return Err(Error::Confirmation(
                "sealed_at decreases in Log order".into(),
            ));
        }
    }
    Ok(())
}

pub fn confirming_index(
    records: &[CandidateRecord],
    window_hours: u64,
) -> Result<Option<usize>, Error> {
    validate_log_order(records)?;
    let window_s = (window_hours as i64) * 3_600;
    for (i, record) in records.iter().enumerate() {
        let confirms = records[..i].iter().any(|earlier| {
            independent(earlier.auditor_id, record.auditor_id)
                && record.block_sealed_at_s - earlier.block_sealed_at_s <= window_s
        });
        if confirms {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

pub fn ci_severity(records: &[CandidateRecord], confirming_index: usize) -> Result<u8, Error> {
    let sim = records[..=confirming_index]
        .iter()
        .map(|r| r.effective_similarity)
        .max()
        .ok_or_else(|| Error::Confirmation("empty confirming set".into()))?;
    if sim >= INCONSISTENT_EFFECTIVE_BELOW {
        return Err(Error::Confirmation(format!(
            "effective similarity {sim} is not in the inconsistent band"
        )));
    }
    Ok(if sim >= SEVERITY_MINOR_FLOOR {
        1
    } else if sim >= SEVERITY_MISLEADING_FLOOR {
        2
    } else {
        3
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: i64 = 3_600;

    fn rec(height: u64, entry: u64, sealed_at_s: i64, auditor_id: &str) -> CandidateRecord<'_> {
        CandidateRecord {
            block_height: height,
            entry_index: entry,
            block_sealed_at_s: sealed_at_s,
            auditor_id,
            effective_similarity: 0,
        }
    }

    fn seq<'a>(specs: &[(i64, &'a str)]) -> Vec<CandidateRecord<'a>> {
        specs
            .iter()
            .enumerate()
            .map(|(i, &(hours, auditor))| rec(i as u64 + 1, 0, hours * HOUR, auditor))
            .collect()
    }

    #[test]
    fn distinct_two_label_suffixes_are_independent() {
        assert!(independent("audit.example.net", "checker.example.org"));
    }

    #[test]
    fn shared_two_label_suffix_is_dependent() {
        assert!(!independent("a.example.org", "b.example.org"));
    }

    #[test]
    fn shared_public_suffix_pair_is_dependent() {
        assert!(!independent("a.com.br", "b.com.br"));
    }

    #[test]
    fn equal_hosts_are_dependent() {
        assert!(!independent("audit.example.org", "audit.example.org"));
    }

    #[test]
    fn shared_single_label_is_independent() {
        assert!(independent("a.example.org", "b.sample.org"));
    }

    #[test]
    fn parent_and_subdomain_are_dependent() {
        assert!(!independent("example.org", "a.example.org"));
    }

    #[test]
    fn no_records_no_confirmation() {
        assert_eq!(confirming_index(&[], CONFIRM_WINDOW_HOURS).unwrap(), None);
    }

    #[test]
    fn single_record_never_confirms() {
        let records = seq(&[(0, "a.example.org")]);
        assert_eq!(
            confirming_index(&records, CONFIRM_WINDOW_HOURS).unwrap(),
            None
        );
    }

    #[test]
    fn independent_pair_inside_window_confirms_at_the_second() {
        let records = seq(&[(0, "audit.example.net"), (10, "checker.example.org")]);
        assert_eq!(
            confirming_index(&records, CONFIRM_WINDOW_HOURS).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn same_auditor_never_confirms() {
        let records = seq(&[(0, "audit.example.net"), (10, "audit.example.net")]);
        assert_eq!(
            confirming_index(&records, CONFIRM_WINDOW_HOURS).unwrap(),
            None
        );
    }

    #[test]
    fn dependent_auditors_never_confirm() {
        let records = seq(&[(0, "a.example.org"), (10, "b.example.org")]);
        assert_eq!(
            confirming_index(&records, CONFIRM_WINDOW_HOURS).unwrap(),
            None
        );
    }

    #[test]
    fn window_boundary_is_inclusive() {
        let at = seq(&[(0, "audit.example.net"), (72, "checker.example.org")]);
        assert_eq!(
            confirming_index(&at, CONFIRM_WINDOW_HOURS).unwrap(),
            Some(1)
        );
        let mut past = seq(&[(0, "audit.example.net"), (72, "checker.example.org")]);
        past[1].block_sealed_at_s += 1;
        assert_eq!(confirming_index(&past, CONFIRM_WINDOW_HOURS).unwrap(), None);
    }

    #[test]
    fn stale_first_record_does_not_block_a_later_pair() {
        let records = seq(&[
            (0, "audit.example.net"),
            (100, "checker.example.org"),
            (110, "watch.sample.net"),
        ]);
        assert_eq!(
            confirming_index(&records, CONFIRM_WINDOW_HOURS).unwrap(),
            Some(2)
        );
    }

    #[test]
    fn pair_may_skip_over_a_dependent_record() {
        let records = seq(&[
            (0, "audit.example.net"),
            (10, "peer.example.net"),
            (20, "checker.example.org"),
        ]);
        assert_eq!(
            confirming_index(&records, CONFIRM_WINDOW_HOURS).unwrap(),
            Some(2)
        );
    }

    #[test]
    fn earliest_satisfying_record_wins() {
        let records = seq(&[
            (0, "audit.example.net"),
            (10, "checker.example.org"),
            (20, "watch.sample.net"),
        ]);
        assert_eq!(
            confirming_index(&records, CONFIRM_WINDOW_HOURS).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn zero_window_needs_a_shared_block() {
        let shared = vec![
            rec(5, 0, 100, "audit.example.net"),
            rec(5, 1, 100, "checker.example.org"),
        ];
        assert_eq!(confirming_index(&shared, 0).unwrap(), Some(1));
        let split = seq(&[(0, "audit.example.net"), (1, "checker.example.org")]);
        assert_eq!(confirming_index(&split, 0).unwrap(), None);
    }

    #[test]
    fn out_of_log_order_records_are_rejected() {
        let descending = vec![
            rec(2, 0, 100, "audit.example.net"),
            rec(1, 0, 200, "checker.example.org"),
        ];
        assert!(confirming_index(&descending, CONFIRM_WINDOW_HOURS).is_err());
        let time_reversed = vec![
            rec(1, 0, 200, "audit.example.net"),
            rec(2, 0, 100, "checker.example.org"),
        ];
        assert!(confirming_index(&time_reversed, CONFIRM_WINDOW_HOURS).is_err());
        let duplicate_position = vec![
            rec(1, 0, 100, "audit.example.net"),
            rec(1, 0, 100, "checker.example.org"),
        ];
        assert!(confirming_index(&duplicate_position, CONFIRM_WINDOW_HOURS).is_err());
    }

    fn with_sims<'a>(records: &mut [CandidateRecord<'a>], sims: &[u64]) {
        for (record, &sim) in records.iter_mut().zip(sims) {
            record.effective_similarity = sim;
        }
    }

    #[test]
    fn severity_bands_read_the_extremum_of_the_closed_set() {
        let mut records = seq(&[(0, "audit.example.net"), (10, "checker.example.org")]);
        with_sims(&mut records, &[220_000, 180_000]);
        assert_eq!(ci_severity(&records, 1).unwrap(), 1);
        with_sims(&mut records, &[120_000, 90_000]);
        assert_eq!(ci_severity(&records, 1).unwrap(), 2);
        with_sims(&mut records, &[40_000, 10_000]);
        assert_eq!(ci_severity(&records, 1).unwrap(), 3);
    }

    #[test]
    fn records_past_the_confirming_index_cannot_move_severity() {
        let mut records = seq(&[
            (0, "audit.example.net"),
            (10, "checker.example.org"),
            (20, "watch.sample.net"),
        ]);
        with_sims(&mut records, &[40_000, 10_000, 250_000]);
        assert_eq!(ci_severity(&records, 1).unwrap(), 3);
    }

    #[test]
    fn severity_boundaries_partition_at_the_edges() {
        let mut records = seq(&[(0, "audit.example.net"), (10, "checker.example.org")]);
        for (sim, severity) in [(150_000, 1), (149_999, 2), (50_000, 2), (49_999, 3), (0, 3)] {
            with_sims(&mut records, &[0, sim]);
            assert_eq!(ci_severity(&records, 1).unwrap(), severity, "sim {sim}");
        }
    }

    #[test]
    fn severity_rejects_a_similarity_outside_the_inconsistent_band() {
        let mut records = seq(&[(0, "audit.example.net"), (10, "checker.example.org")]);
        with_sims(&mut records, &[0, 300_000]);
        assert!(ci_severity(&records, 1).is_err());
    }
}
