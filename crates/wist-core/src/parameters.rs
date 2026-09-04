#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterChange {
    pub block_number: u64,
    pub entry_index: u64,
    pub effective_at_s: i64,
    pub value: i64,
}

pub fn value_in_force(default: i64, changes: &[ParameterChange], t_s: i64) -> (i64, Option<usize>) {
    changes
        .iter()
        .enumerate()
        .filter(|(_, c)| c.effective_at_s <= t_s)
        .max_by_key(|(_, c)| (c.effective_at_s, c.block_number, c.entry_index))
        .map(|(i, c)| (c.value, Some(i)))
        .unwrap_or((default, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(
        block_number: u64,
        entry_index: u64,
        effective_at_s: i64,
        value: i64,
    ) -> ParameterChange {
        ParameterChange {
            block_number,
            entry_index,
            effective_at_s,
            value,
        }
    }

    #[test]
    fn no_amendment_means_the_default() {
        assert_eq!(value_in_force(3600, &[], 0), (3600, None));
        assert_eq!(
            value_in_force(3600, &[change(10, 0, 500, 1800)], 499),
            (3600, None)
        );
    }

    #[test]
    fn an_equal_pair_is_broken_by_log_order_not_slice_position() {
        let later_first = [change(12, 0, 500, 1800), change(10, 0, 500, 900)];
        assert_eq!(value_in_force(3600, &later_first, 500), (1800, Some(0)));
    }

    #[test]
    fn entry_index_breaks_ties_only_inside_a_block() {
        let changes = [change(10, 7, 500, 900), change(11, 0, 500, 1800)];
        assert_eq!(value_in_force(3600, &changes, 600), (1800, Some(1)));
        let same_block = [change(10, 7, 500, 900), change(10, 2, 500, 1800)];
        assert_eq!(value_in_force(3600, &same_block, 600), (900, Some(0)));
    }

    #[test]
    fn the_superseded_amendment_is_never_in_force() {
        let changes = [change(10, 0, 500, 900), change(12, 0, 500, 1800)];
        for t in [500, 501, 10_000] {
            assert_eq!(value_in_force(3600, &changes, t), (1800, Some(1)));
        }
    }
}
