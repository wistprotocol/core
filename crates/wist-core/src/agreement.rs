use std::collections::BTreeSet;

const MICRO: u128 = 1_000_000;

pub fn link_agreement(
    declared: &[String],
    observed: &[String],
    declared_total: u64,
    observed_total: u64,
) -> u64 {
    let d: BTreeSet<&str> = declared.iter().map(String::as_str).collect();
    let o: BTreeSet<&str> = observed.iter().map(String::as_str).collect();
    let subset = if d.is_empty() && o.is_empty() {
        MICRO
    } else {
        let inter = d.intersection(&o).count() as u128;
        let union = d.union(&o).count() as u128;
        inter * MICRO / union
    };
    let count = if declared_total == 0 && observed_total == 0 {
        MICRO
    } else {
        let lo = declared_total.min(observed_total) as u128;
        let hi = declared_total.max(observed_total) as u128;
        lo * MICRO / hi
    };
    subset.min(count) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_dedup_and_order_is_irrelevant() {
        let a = vec!["https://a/1".to_string(), "https://a/2".to_string()];
        let b = vec!["https://a/2".to_string(), "https://a/1".to_string(), "https://a/1".to_string()];
        assert_eq!(link_agreement(&a, &b, 2, 2), 1_000_000);
    }

    #[test]
    fn min_of_the_two_dimensions_wins() {
        let a = vec!["https://a/1".to_string()];
        assert_eq!(link_agreement(&a, &a, 1, 4), 250_000);
        let b = vec!["https://a/2".to_string()];
        assert_eq!(link_agreement(&a, &b, 1, 1), 0);
    }
}
