mod schedule;
pub use schedule::{Amendment, Schedule, ScheduleReplay, LOG_TIMESTAMP_MAX_S};

pub struct ParamSpec {
    pub name: &'static str,
    pub default: Option<i64>,
    pub min: Option<i64>,
    pub max: Option<i64>,
}

const fn p(
    name: &'static str,
    default: Option<i64>,
    min: Option<i64>,
    max: Option<i64>,
) -> ParamSpec {
    ParamSpec {
        name,
        default,
        min,
        max,
    }
}

pub const PARAMS: &[ParamSpec] = &[
    p("block_cadence_seconds", Some(3600), Some(1), Some(86400)),
    p(
        "block_decompressed_cap_bytes",
        Some(268_435_456),
        Some(65_537),
        None,
    ),
    p("checkpoint_witness_quorum", Some(0), Some(0), None),
    p("extract_cap_bytes", Some(32768), Some(2), None),
    p("links_cap_bytes", Some(4096), Some(21), None),
    p("link_url_cap_bytes", Some(2048), Some(14), None),
    p("summary_cap_bytes", Some(2048), Some(12), None),
    p("url_cap_bytes", Some(2048), Some(14), None),
    p("payload_window_days", Some(180), Some(30), None),
    p("mirror_retention_days", Some(90), Some(30), None),
    p("record_seal_blocks", Some(24), Some(1), None),
    p("domain_block_entries_max", Some(10000), Some(1), None),
    p("labeler_block_entries_max", Some(1000), Some(1), None),
    p("max_inclusion_blocks", Some(4), Some(1), None),
    p(
        "ingest_budget_bytes_day",
        Some(1_073_741_824),
        Some(1_048_576),
        None,
    ),
    p("feed_window", Some(1000), Some(1), None),
    p("clock_skew_seconds", Some(600), None, None),
    p("keyset_cache_ttl_seconds", Some(86400), None, None),
    p("baseline_poll_seconds", Some(86400), None, None),
    p("quota_base", Some(1000), Some(1), None),
    p("recovery_window_days", Some(7), Some(1), None),
    p("param_grace_days", Some(7), Some(1), None),
    p("declaration_activation_blocks", Some(24), Some(0), None),
];

pub fn spec(name: &str) -> Option<&'static ParamSpec> {
    PARAMS.iter().find(|s| s.name == name)
}

type EffLookup<'a> = &'a dyn Fn(&str) -> i128;

struct ComboRule {
    participants: &'static [&'static str],
    description: &'static str,
    holds: fn(EffLookup) -> bool,
}

/// WIST-4 §5's combination rules: the bounds a value satisfies only
/// together with another parameter's value in the same map.
const COMBO_RULES: &[ComboRule] = &[
    ComboRule {
        participants: &["links_cap_bytes", "link_url_cap_bytes"],
        description: "links_cap_bytes must not be below link_url_cap_bytes + 21",
        holds: |eff| eff("links_cap_bytes") >= eff("link_url_cap_bytes") + 21,
    },
    ComboRule {
        participants: &["mirror_retention_days", "payload_window_days"],
        description: "mirror_retention_days must not be below payload_window_days / 6",
        holds: |eff| eff("mirror_retention_days") * 6 >= eff("payload_window_days"),
    },
    ComboRule {
        participants: &["labeler_block_entries_max", "domain_block_entries_max"],
        description: "labeler_block_entries_max must not exceed domain_block_entries_max",
        holds: |eff| eff("labeler_block_entries_max") <= eff("domain_block_entries_max"),
    },
];

pub const WIRE_INTEGER_MAX: i64 = 9_007_199_254_740_991;

pub fn validate_value(name: &str, value: i64) -> Result<(), crate::Error> {
    let parameter = spec(name)
        .ok_or_else(|| crate::Error::Parameter(format!("unknown parameter identifier {name:?}")))?;
    if !(-WIRE_INTEGER_MAX..=WIRE_INTEGER_MAX).contains(&value)
        || parameter.min.is_some_and(|min| value < min)
        || parameter.max.is_some_and(|max| value > max)
    {
        return Err(crate::Error::Parameter(format!(
            "{name} = {value} is outside the WIST-4 §5 bounds"
        )));
    }
    Ok(())
}

pub fn validate_combinations(lookup: impl Fn(&str) -> i64) -> Result<(), crate::Error> {
    let eff = |name: &str| i128::from(lookup(name));
    for rule in COMBO_RULES {
        if !(rule.holds)(&eff) {
            return Err(crate::Error::Parameter(rule.description.into()));
        }
    }
    Ok(())
}

pub fn validate(name: &str, value: i64, lookup: impl Fn(&str) -> i64) -> Result<(), crate::Error> {
    validate_value(name, value)?;
    let eff = |n: &str| i128::from(if n == name { value } else { lookup(n) });
    for rule in COMBO_RULES {
        if rule.participants.contains(&name) && !(rule.holds)(&eff) {
            return Err(crate::Error::Parameter(rule.description.into()));
        }
    }
    Ok(())
}

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

    fn defaults(name: &str) -> i64 {
        spec(name).unwrap().default.unwrap()
    }

    #[test]
    fn combination_boundaries() {
        assert!(validate("link_url_cap_bytes", 4076, defaults).is_err());
        validate("link_url_cap_bytes", 4075, defaults).unwrap();
        assert!(validate("links_cap_bytes", 2068, defaults).is_err());
        validate("links_cap_bytes", 2069, defaults).unwrap();
        assert!(validate("payload_window_days", 541, defaults).is_err());
        validate("payload_window_days", 540, defaults).unwrap();
        assert!(validate("mirror_retention_days", 29, defaults).is_err());
        validate("mirror_retention_days", 30, defaults).unwrap();
        assert!(validate("labeler_block_entries_max", 10001, defaults).is_err());
        validate("labeler_block_entries_max", 10000, defaults).unwrap();
        assert!(validate("domain_block_entries_max", 999, defaults).is_err());
        validate("domain_block_entries_max", 1000, defaults).unwrap();
        assert!(validate("mirror_retention_days", 30, |name| {
            if name == "payload_window_days" {
                181
            } else {
                defaults(name)
            }
        })
        .is_err());
    }

    #[test]
    fn wire_sized_intermediates_do_not_overflow() {
        validate("links_cap_bytes", WIRE_INTEGER_MAX, defaults).unwrap();
        assert!(validate("link_url_cap_bytes", WIRE_INTEGER_MAX, defaults).is_err());
        validate("mirror_retention_days", WIRE_INTEGER_MAX, defaults).unwrap();
        assert!(validate("payload_window_days", WIRE_INTEGER_MAX, defaults).is_err());
        assert!(validate_combinations(|_| WIRE_INTEGER_MAX).is_err());
        validate_combinations(|name| {
            if name == "link_url_cap_bytes" {
                WIRE_INTEGER_MAX - 21
            } else if name == "links_cap_bytes" || name == "mirror_retention_days" {
                WIRE_INTEGER_MAX
            } else {
                defaults(name)
            }
        })
        .unwrap();
    }

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
