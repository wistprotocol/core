mod schedule;
pub use schedule::{
    validate_cadence_transitions, Amendment, CadenceProfile, Schedule, ScheduleReplay,
};

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
        Some(1024),
        None,
    ),
    p("extract_cap_bytes", Some(32768), Some(2), None),
    p("summary_cap_bytes", Some(2048), Some(12), None),
    p("feed_window", Some(1000), Some(1), None),
    p("clock_skew_seconds", Some(600), None, None),
    p("baseline_poll_seconds", Some(86400), None, None),
    p("keyset_cache_ttl_seconds", Some(86400), None, None),
    p("recovery_window_days", Some(7), Some(1), None),
    p("sampling_floor", Some(200_000), Some(1), None),
    p("sampling_ceiling", Some(5_000_000), Some(1), None),
    p("sampling_slope", Some(3), None, None),
    p(
        "similarity_consistent",
        Some(600_000),
        Some(150_002),
        Some(1_000_000),
    ),
    p(
        "similarity_variance_floor",
        Some(300_000),
        Some(150_001),
        Some(300_000),
    ),
    p("shingle_size", Some(8), Some(1), None),
    p("confirm_auditors", Some(2), Some(2), None),
    p("confirm_window_hours", Some(72), Some(1), None),
    p("coverage_deadline_hours", Some(72), Some(1), None),
    p("age_norm_days", Some(730), Some(1), None),
    p("decay_horizon_days", Some(1825), Some(1), Some(1825)),
    p("penalty_weight", Some(5), Some(1), None),
    p("c_cap", Some(500), Some(1), None),
    p("provisional_age_days", Some(30), None, None),
    p("provisional_audits", Some(10), None, None),
    p("provisional_cap_u", Some(100_000), Some(0), None),
    p("quota_base", Some(100), None, None),
    p("quota_slope", Some(10000), None, None),
    p("latency_threshold_u", Some(500_000), None, None),
    p("appeal_window_days", Some(14), Some(1), None),
    p("ruling_deadline_days", Some(30), Some(1), None),
    p("param_grace_days", Some(7), Some(1), None),
    p("payload_window_days", Some(180), Some(30), None),
    p("unauditable_horizon_days", Some(30), Some(7), None),
    p("mirror_retention_days", Some(90), Some(51), None),
    p("appeal_seal_days", Some(7), Some(1), None),
    p("url_cap_bytes", Some(2048), Some(14), None),
    p("links_cap_bytes", Some(4096), Some(21), None),
    p("link_url_cap_bytes", Some(2048), Some(14), None),
    p(
        "link_agreement_consistent",
        Some(600_000),
        Some(2),
        Some(1_000_000),
    ),
    p("link_variance_floor", Some(300_000), Some(1), Some(999999)),
    p("warc_retention_days", Some(90), Some(51), None),
    p("record_seal_blocks", Some(24), Some(1), None),
    p("domain_block_entries_max", Some(10000), Some(1), None),
    p("max_inclusion_blocks", Some(4), Some(1), None),
    p(
        "ingest_budget_bytes_day",
        Some(1_073_741_824),
        Some(1_048_576),
        None,
    ),
    p("min_observed_words", Some(40), Some(1), None),
    p("extension_triggers_max", Some(3), Some(1), None),
    p("epoch_blocks", Some(24), Some(1), None),
    p("observer_checkpoint_budget", Some(1024), Some(1), None),
    p("canary_lead_blocks", Some(24), Some(1), None),
    p("canary_leaves_max", Some(1024), Some(1), None),
    p("canary_commitments_max", Some(8), Some(1), None),
    p("canary_reveal_min_blocks", Some(168), Some(1), None),
    p("canary_lifetime_blocks", Some(1440), Some(2), None),
    p("audit_fetch_cap_bytes", Some(8_388_608), Some(65536), None),
    p(
        "audit_domain_budget_bytes_day",
        Some(1_073_741_824),
        None,
        None,
    ),
    p("audit_redirect_max", Some(5), Some(1), None),
    p("audit_fetch_timeout_seconds", Some(30), Some(1), None),
];

pub fn spec(name: &str) -> Option<&'static ParamSpec> {
    PARAMS.iter().find(|s| s.name == name)
}

const COVERAGE_FAILURES_MAX: i128 = 24;
const COVERAGE_COUNT_WINDOW_S: i128 = 30 * 86400;

type EffLookup<'a> = &'a dyn Fn(&str) -> i128;

struct ComboRule {
    participants: &'static [&'static str],
    description: &'static str,
    holds: fn(EffLookup) -> bool,
}

const COMBO_RULES: &[ComboRule] = &[
    ComboRule {
        participants: &["sampling_floor", "sampling_ceiling"],
        description: "sampling_ceiling must not be below sampling_floor",
        holds: |eff| eff("sampling_ceiling") >= eff("sampling_floor"),
    },
    ComboRule {
        participants: &["similarity_consistent", "similarity_variance_floor"],
        description: "similarity_consistent must be greater than similarity_variance_floor",
        holds: |eff| eff("similarity_consistent") > eff("similarity_variance_floor"),
    },
    ComboRule {
        participants: &["c_cap", "provisional_audits"],
        description: "c_cap must not be below provisional_audits",
        holds: |eff| eff("c_cap") >= eff("provisional_audits"),
    },
    ComboRule {
        participants: &["confirm_window_hours", "block_cadence_seconds"],
        description: "confirm_window_hours must not be shorter than block_cadence_seconds",
        holds: |eff| eff("confirm_window_hours") * 3600 >= eff("block_cadence_seconds"),
    },
    ComboRule {
        participants: &["coverage_deadline_hours", "block_cadence_seconds"],
        description: "coverage_deadline_hours must not be shorter than block_cadence_seconds",
        holds: |eff| eff("coverage_deadline_hours") * 3600 >= eff("block_cadence_seconds"),
    },
    ComboRule {
        participants: &["confirm_window_hours", "block_cadence_seconds"],
        description: "confirm_window_hours / 2 must not be shorter than block_cadence_seconds",
        holds: |eff| (eff("confirm_window_hours") / 2) * 3600 >= eff("block_cadence_seconds"),
    },
    ComboRule {
        participants: &["confirm_window_hours", "coverage_deadline_hours"],
        description: "confirm_window_hours / 2 must not exceed coverage_deadline_hours",
        holds: |eff| eff("confirm_window_hours") / 2 <= eff("coverage_deadline_hours"),
    },
    ComboRule {
        participants: &[
            "coverage_deadline_hours",
            "record_seal_blocks",
            "block_cadence_seconds",
        ],
        description: "coverage_deadline_hours + (record_seal_blocks + coverage_failures_max) blocks must be shorter than 30 whole days",
        holds: |eff| {
            eff("coverage_deadline_hours") * 3600
                + (eff("record_seal_blocks") + COVERAGE_FAILURES_MAX)
                    * eff("block_cadence_seconds")
                < COVERAGE_COUNT_WINDOW_S
        },
    },
    ComboRule {
        participants: &[
            "mirror_retention_days",
            "appeal_window_days",
            "appeal_seal_days",
            "ruling_deadline_days",
        ],
        description: "mirror_retention_days must not be below appeal_window_days + appeal_seal_days + ruling_deadline_days",
        holds: |eff| {
            eff("mirror_retention_days")
                >= eff("appeal_window_days") + eff("appeal_seal_days") + eff("ruling_deadline_days")
        },
    },
    ComboRule {
        participants: &["links_cap_bytes", "link_url_cap_bytes"],
        description: "links_cap_bytes must not be below link_url_cap_bytes + 21",
        holds: |eff| eff("links_cap_bytes") >= eff("link_url_cap_bytes") + 21,
    },
    ComboRule {
        participants: &["link_variance_floor", "link_agreement_consistent"],
        description: "link_variance_floor must be below link_agreement_consistent",
        holds: |eff| eff("link_variance_floor") < eff("link_agreement_consistent"),
    },
    ComboRule {
        participants: &[
            "audit_domain_budget_bytes_day",
            "audit_fetch_cap_bytes",
            "extract_cap_bytes",
            "links_cap_bytes",
            "summary_cap_bytes",
        ],
        description: "audit_domain_budget_bytes_day must cover audit_fetch_cap_bytes + extract_cap_bytes + links_cap_bytes + summary_cap_bytes + 32",
        holds: |eff| {
            eff("audit_domain_budget_bytes_day")
                >= eff("audit_fetch_cap_bytes")
                    + eff("extract_cap_bytes")
                    + eff("links_cap_bytes")
                    + eff("summary_cap_bytes")
                    + 32
        },
    },
    ComboRule {
        participants: &["confirm_window_hours", "record_seal_blocks", "block_cadence_seconds"],
        description: "extension publication and sealing must fit the confirmation window",
        holds: |eff| eff("confirm_window_hours") / 2 * 3600
            + eff("record_seal_blocks") * eff("block_cadence_seconds")
            <= eff("confirm_window_hours") * 3600,
    },
    ComboRule {
        participants: &["canary_reveal_min_blocks", "block_cadence_seconds", "coverage_deadline_hours", "record_seal_blocks", "epoch_blocks"],
        description: "canary reveal minimum must cover Record and checkpoint publication and sealing",
        holds: |eff| eff("canary_reveal_min_blocks") * eff("block_cadence_seconds")
            >= eff("coverage_deadline_hours") * 3600
                + (eff("record_seal_blocks") + 2 * eff("epoch_blocks")) * eff("block_cadence_seconds"),
    },
    ComboRule {
        participants: &["canary_lifetime_blocks", "canary_lead_blocks", "canary_reveal_min_blocks"],
        description: "canary lifetime must exceed lead plus reveal minimum",
        holds: |eff| eff("canary_lifetime_blocks")
            > eff("canary_lead_blocks") + eff("canary_reveal_min_blocks"),
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
            "{name} = {value} is outside the WIST-4 §9 bounds"
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
    fn canary_reveal_and_lifetime_boundaries() {
        assert!(validate("canary_reveal_min_blocks", 143, defaults).is_err());
        validate("canary_reveal_min_blocks", 144, defaults).unwrap();
        assert!(validate("canary_lifetime_blocks", 192, defaults).is_err());
        validate("canary_lifetime_blocks", 193, defaults).unwrap();
        for (name, value) in [
            ("epoch_blocks", 37),
            ("coverage_deadline_hours", 97),
            ("block_cadence_seconds", 2699),
            ("record_seal_blocks", 49),
        ] {
            assert!(validate(name, value, defaults).is_err(), "{name}");
        }
        validate("epoch_blocks", 36, defaults).unwrap();
        validate("coverage_deadline_hours", 96, defaults).unwrap();
        validate("block_cadence_seconds", 2700, defaults).unwrap();
        assert!(validate("canary_lead_blocks", 1272, defaults).is_err());
        validate("canary_lead_blocks", 1271, defaults).unwrap();
    }

    #[test]
    fn wire_sized_intermediates_do_not_overflow() {
        validate("canary_leaves_max", WIRE_INTEGER_MAX, defaults).unwrap();
        for name in ["epoch_blocks", "record_seal_blocks", "canary_lead_blocks"] {
            assert!(validate(name, WIRE_INTEGER_MAX, defaults).is_err());
        }
        assert!(
            validate("canary_reveal_min_blocks", WIRE_INTEGER_MAX, |name| {
                if name == "canary_lifetime_blocks" {
                    WIRE_INTEGER_MAX
                } else {
                    defaults(name)
                }
            })
            .is_err()
        );
        assert!(validate_combinations(|_| WIRE_INTEGER_MAX).is_err());
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
