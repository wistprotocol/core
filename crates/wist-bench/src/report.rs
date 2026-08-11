use crate::calibrate::Calibration;
use crate::cost::{self, CostParams, Timing};
use crate::scenario::{Band, Scenario};
use crate::sim;

pub struct ReportInputs {
    pub scenarios: Vec<Scenario>,
    pub params: CostParams,
    pub calibration: Option<Calibration>,
    pub timing: Timing,
    pub command_line: String,
}

fn group_digits(digits: &str) -> String {
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

fn f2(v: f64) -> String {
    let s = format!("{v:.2}");
    let (sign, rest) = s.strip_prefix('-').map_or(("", s.as_str()), |r| ("-", r));
    let (int_part, frac_part) = rest.split_once('.').unwrap_or((rest, "00"));
    format!("{sign}{}.{frac_part}", group_digits(int_part))
}

fn human_int(v: f64) -> String {
    let n = v.round() as i64;
    let sign = if n < 0 { "-" } else { "" };
    format!("{sign}{}", group_digits(&n.unsigned_abs().to_string()))
}

fn band_name(b: Band) -> &'static str {
    match b {
        Band::Mature => "mature",
        Band::Mid => "mid",
        Band::Provisional => "provisional",
        Band::Sanctioned => "sanctioned",
    }
}

fn mix_str(sc: &Scenario) -> String {
    sc.mix
        .iter()
        .map(|m| format!("{}:{}", band_name(m.band), m.share_bp))
        .collect::<Vec<_>>()
        .join(",")
}

fn md_table(cols: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    out.push('|');
    for c in cols {
        out.push_str(&format!(" {c} |"));
    }
    out.push('\n');
    out.push('|');
    for _ in cols {
        out.push_str("---|");
    }
    out.push('\n');
    for row in rows {
        out.push('|');
        for cell in row {
            out.push_str(&format!(" {cell} |"));
        }
        out.push('\n');
    }
    out.push('\n');
    out
}

pub fn render(inputs: &ReportInputs) -> String {
    let mut out = String::new();

    let timing_source = if inputs.command_line.contains("--prove-ns")
        && inputs.command_line.contains("--draw-ns")
    {
        "supplied"
    } else {
        "measured"
    };
    let seeds = inputs
        .scenarios
        .iter()
        .map(|sc| format!("{}={}", sc.name, sc.seed))
        .collect::<Vec<_>>()
        .join(", ");

    out.push_str("# Audit Sampling Volume and Cost Report\n\n");
    out.push_str(&format!(
        "- wist-bench version: {}\n",
        env!("CARGO_PKG_VERSION")
    ));
    out.push_str(&format!("- seed(s): {seeds}\n"));
    out.push_str(&format!("- rerun: `{}`\n", inputs.command_line));
    out.push_str(&format!(
        "- timing: prove_ns={}, draw_ns={} ({timing_source})\n\n",
        inputs.timing.prove_ns, inputs.timing.draw_ns
    ));

    out.push_str("## Model\n\n");
    out.push_str(
        "Each Auditor computes one Verifiable Random Function output per sealed Block over the Block Hash with its own key, then tests every Delta the Block carries against an integer draw from that output, selecting the Delta if and only if the draw falls under the Delta's sampling rate (WIST-4 §4). The sampling rate is `p_1e7 = clamp(200 000 + 3 × (1 000 000 − reputation_u), 200 000, 5 000 000)`, an integer floor of 200 000 (0.02) and ceiling of 5 000 000 (0.50) out of 10^7, with the ceiling substituted whenever a level-1 sanction is in force against the Delta's domain. Each selected Delta costs the Auditor two fetches: the live page and the reference Payload it commits to.\n\n",
    );

    out.push_str("## Scenarios\n\n");
    let scenario_rows: Vec<Vec<String>> = inputs
        .scenarios
        .iter()
        .map(|sc| {
            vec![
                sc.name.clone(),
                human_int(sc.pages as f64),
                sc.churn_bp.to_string(),
                human_int(sc.deltas_per_day() as f64),
                mix_str(sc),
                sc.blocks_per_day.to_string(),
                sc.days.to_string(),
                sc.auditors.to_string(),
            ]
        })
        .collect();
    out.push_str(&md_table(
        &[
            "Tier",
            "Pages",
            "Churn (bp)",
            "Deltas/day",
            "Mix",
            "Blocks/day",
            "Days",
            "Auditors",
        ],
        &scenario_rows,
    ));

    let results: Vec<_> = inputs.scenarios.iter().map(sim::run).collect();

    out.push_str("## Selection: simulated vs expected\n\n");
    let selection_rows: Vec<Vec<String>> = inputs
        .scenarios
        .iter()
        .zip(&results)
        .map(|(sc, r)| {
            vec![
                sc.name.clone(),
                f2(r.mean_per_day),
                human_int(r.min_day as f64),
                human_int(r.max_day as f64),
                f2(r.stddev),
                f2(r.expected_per_day),
                format!("{}%", f2(r.rel_deviation * 100.0)),
            ]
        })
        .collect();
    out.push_str(&md_table(
        &[
            "Tier",
            "Mean/day",
            "Min",
            "Max",
            "Stddev",
            "Expected/day",
            "Rel. deviation",
        ],
        &selection_rows,
    ));

    out.push_str("## Volume and cost\n\n");
    let variants: [(&str, u64); 2] = [
        ("Full page", inputs.params.page_bytes_full),
        ("HTML only", inputs.params.page_bytes_html),
    ];
    for (label, page_bytes) in variants {
        out.push_str(&format!("### {label}\n\n"));
        let rows: Vec<Vec<String>> = inputs
            .scenarios
            .iter()
            .zip(&results)
            .map(|(sc, r)| {
                let c = cost::compute(
                    r.mean_per_day,
                    sc,
                    &inputs.params,
                    page_bytes,
                    &inputs.timing,
                );
                vec![
                    sc.name.clone(),
                    human_int(c.fetches_per_day),
                    f2(c.gb_per_day),
                    f2(c.mbps_sustained),
                    f2(c.warc_gb_at[0].1),
                    f2(c.warc_gb_at[1].1),
                    f2(c.warc_gb_at[2].1),
                    f2(c.vcpu_sec_per_day),
                    f2(c.usd_month_transfer),
                    f2(c.usd_month_storage),
                    f2(c.usd_month_cpu),
                    f2(c.usd_month_requests),
                    f2(c.usd_month_total),
                ]
            })
            .collect();
        out.push_str(&md_table(
            &[
                "Tier",
                "Fetches/day",
                "GB/day",
                "Mbps",
                "WARC GB@30d",
                "WARC GB@90d",
                "WARC GB@365d",
                "vCPU-s/day",
                "USD/mo transfer",
                "USD/mo storage",
                "USD/mo CPU",
                "USD/mo requests",
                "USD/mo total",
            ],
            &rows,
        ));
    }

    out.push_str("## Assumptions and sources\n\n");
    out.push_str(&format!(
        "- page weights: full {} B (`--page-bytes`), HTML {} B (`--html-bytes`) — HTTP Archive Web Almanac (median page weight; retrieved 2026-08)\n",
        human_int(inputs.params.page_bytes_full as f64),
        human_int(inputs.params.page_bytes_html as f64)
    ));
    out.push_str(
        "- churn: assumed; published web-change studies report 0.1–8 %/day depending on cohort\n",
    );
    match &inputs.calibration {
        Some(c) => out.push_str(&format!(
            "- payload bytes: {} (`--calibration`; measured p50 of {} Publisher-built payload objects; max {})\n",
            human_int(inputs.params.payload_bytes as f64),
            c.count,
            human_int(c.payload_max as f64)
        )),
        None => out.push_str(&format!(
            "- payload bytes: {} (upper bound from WIST-1 §3.6 caps, 32 768 extract + 2 048 summary)\n",
            human_int(inputs.params.payload_bytes as f64)
        )),
    }
    out.push_str(&format!(
        "- inconsistency rate: {} bp (`--inconsistency-bp`) — assumed; also sets the fraction of fetched bytes assumed archived as WARC evidence, since only Records with an `inconsistent` or `link_inconsistent` verdict retain their WARC capture (WIST-4 §5)\n",
        inputs.params.inconsistency_bp
    ));
    out.push_str(&format!(
        "- WARC retention floor: {} days (`warc_retention_days`, not a report flag) — WIST-4 §5 Parameter Registry default; caps the WARC GB@90d and WARC GB@365d columns at the same value\n",
        inputs.params.warc_retention_days
    ));
    out.push_str(&format!(
        "- storage price: ${}/GB-month (`--storage-usd-gb-month`) — commodity cloud list prices (retrieved 2026-08)\n",
        inputs.params.usd_per_gb_month_storage
    ));
    out.push_str(&format!(
        "- vCPU price: ${}/hour (`--vcpu-usd-hour`) — commodity cloud list prices (retrieved 2026-08)\n",
        inputs.params.usd_per_vcpu_hour
    ));
    out.push_str(&format!(
        "- request price: ${}/million (`--requests-usd-million`) — commodity cloud list prices (retrieved 2026-08)\n",
        inputs.params.usd_per_million_requests
    ));
    out.push_str(&format!(
        "- transfer price: ${}/GB (`--transfer-usd-gb`), default 0 — ingress is unbilled at most providers; flag for metered links\n\n",
        inputs.params.usd_per_gb_transfer
    ));

    out.push_str(
        "This report states measurements and assumptions only; it makes no claim about any particular operator's budget.\n",
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::{CostParams, Timing};
    use crate::scenario::Scenario;

    fn tiny_inputs() -> ReportInputs {
        let mut sc = Scenario::tier("small").unwrap();
        sc.pages = 100_000;
        sc.days = 1;
        sc.auditors = 1;
        sc.seed = "report-test".into();
        ReportInputs {
            scenarios: vec![sc],
            params: CostParams::default(),
            calibration: None,
            timing: Timing {
                prove_ns: 100_000,
                draw_ns: 300,
            },
            command_line: "wist-bench report --seed report-test".into(),
        }
    }

    #[test]
    fn report_has_all_sections() {
        let md = render(&tiny_inputs());
        for heading in [
            "# Audit Sampling Volume and Cost Report",
            "## Model",
            "## Scenarios",
            "## Selection: simulated vs expected",
            "## Volume and cost",
            "## Assumptions and sources",
        ] {
            assert!(md.contains(heading), "missing {heading}");
        }
        assert!(md.contains("wist-bench report --seed report-test"));
        assert!(md.contains("32 768"));
    }

    #[test]
    fn report_is_deterministic_given_timing() {
        let a = render(&tiny_inputs());
        let b = render(&tiny_inputs());
        assert_eq!(a, b);
    }

    #[test]
    fn calibration_replaces_payload_bytes() {
        let mut inputs = tiny_inputs();
        inputs.calibration = Some(crate::calibrate::Calibration {
            count: 24,
            payload_p50: 5_000,
            payload_max: 34_000,
        });
        inputs.params.payload_bytes = 5_000;
        let md = render(&inputs);
        assert!(md.contains("measured p50 of 24"));
    }
}
