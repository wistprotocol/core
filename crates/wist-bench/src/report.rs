use crate::calibrate::Calibration;
use crate::cost::{self, CostParams, Timing};
use crate::scenario::{band_p_1e7, band_rep_u, Band, Scenario};
use crate::sim;

pub struct ReportInputs {
    pub scenarios: Vec<Scenario>,
    pub params: CostParams,
    pub calibration: Option<Calibration>,
    pub timing: Timing,
    pub timing_supplied: bool,
    pub machine: String,
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

fn mix_str(sc: &Scenario) -> String {
    sc.mix
        .iter()
        .map(|m| format!("{}:{}", m.band.as_str(), m.share_bp))
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

    let timing_desc = if inputs.timing_supplied {
        format!("supplied; pinned from a measurement on {}", inputs.machine)
    } else {
        format!("measured on {}", inputs.machine)
    };
    let seeds = inputs
        .scenarios
        .iter()
        .map(|sc| format!("{}={}", sc.name, sc.seed))
        .collect::<Vec<_>>()
        .join(", ");

    out.push_str("# Audit Sampling Volume and Cost Report\n\n");
    out.push_str(&format!(
        "- wist-bench version: {}, wist-core version: {}\n",
        env!("CARGO_PKG_VERSION"),
        wist_core::VERSION
    ));
    out.push_str(&format!("- seed(s): {seeds}\n"));
    out.push_str(&format!("- rerun: `{}`\n", inputs.command_line));
    out.push_str(&format!(
        "- timing: prove_ns={}, draw_ns={} ({timing_desc})\n\n",
        inputs.timing.prove_ns, inputs.timing.draw_ns
    ));

    out.push_str("## Model\n\n");
    out.push_str(
        "Each Auditor computes one Verifiable Random Function output per sealed Block over the Block Hash with its own key, then tests every Delta the Block carries against an integer draw from that output, selecting the Delta when the draw falls under the Delta's sampling rate. This covers only the VRF-selected set: WIST-4 §4 also puts a Delta into an Auditor's selection set through the **extension rule** — whenever a Block seals an `inconsistent` or `link_inconsistent` Record for a Delta with no earlier such Record in the confirmation window, that Delta enters the selection set of every other independent Auditor, a path no VRF draw gates — and this model excludes it. The excluded volume is bounded: a triggering Record only extends selection while its signing Auditor has triggered fewer than `extension_triggers_max` (Parameter Registry default 3, §9) extensions in the trailing 30 days, so the figures below miss at most that many forced fetches per Auditor per month. The sampling rate is `p_1e7 = clamp(200 000 + 3 × (1 000 000 − reputation_u), 200 000, 5 000 000)`, an integer floor of 200 000 (0.02) and ceiling of 5 000 000 (0.50) out of 10^7, with the ceiling substituted whenever a level-1 sanction is in force against the Delta's domain. Each VRF-selected Delta costs the Auditor two fetches: the live page and the reference Payload it commits to.\n\n",
    );
    let band_rows: Vec<Vec<String>> =
        [Band::Mature, Band::Mid, Band::Provisional, Band::Sanctioned]
            .into_iter()
            .map(|b| {
                vec![
                    b.as_str().to_string(),
                    human_int(band_rep_u(b) as f64),
                    human_int(band_p_1e7(b) as f64),
                ]
            })
            .collect();
    out.push_str(&md_table(&["Band", "reputation_u", "p_1e7"], &band_rows));
    out.push_str(
        "`reputation_u` is the input the Model formula reads; `p_1e7` is its output, the same column the Expected/day figures below are built from. `sanctioned` forces the ceiling via the level-1-sanction override, independent of its `reputation_u`.\n\n",
    );
    out.push_str("Units: GB = 10^9 bytes; month = 30 days, throughout this report.\n\n");

    out.push_str("## Scenarios\n\n");
    out.push_str(
        "Mix shares (`Mix` column) are basis points of that tier's `Deltas/day`; churn (`Churn (bp)` column) is basis points of `Pages` that produce a Delta per day.\n\n",
    );
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

    out.push_str("## Selection: simulated vs expected, per Auditor\n\n");
    out.push_str(
        "Mean/day, Min, Max and Stddev range over the auditors × days observations (each cell one Auditor's selected count for one day); Expected/day is the closed-form expectation of that same per-Auditor daily count.\n\n",
    );
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

    out.push_str("## Volume and cost, per Auditor\n\n");
    out.push_str(
        "Every figure below is one Auditor's daily load: `cost::compute` is fed the mean selected-Delta count over the auditors × days matrix, not a roster total.\n\n",
    );
    out.push_str(
        "Each fetch is one HTML document plus one reference Payload. An Auditor never renders a page or retrieves its subresources: WIST-4 §5 defines the similarity dimension over WIST-2 §12's extraction from a fetched HTML representation, rules any non-HTML representation `not_auditable`, and sends a script-shell whose text exists only after execution to the same verdict through the observed-text mass guard. Stylesheets, scripts, fonts and images are therefore outside what an audit fetches, and full-page transfer weight is not the applicable figure.\n\n",
    );
    {
        let rows: Vec<Vec<String>> = inputs
            .scenarios
            .iter()
            .zip(&results)
            .map(|(sc, r)| {
                let c = cost::compute(
                    r.mean_per_day,
                    sc,
                    &inputs.params,
                    inputs.params.page_bytes,
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
        "- page bytes: {} B (`--page-bytes`) — HTTP Archive Web Almanac (median HTML document transfer size; retrieved 2026-08). The HTML document is the whole of what an audit fetches from the URL (WIST-4 §5, WIST-2 §12); subresources are not fetched\n",
        human_int(inputs.params.page_bytes as f64)
    ));
    out.push_str(
        "- churn: assumed; published web-change studies report 0.1–8 %/day depending on cohort\n",
    );
    const PAYLOAD_CONTENT_CAP_SUM: u64 = 38_944;
    match &inputs.calibration {
        Some(c) => {
            let envelope_note = if c.payload_max > PAYLOAD_CONTENT_CAP_SUM {
                format!(
                    ", above the WIST-1 §3.6 content-cap sum of {} because a served Payload object carries envelope overhead the content caps do not govern",
                    human_int(PAYLOAD_CONTENT_CAP_SUM as f64)
                )
            } else {
                String::new()
            };
            out.push_str(&format!(
                "- payload bytes: {} (`--calibration`; measured p50 of {} Publisher-built payload objects; max {}{envelope_note})\n",
                human_int(inputs.params.payload_bytes as f64),
                c.count,
                human_int(c.payload_max as f64)
            ));
        }
        None => out.push_str(&format!(
            "- payload bytes: {} — sum of the WIST-1 §3.6 content caps (32 768 extract + 4 096 links + 2 048 summary + 32 structure); excludes envelope overhead, so not a bound on transferred bytes\n",
            human_int(inputs.params.payload_bytes as f64)
        )),
    }
    out.push_str(&format!(
        "- inconsistency rate: {} bp (`--inconsistency-bp`) — assumed; also sets the fraction of fetched bytes assumed archived as WARC evidence, since only Records with an `inconsistent` or `link_inconsistent` verdict retain their WARC capture (WIST-4 §5)\n",
        inputs.params.inconsistency_bp
    ));
    out.push_str(&format!(
        "- WARC retention floor: {} days (`warc_retention_days`, not a report flag) — WIST-4 §5 Parameter Registry default; §5 extends this floor while a `notice` naming the Record has an open appeal window, sealing deadline or ruling deadline, so the WARC GB@30d/90d/365d columns are lower bounds, not caps\n",
        inputs.params.warc_retention_days
    ));
    out.push_str(
        "- fetch model: two fetches per **VRF-selected** Delta only (live page + Payload); excludes the Block/Delta stream ingest an Auditor performs on every Delta to run the selection test, the Auditor's own Record-serving traffic, retries and redirects, and the extension-rule fetches (bounded by `extension_triggers_max`, WIST-4 §4, §9) — the GB/day and vCPU-s/day columns are not total Auditor bandwidth or compute\n",
    );
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
            timing_supplied: false,
            machine: "test-cpu".into(),
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
        assert!(md.contains(
            "This report states measurements and assumptions only; it makes no claim about any particular operator's budget."
        ));
    }

    #[test]
    fn report_is_deterministic_given_timing() {
        let a = render(&tiny_inputs());
        let b = render(&tiny_inputs());
        assert_eq!(a, b);
    }

    #[test]
    fn timing_supplied_and_machine_appear_in_header() {
        let mut inputs = tiny_inputs();
        inputs.timing_supplied = true;
        inputs.machine = "Test CPU Model".into();
        let md = render(&inputs);
        assert!(md.contains("supplied; pinned from a measurement on Test CPU Model"));
        let mut inputs2 = tiny_inputs();
        inputs2.timing_supplied = false;
        inputs2.machine = "Another CPU".into();
        let md2 = render(&inputs2);
        assert!(md2.contains("measured on Another CPU"));
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
