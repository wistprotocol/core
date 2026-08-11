# Audit Sampling Volume and Cost Report

- wist-bench version: 0.1.0, wist-core version: 0.2.0
- seed(s): small=wist-bench-v1, medium=wist-bench-v1, large=wist-bench-v1
- rerun: `wist-bench report --calibration docs/audit-cost-calibration.json --prove-ns 104576 --draw-ns 93`
- timing: prove_ns=104576, draw_ns=93 (supplied; pinned from a measurement on AMD Ryzen 7 5700X 8-Core Processor)

## Model

Each Auditor computes one Verifiable Random Function output per sealed Block over the Block Hash with its own key, then tests every Delta the Block carries against an integer draw from that output, selecting the Delta when the draw falls under the Delta's sampling rate. This covers only the VRF-selected set: WIST-4 §4 also puts a Delta into an Auditor's selection set through the **extension rule** — whenever a Block seals an `inconsistent` or `link_inconsistent` Record for a Delta with no earlier such Record in the confirmation window, that Delta enters the selection set of every other independent Auditor, a path no VRF draw gates — and this model excludes it. The excluded volume is bounded: a triggering Record only extends selection while its signing Auditor has triggered fewer than `extension_triggers_max` (Parameter Registry default 3, §9) extensions in the trailing 30 days, so the figures below miss at most that many forced fetches per Auditor per month. The sampling rate is `p_1e7 = clamp(200 000 + 3 × (1 000 000 − reputation_u), 200 000, 5 000 000)`, an integer floor of 200 000 (0.02) and ceiling of 5 000 000 (0.50) out of 10^7, with the ceiling substituted whenever a level-1 sanction is in force against the Delta's domain. Each VRF-selected Delta costs the Auditor two fetches: the live page and the reference Payload it commits to.

| Band | reputation_u | p_1e7 |
|---|---|---|
| mature | 1 000 000 | 200 000 |
| mid | 600 000 | 1 400 000 |
| provisional | 100 000 | 2 900 000 |
| sanctioned | 0 | 5 000 000 |

`reputation_u` is the input the Model formula reads; `p_1e7` is its output, the same column the Expected/day figures below are built from. `sanctioned` forces the ceiling via the level-1-sanction override, independent of its `reputation_u`.

Units: GB = 10^9 bytes; month = 30 days, throughout this report.

## Scenarios

Mix shares (`Mix` column) are basis points of that tier's `Deltas/day`; churn (`Churn (bp)` column) is basis points of `Pages` that produce a Delta per day.

| Tier | Pages | Churn (bp) | Deltas/day | Mix | Blocks/day | Days | Auditors |
|---|---|---|---|---|---|---|---|
| small | 1 000 000 | 200 | 20 000 | mature:9000,provisional:1000 | 24 | 7 | 5 |
| medium | 100 000 000 | 100 | 1 000 000 | mature:7000,mid:2000,provisional:1000 | 24 | 7 | 5 |
| large | 1 000 000 000 | 50 | 5 000 000 | mature:6000,mid:2500,provisional:1400,sanctioned:100 | 24 | 7 | 5 |

## Selection: simulated vs expected, per Auditor

Mean/day, Min, Max and Stddev range over the auditors × days observations (each cell one Auditor's selected count for one day); Expected/day is the closed-form expectation of that same per-Auditor daily count.

| Tier | Mean/day | Min | Max | Stddev | Expected/day | Rel. deviation |
|---|---|---|---|---|---|---|
| small | 940.23 | 884 | 982 | 24.34 | 937.84 | 0.25% |
| medium | 70 946.69 | 70 143 | 71 359 | 256.28 | 70 994.72 | -0.07% |
| large | 463 012.54 | 461 759 | 464 196 | 623.12 | 462 990.88 | 0.00% |

## Volume and cost, per Auditor

Every figure below is one Auditor's daily load: `cost::compute` is fed the mean selected-Delta count over the auditors × days matrix, not a roster total.

### Full page

| Tier | Fetches/day | GB/day | Mbps | WARC GB@30d | WARC GB@90d | WARC GB@365d | vCPU-s/day | USD/mo transfer | USD/mo storage | USD/mo CPU | USD/mo requests | USD/mo total |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| small | 1 880 | 2.07 | 0.19 | 0.06 | 0.19 | 0.19 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| medium | 141 893 | 156.35 | 14.48 | 4.69 | 14.07 | 14.07 | 0.10 | 0.00 | 0.32 | 0.00 | 0.00 | 0.32 |
| large | 926 025 | 1 020.38 | 94.48 | 30.61 | 91.83 | 91.83 | 0.47 | 0.00 | 2.11 | 0.00 | 0.00 | 2.11 |

### HTML only

| Tier | Fetches/day | GB/day | Mbps | WARC GB@30d | WARC GB@90d | WARC GB@365d | vCPU-s/day | USD/mo transfer | USD/mo storage | USD/mo CPU | USD/mo requests | USD/mo total |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| small | 1 880 | 0.03 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| medium | 141 893 | 2.47 | 0.23 | 0.07 | 0.22 | 0.22 | 0.10 | 0.00 | 0.01 | 0.00 | 0.00 | 0.01 |
| large | 926 025 | 16.11 | 1.49 | 0.48 | 1.45 | 1.45 | 0.47 | 0.00 | 0.03 | 0.00 | 0.00 | 0.03 |

## Assumptions and sources

- page weights: full 2 200 000 B (`--page-bytes`), HTML 31 000 B (`--html-bytes`) — HTTP Archive Web Almanac (median page weight; retrieved 2026-08)
- churn: assumed; published web-change studies report 0.1–8 %/day depending on cohort
- payload bytes: 3 792 (`--calibration`; measured p50 of 15 Publisher-built payload objects; max 41 624, above the WIST-1 §3.6 content-cap sum of 38 944 because a served Payload object carries envelope overhead the content caps do not govern)
- inconsistency rate: 10 bp (`--inconsistency-bp`) — assumed; also sets the fraction of fetched bytes assumed archived as WARC evidence, since only Records with an `inconsistent` or `link_inconsistent` verdict retain their WARC capture (WIST-4 §5)
- WARC retention floor: 90 days (`warc_retention_days`, not a report flag) — WIST-4 §5 Parameter Registry default; §5 extends this floor while a `notice` naming the Record has an open appeal window, sealing deadline or ruling deadline, so the WARC GB@30d/90d/365d columns are lower bounds, not caps
- fetch model: two fetches per **VRF-selected** Delta only (live page + Payload); excludes the Block/Delta stream ingest an Auditor performs on every Delta to run the selection test, the Auditor's own Record-serving traffic, retries and redirects, and the extension-rule fetches (bounded by `extension_triggers_max`, WIST-4 §4, §9) — the GB/day and vCPU-s/day columns are not total Auditor bandwidth or compute
- storage price: $0.023/GB-month (`--storage-usd-gb-month`) — commodity cloud list prices (retrieved 2026-08)
- vCPU price: $0.04/hour (`--vcpu-usd-hour`) — commodity cloud list prices (retrieved 2026-08)
- request price: $0/million (`--requests-usd-million`) — commodity cloud list prices (retrieved 2026-08)
- transfer price: $0/GB (`--transfer-usd-gb`), default 0 — ingress is unbilled at most providers; flag for metered links

This report states measurements and assumptions only; it makes no claim about any particular operator's budget.

