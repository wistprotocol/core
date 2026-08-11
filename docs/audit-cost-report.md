# Audit Sampling Volume and Cost Report

- wist-bench version: 0.1.0
- seed(s): small=wist-bench-v1, medium=wist-bench-v1, large=wist-bench-v1
- rerun: `wist-bench report --calibration docs/audit-cost-calibration.json`
- timing: prove_ns=111761, draw_ns=330 (measured)

## Model

Each Auditor computes one Verifiable Random Function output per sealed Block over the Block Hash with its own key, then tests every Delta the Block carries against an integer draw from that output, selecting the Delta if and only if the draw falls under the Delta's sampling rate (WIST-4 §4). The sampling rate is `p_1e7 = clamp(200 000 + 3 × (1 000 000 − reputation_u), 200 000, 5 000 000)`, an integer floor of 200 000 (0.02) and ceiling of 5 000 000 (0.50) out of 10^7, with the ceiling substituted whenever a level-1 sanction is in force against the Delta's domain. Each selected Delta costs the Auditor two fetches: the live page and the reference Payload it commits to.

## Scenarios

| Tier | Pages | Churn (bp) | Deltas/day | Mix | Blocks/day | Days | Auditors |
|---|---|---|---|---|---|---|---|
| small | 1 000 000 | 200 | 20 000 | mature:9000,provisional:1000 | 24 | 7 | 5 |
| medium | 100 000 000 | 100 | 1 000 000 | mature:7000,mid:2000,provisional:1000 | 24 | 7 | 5 |
| large | 1 000 000 000 | 50 | 5 000 000 | mature:6000,mid:2500,provisional:1400,sanctioned:100 | 24 | 7 | 5 |

## Selection: simulated vs expected

| Tier | Mean/day | Min | Max | Stddev | Expected/day | Rel. deviation |
|---|---|---|---|---|---|---|
| small | 940.23 | 884 | 982 | 24.34 | 940.00 | 0.02% |
| medium | 70946.69 | 70 143 | 71 359 | 256.28 | 71000.00 | -0.08% |
| large | 463012.54 | 461 759 | 464 196 | 623.12 | 463000.00 | 0.00% |

## Volume and cost

### Full page

| Tier | Fetches/day | GB/day | Mbps | WARC GB@30d | WARC GB@90d | WARC GB@365d | vCPU-s/day | USD/mo transfer | USD/mo storage | USD/mo CPU | USD/mo requests | USD/mo total |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| small | 1 880 | 2.07 | 0.19 | 0.06 | 0.19 | 0.19 | 0.01 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| medium | 141 893 | 156.35 | 14.48 | 4.69 | 14.07 | 14.07 | 0.33 | 0.00 | 0.32 | 0.00 | 0.00 | 0.32 |
| large | 926 025 | 1020.38 | 94.48 | 30.61 | 91.83 | 91.83 | 1.65 | 0.00 | 2.11 | 0.00 | 0.00 | 2.11 |

### HTML only

| Tier | Fetches/day | GB/day | Mbps | WARC GB@30d | WARC GB@90d | WARC GB@365d | vCPU-s/day | USD/mo transfer | USD/mo storage | USD/mo CPU | USD/mo requests | USD/mo total |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| small | 1 880 | 0.03 | 0.00 | 0.00 | 0.00 | 0.00 | 0.01 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| medium | 141 893 | 2.47 | 0.23 | 0.07 | 0.22 | 0.22 | 0.33 | 0.00 | 0.01 | 0.00 | 0.00 | 0.01 |
| large | 926 025 | 16.11 | 1.49 | 0.48 | 1.45 | 1.45 | 1.65 | 0.00 | 0.03 | 0.00 | 0.00 | 0.03 |

## Assumptions and sources

- page weights: full 2 200 000 B (`--page-bytes`), HTML 31 000 B (`--html-bytes`) — HTTP Archive Web Almanac (median page weight; retrieved 2026-08)
- churn: assumed; published web-change studies report 0.1–8 %/day depending on cohort
- payload bytes: 3 792 (`--calibration`; measured p50 of 15 Publisher-built payload objects; max 41 624)
- inconsistency rate: 10 bp (`--inconsistency-bp`) — assumed
- WARC retention floor: 90 days (`warc_retention_days`, not a report flag) — WIST-4 §5 Parameter Registry default; caps the WARC GB@90d and WARC GB@365d columns at the same value
- storage price: $0.023/GB-month (`--storage-usd-gb-month`) — commodity cloud list prices (retrieved 2026-08)
- vCPU price: $0.04/hour (`--vcpu-usd-hour`) — commodity cloud list prices (retrieved 2026-08)
- request price: $0/million (`--requests-usd-million`) — commodity cloud list prices (retrieved 2026-08)
- transfer price: $0/GB (`--transfer-usd-gb`), default 0 — ingress is unbilled at most providers; flag for metered links

This report states measurements and assumptions only; it makes no claim about any particular operator's budget.

