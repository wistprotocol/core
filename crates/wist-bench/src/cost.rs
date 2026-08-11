use crate::scenario::{band_p_1e7, Band, Scenario};
use serde::Serialize;
use std::time::Instant;
use wist_core::{sampling, vrf};

pub struct CostParams {
    pub page_bytes_full: u64,
    pub page_bytes_html: u64,
    pub payload_bytes: u64,
    pub inconsistency_bp: u32,
    pub warc_retention_days: u32,
    pub usd_per_gb_transfer: f64,
    pub usd_per_gb_month_storage: f64,
    pub usd_per_vcpu_hour: f64,
    pub usd_per_million_requests: f64,
}

impl Default for CostParams {
    fn default() -> Self {
        CostParams {
            page_bytes_full: 2_200_000,
            page_bytes_html: 31_000,
            payload_bytes: 38_944,
            inconsistency_bp: 10,
            warc_retention_days: 90,
            usd_per_gb_transfer: 0.0,
            usd_per_gb_month_storage: 0.023,
            usd_per_vcpu_hour: 0.04,
            usd_per_million_requests: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Timing {
    pub prove_ns: u64,
    pub draw_ns: u64,
}

pub fn measure_timing(proves: u32, draws: u64) -> Timing {
    let sk = [7u8; 32];
    let alpha = [9u8; 32];
    let pi = vrf::prove(&sk, &alpha).unwrap();
    let beta = vrf::proof_to_hash(&pi).unwrap();
    let start = Instant::now();
    for _ in 0..proves {
        let pi = vrf::prove(std::hint::black_box(&sk), std::hint::black_box(&alpha)).unwrap();
        std::hint::black_box(vrf::proof_to_hash(&pi).unwrap());
    }
    let prove_ns = (start.elapsed().as_nanos() / proves as u128) as u64;
    const ID_RING: usize = 256;
    let ids: Vec<String> = (0..ID_RING).map(|i| format!("sha256:{i:064x}")).collect();
    let mature_p_1e7 = band_p_1e7(Band::Mature);
    let start = Instant::now();
    let mut acc = 0u64;
    for i in 0..draws {
        let id = std::hint::black_box(&ids[(i % ID_RING as u64) as usize]);
        let d = sampling::draw(&beta, id);
        acc += u64::from(sampling::selected(d, mature_p_1e7));
    }
    let draw_ns = (start.elapsed().as_nanos() / draws as u128) as u64;
    std::hint::black_box(acc);
    Timing {
        prove_ns: prove_ns.max(1),
        draw_ns: draw_ns.max(1),
    }
}

#[derive(Debug, Serialize)]
pub struct CostBreakdown {
    pub selected_per_day: f64,
    pub fetches_per_day: f64,
    pub gb_per_day: f64,
    pub mbps_sustained: f64,
    pub warc_gb_steady: f64,
    pub warc_gb_at: [(u32, f64); 3],
    pub vcpu_sec_per_day: f64,
    pub usd_month_transfer: f64,
    pub usd_month_storage: f64,
    pub usd_month_cpu: f64,
    pub usd_month_requests: f64,
    pub usd_month_total: f64,
}

pub fn compute(
    selected_per_day: f64,
    sc: &Scenario,
    params: &CostParams,
    page_bytes: u64,
    timing: &Timing,
) -> CostBreakdown {
    let per_fetch_bytes = (page_bytes + params.payload_bytes) as f64;
    let gb_per_day = selected_per_day * per_fetch_bytes / 1e9;
    let warc_gb_per_day =
        selected_per_day * params.inconsistency_bp as f64 / 10_000.0 * per_fetch_bytes / 1e9;
    let retention = params.warc_retention_days as f64;
    let warc_at = |days: u32| warc_gb_per_day * (days as f64).min(retention);
    let vcpu_sec_per_day = (sc.blocks_per_day as f64 * timing.prove_ns as f64
        + sc.deltas_per_day() as f64 * timing.draw_ns as f64)
        / 1e9;
    let fetches_per_day = 2.0 * selected_per_day;
    let usd_month_transfer = gb_per_day * 30.0 * params.usd_per_gb_transfer;
    let usd_month_storage = warc_gb_per_day * retention * params.usd_per_gb_month_storage;
    let usd_month_cpu = vcpu_sec_per_day * 30.0 / 3600.0 * params.usd_per_vcpu_hour;
    let usd_month_requests = fetches_per_day * 30.0 / 1e6 * params.usd_per_million_requests;
    CostBreakdown {
        selected_per_day,
        fetches_per_day,
        gb_per_day,
        mbps_sustained: gb_per_day * 8000.0 / 86_400.0,
        warc_gb_steady: warc_gb_per_day * retention,
        warc_gb_at: [(30, warc_at(30)), (90, warc_at(90)), (365, warc_at(365))],
        vcpu_sec_per_day,
        usd_month_transfer,
        usd_month_storage,
        usd_month_cpu,
        usd_month_requests,
        usd_month_total: usd_month_transfer
            + usd_month_storage
            + usd_month_cpu
            + usd_month_requests,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::Scenario;

    #[test]
    fn cost_arithmetic_small_tier() {
        let sc = Scenario::tier("small").unwrap();
        let params = CostParams::default();
        let timing = Timing {
            prove_ns: 100_000,
            draw_ns: 300,
        };
        let c = compute(940.0, &sc, &params, params.page_bytes_full, &timing);
        assert!((c.fetches_per_day - 1880.0).abs() < 1e-9);
        let expect_gb = 940.0 * (2_200_000.0 + 38_944.0) / 1e9;
        assert!((c.gb_per_day - expect_gb).abs() < 1e-9);
        let wd = 940.0 * 0.001 * (2_200_000.0 + 38_944.0) / 1e9;
        assert!((c.warc_gb_steady - wd * 90.0).abs() < 1e-9);
        assert_eq!(c.warc_gb_at[0].0, 30);
        assert_eq!(c.warc_gb_at[1].0, 90);
        assert!((c.warc_gb_at[1].1 - wd * 90.0).abs() < 1e-9);
        assert!((c.warc_gb_at[2].1 - wd * 90.0).abs() < 1e-9);
        let cpu = (24.0 * 100_000.0 + 20_000.0 * 300.0) / 1e9;
        assert!((c.vcpu_sec_per_day - cpu).abs() < 1e-9);
        assert!((c.mbps_sustained - expect_gb * 8000.0 / 86_400.0).abs() < 1e-9);
        assert!((c.usd_month_storage - c.warc_gb_steady * 0.023).abs() < 1e-9);
        assert!((c.usd_month_transfer - 0.0).abs() < 1e-12);
        assert!((c.usd_month_cpu - cpu * 30.0 / 3600.0 * 0.04).abs() < 1e-9);
        assert!((c.usd_month_requests - 0.0).abs() < 1e-12);
        assert!(
            (c.usd_month_total
                - (c.usd_month_transfer
                    + c.usd_month_storage
                    + c.usd_month_cpu
                    + c.usd_month_requests))
                .abs()
                < 1e-9
        );
    }

    #[test]
    fn timing_is_positive() {
        let t = measure_timing(5, 50_000);
        assert!(t.prove_ns > 0);
        assert!(t.draw_ns > 0);
    }
}
