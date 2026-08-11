use clap::{Parser, Subcommand};
use wist_bench::cli::ScenarioFlags;

#[derive(Parser)]
#[command(name = "wist-bench", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Simulate {
        #[command(flatten)]
        flags: ScenarioFlags,
    },
    Report {
        #[arg(long)]
        calibration: Option<std::path::PathBuf>,
        #[arg(long)]
        page_bytes: Option<u64>,
        #[arg(long)]
        inconsistency_bp: Option<u32>,
        #[arg(long)]
        transfer_usd_gb: Option<f64>,
        #[arg(long)]
        storage_usd_gb_month: Option<f64>,
        #[arg(long)]
        vcpu_usd_hour: Option<f64>,
        #[arg(long)]
        requests_usd_million: Option<f64>,
        #[arg(long)]
        prove_ns: Option<u64>,
        #[arg(long)]
        draw_ns: Option<u64>,
        #[arg(long)]
        days: Option<u32>,
        #[arg(long)]
        auditors: Option<u32>,
        #[arg(long)]
        seed: Option<String>,
    },
    Calibrate {
        #[arg(long)]
        payload_dir: std::path::PathBuf,
    },
}

fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn main() {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Simulate { flags } => flags.to_scenario().map(|sc| {
            println!("{}", wist_bench::cli::simulate_json(&sc));
        }),
        Command::Report {
            calibration,
            page_bytes,
            inconsistency_bp,
            transfer_usd_gb,
            storage_usd_gb_month,
            vcpu_usd_hour,
            requests_usd_million,
            prove_ns,
            draw_ns,
            days,
            auditors,
            seed,
        } => (|| {
            let mut params = wist_bench::cost::CostParams::default();
            if let Some(v) = page_bytes {
                params.page_bytes = v;
            }
            if let Some(v) = inconsistency_bp {
                params.inconsistency_bp = v;
            }
            if let Some(v) = transfer_usd_gb {
                params.usd_per_gb_transfer = v;
            }
            if let Some(v) = storage_usd_gb_month {
                params.usd_per_gb_month_storage = v;
            }
            if let Some(v) = vcpu_usd_hour {
                params.usd_per_vcpu_hour = v;
            }
            if let Some(v) = requests_usd_million {
                params.usd_per_million_requests = v;
            }
            let calibration = calibration
                .map(|path| wist_bench::calibrate::load(&path))
                .transpose()?;
            if let Some(c) = &calibration {
                params.payload_bytes = c.payload_p50;
            }
            let timing_supplied = prove_ns.is_some() && draw_ns.is_some();
            let timing = match (prove_ns, draw_ns) {
                (Some(prove_ns), Some(draw_ns)) => wist_bench::cost::Timing { prove_ns, draw_ns },
                _ => wist_bench::cost::measure_timing(200, 2_000_000),
            };
            let scenarios = ["small", "medium", "large"]
                .into_iter()
                .map(|tier| {
                    let mut sc = wist_bench::scenario::Scenario::tier(tier).unwrap();
                    if let Some(v) = days {
                        sc.days = v;
                    }
                    if let Some(v) = auditors {
                        sc.auditors = v;
                    }
                    if let Some(v) = &seed {
                        sc.seed = v.clone();
                    }
                    sc.validate()?;
                    Ok(sc)
                })
                .collect::<Result<Vec<_>, String>>()?;
            let mut args: Vec<String> = std::env::args().collect();
            if let Some(first) = args.first_mut() {
                *first = "wist-bench".to_string();
            }
            let command_line = args.join(" ");
            println!(
                "{}",
                wist_bench::report::render(&wist_bench::report::ReportInputs {
                    scenarios,
                    params,
                    calibration,
                    timing,
                    timing_supplied,
                    machine: cpu_model(),
                    command_line,
                })
            );
            Ok(())
        })(),
        Command::Calibrate { payload_dir } => wist_bench::calibrate::measure(&payload_dir)
            .map(|c| println!("{}", serde_json::to_string_pretty(&c).unwrap())),
    };
    if let Err(e) = outcome {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
