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
    Report,
    Calibrate {
        #[arg(long)]
        payload_dir: std::path::PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Simulate { flags } => flags.to_scenario().map(|sc| {
            println!("{}", wist_bench::cli::simulate_json(&sc));
        }),
        Command::Report => Ok(()),
        Command::Calibrate { payload_dir } => wist_bench::calibrate::measure(&payload_dir)
            .map(|c| println!("{}", serde_json::to_string_pretty(&c).unwrap())),
    };
    if let Err(e) = outcome {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
