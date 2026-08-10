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
    Calibrate,
}

fn main() {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Simulate { flags } => flags.to_scenario().map(|sc| {
            println!("{}", wist_bench::cli::simulate_json(&sc));
        }),
        Command::Report => Ok(()),
        Command::Calibrate => Ok(()),
    };
    if let Err(e) = outcome {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
