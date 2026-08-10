use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "wist-bench", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Simulate,
    Report,
    Calibrate,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Simulate => {}
        Command::Report => {}
        Command::Calibrate => {}
    }
}
