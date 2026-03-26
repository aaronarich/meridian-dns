mod config;
mod listener;
mod resolver;
mod cache;
mod blocklist;
mod dnssec;
mod metrics;
mod tui;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "meridian", about = "A privacy-focused DNS recursive resolver")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "meridian.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Attach the live TUI dashboard
    Tui,
    /// Validate config and exit
    Check,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("meridian=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    let config = match config::Config::load(&cli.config) {
        Ok(c) => {
            info!("loaded config from {}", cli.config.display());
            c
        }
        Err(e) => {
            error!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    match cli.command {
        Some(Command::Check) => {
            println!("Config OK: {:#?}", config);
        }
        Some(Command::Tui) => {
            println!("TUI not yet implemented");
        }
        None => {
            info!(mode = ?config.mode, "starting meridian DNS resolver");
            println!("Resolver not yet implemented");
        }
    }
}
