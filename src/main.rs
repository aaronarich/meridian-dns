mod blocklist;
mod cache;
mod config;
mod dnssec;
mod listener;
mod metrics;
mod resolver;
mod stats;
mod tui;

use std::sync::Arc;

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
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");

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
            if let Err(e) = tui::run_demo(&config.tui) {
                error!("TUI error: {e}");
                std::process::exit(1);
            }
        }
        None => {
            info!(mode = ?config.mode, listen = %config.listen, "starting meridian DNS resolver");

            let shared_stats = stats::new_shared_stats();
            let shared_cache = cache::new_shared_cache(config.cache.max_entries);
            let shared_blocklist = blocklist::new_shared_blocklist();

            // Load blocklists on startup
            blocklist::load(&config.blocklist, &shared_blocklist).await;

            // Spawn background refresh task
            blocklist::spawn_refresh_task(config.blocklist.clone(), shared_blocklist.clone());

            let config = Arc::new(config);

            if let Err(e) = listener::start(config, shared_stats, shared_cache, shared_blocklist).await {
                error!("listener error: {e}");
                std::process::exit(1);
            }
        }
    }
}
