use anyhow::{Context, Result};
use clap::Parser;
use garage_door::config::Configuration;
use garage_door::server::Server;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::process::ExitCode;
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone, Debug, clap::Parser)]
pub struct Cli {
    /// Port to bind to
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,
    /// Address to bind to
    #[arg(short, long, default_value_t = Ipv6Addr::LOCALHOST.into())]
    pub bind: IpAddr,
    /// Base URL
    #[arg(short = 'B', long)]
    pub base: Option<String>,
    /// Configuration file
    #[arg(short, long, default_value = "garage-door.yaml")]
    pub config: PathBuf,
}

fn init_log() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(true)
                .with_target(true)
                .with_level(true)
                .compact(),
        )
        .try_init()
        .context("error initializing logging")?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    init_log()?;

    tracing::info!("Starting up...");

    let config: Configuration = serde_yaml::from_reader(std::fs::File::open(&cli.config)?)?;

    log::debug!("Read config file");

    let mut server = Server::new();
    server.port(cli.port).bind(cli.bind);

    if let Some(base) = &cli.base {
        server.base(base);
    }

    for (name, issuer) in config.issuers {
        server.add_issuer(name, issuer)?;
    }

    server.run().await?;

    Ok(ExitCode::SUCCESS)
}
