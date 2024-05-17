use anyhow::{Context, Result};
use clap::Parser;
use garage_door::{issuer::Issuer, server::Server};
use std::net::{IpAddr, Ipv6Addr};
use std::process::ExitCode;
use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

#[derive(Clone, Debug, clap::Parser)]
pub struct Cli {
    /// Port to bind to
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,
    /// Address to bind to
    #[arg(short, long, default_value_t = Ipv6Addr::LOCALHOST.into())]
    pub bind: IpAddr,
    /// Public URL
    #[arg(short = 'u', long)]
    pub public_url: Option<Url>,
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

    let public_url = match cli.public_url {
        Some(public_url) => public_url,
        // FIXME: need to align default host with actual binding address
        None => Url::parse(&format!("http://localhost:{}", cli.port))?,
    };

    let mut server = Server::new();
    server
        .port(cli.port)
        .bind(cli.bind)
        .add_issuer(Issuer::new("chickens", public_url)?)?;
    server.run().await?;

    Ok(ExitCode::SUCCESS)
}
