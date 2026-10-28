mod cluster;
mod config;
mod patch;
mod presets;
mod reconcile;
mod templates;
mod watch;

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;
use tracing_subscriber::EnvFilter;
use tunnelrs_proto::{bind_endpoint, load_or_create_secret_key};

use crate::cluster::Cluster;

#[derive(Parser)]
#[command(
    name = "tunnelrs-operator",
    version,
    about = "Creates routing objects for tunnelrs routes"
)]
struct Cli {
    #[arg(long, short)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = config::load(&cli.config)?;
    let client = kube::Client::try_default()
        .await
        .context("creating kubernetes client")?;
    let secret_key = load_or_create_secret_key(&config.key_path)?;
    let endpoint = bind_endpoint(secret_key, &config.server.relays, None, Vec::new(), None).await?;
    info!(id = %endpoint.id(), server = %config.server.id, "operator started");

    let mut cluster = Cluster::new(client);
    let mut terminate = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    tokio::select! {
        never = watch::run(&endpoint, &config, &mut cluster) => match never {},
        result = tokio::signal::ctrl_c() => result.context("waiting for ctrl-c")?,
        _ = terminate.recv() => {}
    }
    info!("shutting down");
    endpoint.close().await;
    Ok(())
}
