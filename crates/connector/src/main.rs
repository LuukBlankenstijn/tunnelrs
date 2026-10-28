mod config;
mod forward;
mod reload;
mod session;

use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::Parser;
use iroh::endpoint::{QuicTransportConfig, VarInt};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::watch,
};
use tracing::info;
use tracing_subscriber::EnvFilter;
use tunnelrs_proto::{bind_endpoint, load_or_create_secret_key};

const MAX_DATA_STREAMS: u32 = 4096;

#[derive(Parser)]
#[command(
    name = "tunnelrs-connector",
    version,
    about = "Expose local backends through a tunnelrs server"
)]
struct Args {
    #[arg(short, long, help = "Path to the connector config file (TOML)")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let config_path = std::path::absolute(&args.config)
        .with_context(|| format!("resolving {}", args.config.display()))?;
    let settings = config::load(&config_path)?;

    let secret_key = load_or_create_secret_key(&settings.key_path)?;
    let connector_id = secret_key.public();
    info!(
        %connector_id,
        "connector identity; an admin approves it with `tunnelrs-ctl approve {connector_id}`"
    );

    let transport = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_DATA_STREAMS))
        .build();
    let endpoint = bind_endpoint(
        secret_key,
        &settings.server.relays,
        None,
        Vec::new(),
        Some(transport),
    )
    .await
    .context("binding the iroh endpoint")?;

    let server = settings.server.endpoint_addr();
    let (targets_tx, targets_rx) = watch::channel(Arc::new(settings.targets.clone()));
    let hangup = signal(SignalKind::hangup()).context("installing the SIGHUP handler")?;
    let mut terminate =
        signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    tokio::spawn(reload::run(config_path, settings, targets_tx, hangup));

    tokio::select! {
        () = session::run(endpoint.clone(), server, targets_rx) => {}
        _ = tokio::signal::ctrl_c() => info!("interrupted; shutting down"),
        _ = terminate.recv() => info!("terminated; shutting down"),
    }
    endpoint.close().await;
    Ok(())
}
