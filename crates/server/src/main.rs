mod config;
mod control;
mod db;
mod handlers;
mod http;
mod model;
mod routing;
mod sni;
mod tls;

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::{Context, anyhow};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tunnelrs_proto::{ADMIN_ALPN, CONNECTOR_ALPN, bind_endpoint, load_or_create_secret_key};

use crate::{config::Config, db::Db, handlers::Handlers, routing::ForwardTable};

#[derive(Parser)]
#[command(
    version,
    about = "tunnelrs server: accepts connector sessions and forwards visitor traffic"
)]
struct Args {
    #[arg(long)]
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
    let config = Config::load(&args.config)
        .with_context(|| format!("loading config {}", args.config.display()))?;

    let secret_key = load_or_create_secret_key(&config.key_path)?;
    let db = Db::open(&config.database).await?;
    let table = Arc::new(ForwardTable::from_pointee(HashMap::new()));
    let control = control::start(db, table.clone(), config.offline_expiry_secs).await?;

    let endpoint = bind_endpoint(
        secret_key,
        &config.iroh.relays,
        config.iroh.bind,
        vec![CONNECTOR_ALPN.to_vec(), ADMIN_ALPN.to_vec()],
        None,
    )
    .await
    .context("binding iroh endpoint")?;
    info!(endpoint_id = %endpoint.id(), "iroh endpoint ready");
    println!("{}", endpoint.id());

    let http_listener = TcpListener::bind(config.http_listen)
        .await
        .with_context(|| format!("binding http listener on {}", config.http_listen))?;
    let tls_listener = TcpListener::bind(config.tls_listen)
        .await
        .with_context(|| format!("binding tls listener on {}", config.tls_listen))?;
    info!(http = %config.http_listen, tls = %config.tls_listen, "listening");

    let handlers = Arc::new(Handlers::new(control, config.admin_keys));
    let result = tokio::select! {
        result = http::serve(http_listener, table.clone()) => result.context("http listener"),
        result = tls::serve(tls_listener, table) => result.context("tls listener"),
        () = handlers::accept(endpoint.clone(), handlers) => Err(anyhow!("iroh endpoint stopped accepting connections")),
        result = tokio::signal::ctrl_c() => {
            info!("shutting down");
            result.context("waiting for ctrl-c")
        }
    };
    endpoint.close().await;
    result
}
