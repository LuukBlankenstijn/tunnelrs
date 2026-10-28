use std::{sync::Arc, time::Duration};

use anyhow::{Context, bail};
use iroh::endpoint::{RecvStream, SendStream};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tunnelrs_proto::TlsMode;

use crate::{
    routing::{self, ForwardTable, Lookup, Pool},
    sni::{self, SniError},
};

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CLIENT_HELLO: usize = 16 * 1024;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

pub async fn serve(listener: TcpListener, table: Arc<ForwardTable>) -> anyhow::Result<()> {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(%err, "tls listener accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        if let Err(err) = tcp.set_nodelay(true) {
            tracing::debug!(%peer, %err, "setting TCP_NODELAY failed");
        }
        let table = table.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(tcp, &table).await {
                tracing::debug!(%peer, "tls connection closed: {err:#}");
            }
        });
    }
}

async fn handle(mut tcp: TcpStream, table: &ForwardTable) -> anyhow::Result<()> {
    let (hello, hostname) = tokio::time::timeout(CLIENT_HELLO_TIMEOUT, read_client_hello(&mut tcp))
        .await
        .context("timed out reading ClientHello")??;
    let hostname = hostname.context("ClientHello carries no SNI")?;
    let pool = match routing::lookup(table, &hostname, TlsMode::Passthrough) {
        Lookup::Live(pool) => pool,
        Lookup::NoLiveConnector => bail!("no live connector for {hostname}"),
        Lookup::Unknown => bail!("unknown passthrough hostname {hostname}"),
    };
    let (mut send, recv) = open_data_stream(&pool, &hostname).await?;
    send.write_all(&hello)
        .await
        .context("forwarding ClientHello")?;
    let mut upstream = tokio::io::join(recv, send);
    tokio::io::copy_bidirectional(&mut tcp, &mut upstream)
        .await
        .with_context(|| format!("piping {hostname}"))?;
    Ok(())
}

async fn read_client_hello(tcp: &mut TcpStream) -> anyhow::Result<(Vec<u8>, Option<String>)> {
    let mut buf = vec![0; MAX_CLIENT_HELLO];
    let mut filled = 0;
    loop {
        let read = tcp.read(&mut buf[filled..]).await?;
        if read == 0 {
            bail!("connection closed before ClientHello completed");
        }
        filled += read;
        match sni::server_name(&buf[..filled]) {
            Ok(hostname) => {
                buf.truncate(filled);
                return Ok((buf, hostname));
            }
            Err(SniError::Incomplete) if filled < MAX_CLIENT_HELLO => {}
            Err(SniError::Incomplete) => bail!("ClientHello exceeds {MAX_CLIENT_HELLO} bytes"),
            Err(err @ SniError::Invalid) => return Err(err.into()),
        }
    }
}

async fn open_data_stream(pool: &Pool, hostname: &str) -> anyhow::Result<(SendStream, RecvStream)> {
    for session in pool.round_robin() {
        match session.open_data_stream(hostname).await {
            Ok(streams) => return Ok(streams),
            Err(err) => tracing::warn!(
                session = session.id,
                connector = %session.connector,
                hostname,
                %err,
                "opening passthrough data stream failed"
            ),
        }
    }
    bail!("no connector session could serve {hostname}")
}
