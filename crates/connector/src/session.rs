use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow, bail};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, VarInt},
};
use remoc::{robs::RecvError, rtc::Client};
use tokio::sync::watch;
use tracing::{info, warn};
use tunnelrs_proto::{
    CONNECTOR_ALPN, Connector, ConnectorClient, ConnectorSession, Exposure, Hostname, RouteStatus,
    ServerAddr, consume_session,
};

use crate::{
    config::{Targets, announcement},
    forward,
};

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const STABLE_SESSION: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STATUS_ENTRIES: usize = 65_536;

pub async fn run(
    endpoint: Endpoint,
    server: ServerAddr,
    mut targets: watch::Receiver<Arc<Targets>>,
) {
    let mut backoff = Backoff::new();
    loop {
        match establish(&endpoint, &server).await {
            Ok((conn, client)) => {
                let established = Instant::now();
                info!(server = %server.id, "session established");
                if let Err(err) = serve(&conn, &client, &mut targets, endpoint.id()).await {
                    warn!(error = format!("{err:#}"), "session failed");
                }
                conn.close(VarInt::from_u32(0), b"session ended");
                if established.elapsed() >= STABLE_SESSION {
                    backoff.reset();
                }
            }
            Err(err) => warn!(error = format!("{err:#}"), "could not establish a session"),
        }
        let delay = backoff.next_delay();
        info!(?delay, "reconnecting");
        tokio::time::sleep(delay).await;
    }
}

async fn establish(
    endpoint: &Endpoint,
    server: &ServerAddr,
) -> anyhow::Result<(Connection, ConnectorClient)> {
    let handshake = async {
        let conn = endpoint
            .connect(server.resolve().await?, CONNECTOR_ALPN)
            .await
            .context("connecting to the server")?;
        let session = consume_session::<ConnectorSession>(&conn).await?;
        anyhow::Ok((conn, session))
    };
    let (conn, session) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| anyhow!("handshake timed out after {HANDSHAKE_TIMEOUT:?}"))??;
    match session {
        ConnectorSession::Accepted(client) => Ok((conn, client)),
        ConnectorSession::Rejected(reason) => {
            conn.close(VarInt::from_u32(0), b"rejected");
            bail!("server rejected this connector: {reason}")
        }
    }
}

async fn serve(
    conn: &Connection,
    client: &ConnectorClient,
    targets: &mut watch::Receiver<Arc<Targets>>,
    connector_id: EndpointId,
) -> anyhow::Result<()> {
    let announced = announcement(&targets.borrow_and_update());
    client
        .announce(announced.clone())
        .await
        .context("announcing exposures")?;
    info!(exposures = announced.len(), "announced exposures");
    let stream_targets = targets.clone();
    tokio::select! {
        biased;
        err = forward::accept_streams(conn, stream_targets) => {
            info!(reason = %err, "session closed");
            Ok(())
        }
        result = reannounce(client, targets, announced) => result,
        result = watch_status(client, connector_id) => result,
        () = client.closed() => Err(anyhow!("control channel closed")),
    }
}

async fn reannounce(
    client: &ConnectorClient,
    targets: &mut watch::Receiver<Arc<Targets>>,
    mut announced: Vec<Exposure>,
) -> anyhow::Result<()> {
    while targets.changed().await.is_ok() {
        let next = announcement(&targets.borrow_and_update());
        if next != announced {
            client
                .announce(next.clone())
                .await
                .context("re-announcing exposures")?;
            info!(exposures = next.len(), "re-announced exposures");
            announced = next;
        }
    }
    std::future::pending().await
}

async fn watch_status(client: &ConnectorClient, connector_id: EndpointId) -> anyhow::Result<()> {
    let mut known = HashMap::new();
    loop {
        let mut mirror = client
            .status()
            .await
            .context("subscribing to route status")?
            .mirror(MAX_STATUS_ENTRIES);
        loop {
            let (current, done) = match mirror.borrow_and_update().await {
                Ok(view) => ((*view).clone(), view.is_done()),
                Err(RecvError::Lagged) => break,
                Err(err) => bail!("route status subscription failed: {err}"),
            };
            log_status_changes(&mut known, current, connector_id);
            if done {
                return std::future::pending().await;
            }
            mirror.changed().await;
        }
        warn!("route status subscription lagged; subscribing again");
    }
}

fn log_status_changes(
    known: &mut HashMap<Hostname, RouteStatus>,
    current: HashMap<Hostname, RouteStatus>,
    connector_id: EndpointId,
) {
    known.retain(|hostname, _| {
        let present = current.contains_key(hostname);
        if !present {
            info!(%hostname, "route status withdrawn");
        }
        present
    });
    for (hostname, status) in current {
        if known.get(&hostname) == Some(&status) {
            continue;
        }
        match &status {
            RouteStatus::Accepted => info!(%hostname, "route accepted"),
            RouteStatus::Pending => info!(
                %hostname,
                "route pending: an admin must approve this connector with `tunnelrs-ctl approve {connector_id}`"
            ),
            RouteStatus::Denied(reason) => warn!(%hostname, %reason, "route denied"),
            RouteStatus::Conflict(reason) => warn!(%hostname, %reason, "route in conflict"),
        }
        known.insert(hostname, status);
    }
}

struct Backoff {
    current: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self {
            current: INITIAL_BACKOFF,
        }
    }

    fn reset(&mut self) {
        self.current = INITIAL_BACKOFF;
    }

    fn next_delay(&mut self) -> Duration {
        let delay = self.current.mul_f64(rand::random_range(0.5..=1.0));
        self.current = (self.current * 2).min(MAX_BACKOFF);
        delay
    }
}
