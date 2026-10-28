use std::{convert::Infallible, time::Duration};

use anyhow::{Context, bail};
use iroh::Endpoint;
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep};
use tracing::{info, warn};
use tunnelrs_proto::{ADMIN_ALPN, Admin as _, AdminSession, Watch as _, consume_session};

use crate::{cluster::Cluster, config::Config};

const MAX_ROUTES: usize = 100_000;
const RESYNC_INTERVAL: Duration = Duration::from_secs(60);
const DEBOUNCE: Duration = Duration::from_millis(500);
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

struct Backoff {
    next: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self { next: MIN_BACKOFF }
    }

    fn reset(&mut self) {
        self.next = MIN_BACKOFF;
    }

    fn advance(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(MAX_BACKOFF);
        delay
    }
}

pub async fn run(endpoint: &Endpoint, config: &Config, cluster: &mut Cluster) -> Infallible {
    let mut backoff = Backoff::new();
    loop {
        match session(endpoint, config, cluster, &mut backoff).await {
            Ok(()) => info!("route subscription ended"),
            Err(err) => warn!("route subscription failed: {err:#}"),
        }
        let delay = backoff.advance();
        info!(delay_secs = delay.as_secs(), "reconnecting to server");
        sleep(delay).await;
    }
}

async fn session(
    endpoint: &Endpoint,
    config: &Config,
    cluster: &mut Cluster,
    backoff: &mut Backoff,
) -> anyhow::Result<()> {
    let conn = endpoint
        .connect(config.server.resolve().await?, ADMIN_ALPN)
        .await
        .context("connecting to server")?;
    let session = consume_session::<AdminSession>(&conn).await?;
    let (db_id, subscription) = match &session {
        AdminSession::Admin(client) => client.subscribe().await,
        AdminSession::Watch(client) => client.subscribe().await,
    }
    .context("subscribing to routes")?;
    info!(db_id = %db_id.0, "subscribed to routes");
    let mut mirror = subscription.mirror(MAX_ROUTES);
    backoff.reset();

    let mut resync = interval_at(Instant::now() + RESYNC_INTERVAL, RESYNC_INTERVAL);
    resync.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let routes = {
            let view = mirror
                .borrow_and_update()
                .await
                .context("route subscription")?;
            if view.is_done() {
                return Ok(());
            }
            view.is_complete().then(|| (*view).clone())
        };
        if let Some(routes) = routes
            && let Err(err) = cluster.reconcile(&config.routing, &db_id, &routes).await
        {
            warn!("reconcile failed: {err:#}");
        }
        tokio::select! {
            () = mirror.changed() => sleep(DEBOUNCE).await,
            _ = resync.tick() => {}
            reason = conn.closed() => bail!("connection closed: {reason}"),
        }
    }
}
