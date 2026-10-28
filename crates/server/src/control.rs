use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use iroh::endpoint::VarInt;
use remoc::{RemoteSend, robs::hash_map::ObservableHashMap};
use tokio::{
    sync::{mpsc, oneshot},
    time::MissedTickBehavior,
};
use tracing::{error, info};
use tunnelrs_proto::{
    ApiError, Claim, ConnectorId, ConnectorInfo, DbId, Enrollment, Exposure, Hostname, Liveness,
    PoolMember, RouteInfo, RouteStatus, RouteSubscription, RouteView, StatusSubscription, TlsMode,
};

use crate::{
    db::{Db, DbError},
    model::{ConnectorRecord, Model, normalize_hostname},
    routing::{ForwardTable, Pool, SessionHandle},
};

pub const CLOSE_DENIED: u32 = 1;
pub const CLOSE_REVOKED: u32 = 2;
pub const CLOSE_REJECTED: u32 = 3;
pub const CLOSE_UNAUTHORIZED: u32 = 4;
pub const CLOSE_UNSUPPORTED_ALPN: u32 = 5;
pub const CLOSE_SETUP_FAILED: u32 = 6;

const COMMAND_BUFFER: usize = 256;
const SUBSCRIPTION_BUFFER: usize = 1024;
const EXPIRY_INTERVAL: Duration = Duration::from_secs(60);
const STOPPED: &str = "control plane is not running";

type Reply<T> = oneshot::Sender<Result<T, ApiError>>;

enum Command {
    CheckHandshake {
        connector: ConnectorId,
        reply: oneshot::Sender<Result<(), String>>,
    },
    SessionUp {
        session: Arc<SessionHandle>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    SessionDown {
        session: u64,
        reply: oneshot::Sender<()>,
    },
    Announce {
        session: u64,
        exposures: Vec<Exposure>,
        reply: Reply<()>,
    },
    Approve {
        id: ConnectorId,
        hosts: Option<Vec<String>>,
        tls_modes: Option<Vec<TlsMode>>,
        reply: Reply<()>,
    },
    Deny {
        id: ConnectorId,
        reply: Reply<()>,
    },
    Revoke {
        id: ConnectorId,
        reply: Reply<()>,
    },
    Forget {
        hostname: Hostname,
        reply: Reply<()>,
    },
    ExpiryTick {
        reply: oneshot::Sender<()>,
    },
    List {
        reply: Reply<Vec<ConnectorInfo>>,
    },
    Routes {
        reply: Reply<Vec<RouteInfo>>,
    },
    SubscribeRoutes {
        reply: Reply<(DbId, RouteSubscription)>,
    },
    SubscribeStatus {
        session: u64,
        reply: Reply<StatusSubscription>,
    },
}

#[derive(Clone)]
pub struct Control {
    commands: mpsc::Sender<Command>,
}

impl Control {
    async fn call<T>(&self, command: impl FnOnce(oneshot::Sender<T>) -> Command) -> Option<T> {
        let (reply, response) = oneshot::channel();
        self.commands.send(command(reply)).await.ok()?;
        response.await.ok()
    }

    async fn request<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> Result<T, ApiError> {
        self.call(command)
            .await
            .unwrap_or_else(|| Err(ApiError::Internal(STOPPED.to_owned())))
    }

    pub async fn check_handshake(&self, connector: ConnectorId) -> Result<(), String> {
        self.call(|reply| Command::CheckHandshake { connector, reply })
            .await
            .unwrap_or_else(|| Err(STOPPED.to_owned()))
    }

    pub async fn session_up(&self, session: Arc<SessionHandle>) -> Result<(), String> {
        self.call(|reply| Command::SessionUp { session, reply })
            .await
            .unwrap_or_else(|| Err(STOPPED.to_owned()))
    }

    pub async fn session_down(&self, session: u64) {
        self.call(|reply| Command::SessionDown { session, reply })
            .await;
    }

    pub async fn announce(&self, session: u64, exposures: Vec<Exposure>) -> Result<(), ApiError> {
        self.request(|reply| Command::Announce {
            session,
            exposures,
            reply,
        })
        .await
    }

    pub async fn subscribe_status(&self, session: u64) -> Result<StatusSubscription, ApiError> {
        self.request(|reply| Command::SubscribeStatus { session, reply })
            .await
    }

    pub async fn approve(
        &self,
        id: ConnectorId,
        hosts: Option<Vec<String>>,
        tls_modes: Option<Vec<TlsMode>>,
    ) -> Result<(), ApiError> {
        self.request(|reply| Command::Approve {
            id,
            hosts,
            tls_modes,
            reply,
        })
        .await
    }

    pub async fn deny(&self, id: ConnectorId) -> Result<(), ApiError> {
        self.request(|reply| Command::Deny { id, reply }).await
    }

    pub async fn revoke(&self, id: ConnectorId) -> Result<(), ApiError> {
        self.request(|reply| Command::Revoke { id, reply }).await
    }

    pub async fn forget(&self, hostname: Hostname) -> Result<(), ApiError> {
        self.request(|reply| Command::Forget { hostname, reply })
            .await
    }

    pub async fn list(&self) -> Result<Vec<ConnectorInfo>, ApiError> {
        self.request(|reply| Command::List { reply }).await
    }

    pub async fn routes(&self) -> Result<Vec<RouteInfo>, ApiError> {
        self.request(|reply| Command::Routes { reply }).await
    }

    pub async fn subscribe_routes(&self) -> Result<(DbId, RouteSubscription), ApiError> {
        self.request(|reply| Command::SubscribeRoutes { reply })
            .await
    }

    async fn expiry_tick(&self) -> bool {
        self.call(|reply| Command::ExpiryTick { reply })
            .await
            .is_some()
    }
}

pub async fn start(
    db: Db,
    table: Arc<ForwardTable>,
    offline_expiry_secs: u64,
) -> anyhow::Result<Control> {
    let plane = ControlPlane::load(db, table, offline_expiry_secs).await?;
    let (commands, receiver) = mpsc::channel(COMMAND_BUFFER);
    tokio::spawn(plane.run(receiver));
    let control = Control { commands };
    tokio::spawn(expire_offline_routes(control.clone()));
    Ok(control)
}

async fn expire_offline_routes(control: Control) {
    let mut interval = tokio::time::interval(EXPIRY_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if !control.expiry_tick().await {
            break;
        }
    }
}

struct LiveSession {
    handle: Arc<SessionHandle>,
    announced: bool,
    status: ObservableHashMap<Hostname, RouteStatus>,
}

struct ControlPlane {
    db: Db,
    db_id: DbId,
    offline_expiry_secs: u64,
    model: Model,
    sessions: BTreeMap<u64, LiveSession>,
    views: ObservableHashMap<Hostname, RouteView>,
    table: Arc<ForwardTable>,
}

impl ControlPlane {
    async fn load(
        db: Db,
        table: Arc<ForwardTable>,
        offline_expiry_secs: u64,
    ) -> anyhow::Result<Self> {
        let db_id = db.db_id().await?;
        let stored = db.load().await?;
        let mut restored = stored.clone();
        restored.restore();
        let mut plane = Self {
            db,
            db_id,
            offline_expiry_secs,
            model: stored,
            sessions: BTreeMap::new(),
            views: ObservableHashMap::new(),
            table,
        };
        plane.apply(restored).await?;
        plane.publish();
        info!(
            db_id = %plane.db_id.0,
            connectors = plane.model.connectors.len(),
            routes = plane.model.routes.len(),
            "loaded server state"
        );
        Ok(plane)
    }

    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        while let Some(command) = commands.recv().await {
            self.handle(command).await;
        }
    }

    async fn handle(&mut self, command: Command) {
        match command {
            Command::CheckHandshake { connector, reply } => {
                let _ = reply.send(self.check_handshake(connector));
            }
            Command::SessionUp { session, reply } => {
                let result = self.session_up(session).await;
                self.publish();
                let _ = reply.send(result);
            }
            Command::SessionDown { session, reply } => {
                self.session_down(session).await;
                self.publish();
                let _ = reply.send(());
            }
            Command::Announce {
                session,
                exposures,
                reply,
            } => {
                let result = self.announce(session, exposures).await;
                self.publish();
                let _ = reply.send(result);
            }
            Command::Approve {
                id,
                hosts,
                tls_modes,
                reply,
            } => {
                let result = self.approve(id, hosts, tls_modes).await;
                self.publish();
                let _ = reply.send(result);
            }
            Command::Deny { id, reply } => {
                let result = self.deny(id).await;
                self.publish();
                let _ = reply.send(result);
            }
            Command::Revoke { id, reply } => {
                let result = self.revoke(id).await;
                self.publish();
                let _ = reply.send(result);
            }
            Command::Forget { hostname, reply } => {
                let result = self.forget(hostname).await;
                self.publish();
                let _ = reply.send(result);
            }
            Command::ExpiryTick { reply } => {
                self.expire().await;
                self.publish();
                let _ = reply.send(());
            }
            Command::List { reply } => {
                let _ = reply.send(Ok(self.list()));
            }
            Command::Routes { reply } => {
                let _ = reply.send(Ok(self.routes()));
            }
            Command::SubscribeRoutes { reply } => {
                let subscription = self.views.subscribe(SUBSCRIPTION_BUFFER);
                let _ = reply.send(Ok((self.db_id.clone(), subscription)));
            }
            Command::SubscribeStatus { session, reply } => {
                let _ = reply.send(self.subscribe_status(session));
            }
        }
    }

    async fn apply(&mut self, mut next: Model) -> Result<(), DbError> {
        let now = unix_now();
        next.settle(&self.live_connectors(), now);
        self.db.persist(&self.model, &next, now).await?;
        self.model = next;
        Ok(())
    }

    fn live_connectors(&self) -> BTreeSet<ConnectorId> {
        self.sessions
            .values()
            .filter(|session| session.announced)
            .map(|session| session.handle.connector)
            .collect()
    }

    fn check_handshake(&self, connector: ConnectorId) -> Result<(), String> {
        match self
            .model
            .connectors
            .get(&connector)
            .map(|record| record.enrollment)
        {
            Some(Enrollment::Denied) => Err("connector is denied".to_owned()),
            Some(Enrollment::Revoked) => Err("connector is revoked".to_owned()),
            _ => Ok(()),
        }
    }

    async fn session_up(&mut self, handle: Arc<SessionHandle>) -> Result<(), String> {
        let connector = handle.connector;
        let session = handle.id;
        self.check_handshake(connector)?;
        if !self.model.connectors.contains_key(&connector) {
            let mut next = self.model.clone();
            next.connectors
                .insert(connector, ConnectorRecord::new(Enrollment::Pending));
            self.apply(next).await.map_err(|err| {
                error!(%connector, %err, "registering connector failed");
                "server error while registering the connector".to_owned()
            })?;
            info!(%connector, "new connector is pending approval");
        }
        self.sessions.insert(
            session,
            LiveSession {
                handle,
                announced: false,
                status: ObservableHashMap::new(),
            },
        );
        info!(%connector, session, "connector session up");
        Ok(())
    }

    async fn session_down(&mut self, session: u64) {
        let Some(closed) = self.sessions.remove(&session) else {
            return;
        };
        info!(connector = %closed.handle.connector, session, "connector session down");
        if closed.announced {
            let next = self.model.clone();
            if let Err(err) = self.apply(next).await {
                error!(%err, "persisting route liveness failed");
            }
        }
    }

    async fn announce(&mut self, session: u64, exposures: Vec<Exposure>) -> Result<(), ApiError> {
        let (connector, announced) = self
            .sessions
            .get(&session)
            .map(|live| (live.handle.connector, live.announced))
            .ok_or_else(|| closed_session(session))?;
        let mut live = self.live_connectors();
        live.insert(connector);
        let mut next = self.model.clone();
        next.announce(connector, exposures, &live)?;
        self.mark_announced(session, true);
        if let Err(err) = self.apply(next).await {
            self.mark_announced(session, announced);
            return Err(internal(err));
        }
        info!(
            %connector,
            session,
            exposures = self
                .model
                .connectors
                .get(&connector)
                .map_or(0, |record| record.statuses.len()),
            "connector announced"
        );
        Ok(())
    }

    fn mark_announced(&mut self, session: u64, announced: bool) {
        if let Some(live) = self.sessions.get_mut(&session) {
            live.announced = announced;
        }
    }

    async fn approve(
        &mut self,
        id: ConnectorId,
        hosts: Option<Vec<String>>,
        tls_modes: Option<Vec<TlsMode>>,
    ) -> Result<(), ApiError> {
        let mut next = self.model.clone();
        next.approve(id, hosts, tls_modes, &self.live_connectors())?;
        self.apply(next).await.map_err(internal)?;
        info!(connector = %id, "connector approved");
        Ok(())
    }

    async fn deny(&mut self, id: ConnectorId) -> Result<(), ApiError> {
        let mut next = self.model.clone();
        next.deny(id, &self.live_connectors())?;
        self.apply(next).await.map_err(internal)?;
        self.close_sessions(id, CLOSE_DENIED, "connector denied");
        info!(connector = %id, "connector denied");
        Ok(())
    }

    async fn revoke(&mut self, id: ConnectorId) -> Result<(), ApiError> {
        let mut next = self.model.clone();
        next.revoke(id, &self.live_connectors())?;
        self.apply(next).await.map_err(internal)?;
        self.close_sessions(id, CLOSE_REVOKED, "connector revoked");
        info!(connector = %id, "connector revoked");
        Ok(())
    }

    async fn forget(&mut self, hostname: Hostname) -> Result<(), ApiError> {
        let host = normalize_hostname(&hostname);
        let live = self.live_connectors();
        let route = self
            .model
            .routes
            .get(&host)
            .ok_or_else(|| ApiError::NotFound(format!("no route for {host}")))?;
        if route.is_live(&live) {
            return Err(ApiError::Invalid(format!(
                "{host} is live; only offline routes can be forgotten"
            )));
        }
        let mut next = self.model.clone();
        next.withdraw(&host, &live);
        self.apply(next).await.map_err(internal)?;
        info!(hostname = %host, "route forgotten");
        Ok(())
    }

    async fn expire(&mut self) {
        let live = self.live_connectors();
        let expired = self
            .model
            .expired(&live, unix_now(), self.offline_expiry_secs);
        if expired.is_empty() {
            return;
        }
        let mut next = self.model.clone();
        for host in &expired {
            next.withdraw(host, &live);
        }
        match self.apply(next).await {
            Ok(()) => {
                for host in expired {
                    info!(hostname = %host, "offline route expired");
                }
            }
            Err(err) => error!(%err, "expiring offline routes failed"),
        }
    }

    fn close_sessions(&mut self, connector: ConnectorId, code: u32, reason: &str) {
        let closing: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, live)| live.handle.connector == connector)
            .map(|(session, _)| *session)
            .collect();
        for session in closing {
            if let Some(live) = self.sessions.remove(&session) {
                live.handle
                    .conn
                    .close(VarInt::from_u32(code), reason.as_bytes());
            }
        }
    }

    fn list(&self) -> Vec<ConnectorInfo> {
        let mut sessions: BTreeMap<ConnectorId, u32> = BTreeMap::new();
        for live in self.sessions.values() {
            *sessions.entry(live.handle.connector).or_default() += 1;
        }
        self.model
            .connectors
            .iter()
            .map(|(id, record)| ConnectorInfo {
                id: *id,
                enrollment: record.enrollment,
                patterns: record
                    .grant
                    .as_ref()
                    .map(|grant| grant.patterns.clone())
                    .unwrap_or_default(),
                tls_modes: record
                    .grant
                    .as_ref()
                    .and_then(|grant| grant.tls_modes.clone()),
                requested: record.announcement.keys().cloned().collect(),
                sessions: sessions.get(id).copied().unwrap_or(0),
            })
            .collect()
    }

    fn routes(&self) -> Vec<RouteInfo> {
        let mut claims: BTreeMap<&Hostname, Vec<Claim>> = self
            .model
            .routes
            .keys()
            .map(|host| (host, Vec::new()))
            .collect();
        for (id, record) in &self.model.connectors {
            for (host, status) in &record.statuses {
                claims.entry(host).or_default().push(Claim {
                    connector: *id,
                    status: status.clone(),
                });
            }
        }
        claims
            .into_iter()
            .map(|(host, claims)| RouteInfo {
                hostname: host.clone(),
                view: self.views.get(host).cloned(),
                claims,
            })
            .collect()
    }

    fn subscribe_status(&self, session: u64) -> Result<StatusSubscription, ApiError> {
        self.sessions
            .get(&session)
            .map(|live| live.status.subscribe(SUBSCRIPTION_BUFFER))
            .ok_or_else(|| closed_session(session))
    }

    fn publish(&mut self) {
        let now = unix_now();
        let mut counts: BTreeMap<ConnectorId, u32> = BTreeMap::new();
        for live in self.sessions.values().filter(|live| live.announced) {
            *counts.entry(live.handle.connector).or_default() += 1;
        }
        let current = self.table.load_full();
        let mut table = HashMap::with_capacity(self.model.routes.len());
        let mut views = BTreeMap::new();
        for (host, route) in &self.model.routes {
            let sessions: Vec<Arc<SessionHandle>> = self
                .sessions
                .values()
                .filter(|live| live.announced && route.members.contains(&live.handle.connector))
                .map(|live| live.handle.clone())
                .collect();
            let liveness = if sessions.is_empty() {
                Liveness::Offline {
                    since_unix: route.offline_since.unwrap_or(now),
                }
            } else {
                Liveness::Live
            };
            let members = route
                .members
                .iter()
                .map(|connector| PoolMember {
                    connector: *connector,
                    sessions: counts.get(connector).copied().unwrap_or(0),
                })
                .collect();
            views.insert(
                host.clone(),
                RouteView {
                    tls: route.tls,
                    meta: route.meta.clone(),
                    liveness,
                    members,
                },
            );
            let pool = match current.get(host) {
                Some(pool) if pool.tls == route.tls && same_sessions(&pool.sessions, &sessions) => {
                    pool.clone()
                }
                _ => Arc::new(Pool::new(route.tls, sessions)),
            };
            table.insert(host.clone(), pool);
        }
        self.table.store(Arc::new(table));
        sync(&mut self.views, &views);
        let empty = BTreeMap::new();
        for live in self.sessions.values_mut() {
            let desired = if live.announced {
                self.model
                    .connectors
                    .get(&live.handle.connector)
                    .map_or(&empty, |record| &record.statuses)
            } else {
                &empty
            };
            sync(&mut live.status, desired);
        }
    }
}

fn sync<V>(map: &mut ObservableHashMap<Hostname, V>, desired: &BTreeMap<Hostname, V>)
where
    V: Clone + PartialEq + RemoteSend,
{
    let stale: Vec<Hostname> = map
        .keys()
        .filter(|host| !desired.contains_key(*host))
        .cloned()
        .collect();
    for host in stale {
        map.remove(&host);
    }
    for (host, value) in desired {
        if map.get(host) != Some(value) {
            map.insert(host.clone(), value.clone());
        }
    }
}

fn same_sessions(current: &[Arc<SessionHandle>], next: &[Arc<SessionHandle>]) -> bool {
    current.len() == next.len()
        && current
            .iter()
            .zip(next)
            .all(|(current, next)| Arc::ptr_eq(current, next))
}

fn closed_session(session: u64) -> ApiError {
    ApiError::NotFound(format!("session {session} is closed"))
}

fn internal(err: DbError) -> ApiError {
    error!(%err, "persisting state failed");
    ApiError::Internal(format!("persisting state failed: {err}"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
