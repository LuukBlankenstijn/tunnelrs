use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, VarInt},
};
use remoc::{
    RemoteSend,
    rtc::{ServeError, ServerShared},
};
use tracing::{debug, info, warn};
use tunnelrs_proto::{
    ADMIN_ALPN, Admin, AdminServerShared, AdminSession, ApiError, CONNECTOR_ALPN, Connector,
    ConnectorId, ConnectorInfo, ConnectorServerShared, ConnectorSession, DbId, Exposure, Hostname,
    RouteInfo, RouteSubscription, StatusSubscription, TlsMode, Watch, WatchServerShared,
    provide_session,
};

use crate::{
    config::{AdminKey, Role},
    control::{
        CLOSE_REJECTED, CLOSE_SETUP_FAILED, CLOSE_UNAUTHORIZED, CLOSE_UNSUPPORTED_ALPN, Control,
    },
    routing::SessionHandle,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REJECT_LINGER: Duration = Duration::from_secs(5);

pub struct Handlers {
    control: Control,
    admin_keys: HashMap<EndpointId, Role>,
    next_session: AtomicU64,
}

impl Handlers {
    pub fn new(control: Control, admin_keys: Vec<AdminKey>) -> Self {
        Self {
            control,
            admin_keys: admin_keys
                .into_iter()
                .map(|key| (key.id, key.role))
                .collect(),
            next_session: AtomicU64::new(1),
        }
    }

    async fn handle(&self, conn: Connection) {
        let alpn = conn.alpn();
        if alpn == CONNECTOR_ALPN {
            self.connector(conn).await;
        } else if alpn == ADMIN_ALPN {
            self.admin(conn).await;
        } else {
            warn!(peer = %conn.remote_id(), "connection with unsupported alpn");
            conn.close(
                VarInt::from_u32(CLOSE_UNSUPPORTED_ALPN),
                b"unsupported alpn",
            );
        }
    }

    async fn connector(&self, conn: Connection) {
        let connector = conn.remote_id();
        if let Err(reason) = self.control.check_handshake(connector).await {
            reject(&conn, connector, reason).await;
            return;
        }
        let session = self.next_session.fetch_add(1, Ordering::Relaxed);
        let handle = Arc::new(SessionHandle::new(session, connector, conn.clone()));
        if let Err(reason) = self.control.session_up(handle).await {
            reject(&conn, connector, reason).await;
            return;
        }
        let api = ConnectorApi {
            control: self.control.clone(),
            connector,
            session,
        };
        let (server, client) =
            ConnectorServerShared::<_, remoc::codec::Default>::new(Arc::new(api));
        tokio::spawn(serve("connector", server.serve()));
        if let Err(err) = provide(&conn, ConnectorSession::Accepted(client)).await {
            warn!(%connector, session, %err, "providing connector session failed");
            conn.close(
                VarInt::from_u32(CLOSE_SETUP_FAILED),
                b"session setup failed",
            );
        }
        let reason = conn.closed().await;
        debug!(%connector, session, %reason, "connector connection closed");
        self.control.session_down(session).await;
    }

    async fn admin(&self, conn: Connection) {
        let peer = conn.remote_id();
        let Some(role) = self.admin_keys.get(&peer).copied() else {
            warn!(%peer, "admin connection from unknown key");
            conn.close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"unknown admin key");
            return;
        };
        let session = match role {
            Role::Admin => {
                let api = AdminApi {
                    control: self.control.clone(),
                };
                let (server, client) =
                    AdminServerShared::<_, remoc::codec::Default>::new(Arc::new(api));
                tokio::spawn(serve("admin", server.serve()));
                AdminSession::Admin(client)
            }
            Role::Watcher => {
                let api = WatchApi {
                    control: self.control.clone(),
                };
                let (server, client) =
                    WatchServerShared::<_, remoc::codec::Default>::new(Arc::new(api));
                tokio::spawn(serve("watch", server.serve()));
                AdminSession::Watch(client)
            }
        };
        if let Err(err) = provide(&conn, session).await {
            warn!(%peer, ?role, %err, "providing admin session failed");
            conn.close(
                VarInt::from_u32(CLOSE_SETUP_FAILED),
                b"session setup failed",
            );
            return;
        }
        info!(%peer, ?role, "admin session open");
        let reason = conn.closed().await;
        info!(%peer, ?role, %reason, "admin session closed");
    }
}

pub async fn accept(endpoint: Endpoint, handlers: Arc<Handlers>) {
    while let Some(incoming) = endpoint.accept().await {
        let handlers = handlers.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => handlers.handle(conn).await,
                Err(err) => debug!(%err, "incoming connection failed"),
            }
        });
    }
}

async fn reject(conn: &Connection, connector: ConnectorId, reason: String) {
    info!(%connector, %reason, "rejecting connector");
    match provide(conn, ConnectorSession::Rejected(reason.clone())).await {
        Ok(()) => {
            let _ = tokio::time::timeout(REJECT_LINGER, conn.closed()).await;
        }
        Err(err) => debug!(%connector, %err, "sending rejection failed"),
    }
    conn.close(VarInt::from_u32(CLOSE_REJECTED), reason.as_bytes());
}

async fn provide<T: RemoteSend>(conn: &Connection, value: T) -> Result<(), String> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, provide_session(conn, value)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(format!("{err:#}")),
        Err(_) => Err("timed out waiting for the session stream".to_owned()),
    }
}

async fn serve(kind: &'static str, serving: impl Future<Output = Result<(), ServeError>>) {
    if let Err(err) = serving.await {
        debug!(kind, %err, "rpc server stopped");
    }
}

struct ConnectorApi {
    control: Control,
    connector: ConnectorId,
    session: u64,
}

impl Connector for ConnectorApi {
    async fn announce(&self, exposures: Vec<Exposure>) -> Result<(), ApiError> {
        debug!(
            connector = %self.connector,
            session = self.session,
            exposures = exposures.len(),
            "announce received"
        );
        self.control.announce(self.session, exposures).await
    }

    async fn status(&self) -> Result<StatusSubscription, ApiError> {
        self.control.subscribe_status(self.session).await
    }
}

struct AdminApi {
    control: Control,
}

impl Admin for AdminApi {
    async fn list(&self) -> Result<Vec<ConnectorInfo>, ApiError> {
        self.control.list().await
    }

    async fn approve(
        &self,
        id: ConnectorId,
        hosts: Option<Vec<String>>,
        tls_modes: Option<Vec<TlsMode>>,
    ) -> Result<(), ApiError> {
        self.control.approve(id, hosts, tls_modes).await
    }

    async fn deny(&self, id: ConnectorId) -> Result<(), ApiError> {
        self.control.deny(id).await
    }

    async fn revoke(&self, id: ConnectorId) -> Result<(), ApiError> {
        self.control.revoke(id).await
    }

    async fn routes(&self) -> Result<Vec<RouteInfo>, ApiError> {
        self.control.routes().await
    }

    async fn forget(&self, hostname: Hostname) -> Result<(), ApiError> {
        self.control.forget(hostname).await
    }

    async fn subscribe(&self) -> Result<(DbId, RouteSubscription), ApiError> {
        self.control.subscribe_routes().await
    }
}

struct WatchApi {
    control: Control,
}

impl Watch for WatchApi {
    async fn subscribe(&self) -> Result<(DbId, RouteSubscription), ApiError> {
        self.control.subscribe_routes().await
    }
}
