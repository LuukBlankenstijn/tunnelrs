mod data;
mod endpoint;
mod hostname;

use std::collections::BTreeMap;

use iroh::EndpointId;
use remoc::{robs::hash_map::HashMapSubscription, rtc};
use serde::{Deserialize, Serialize};

pub use data::{Ack, MAX_HOSTNAME_LEN, read_ack, read_header, write_ack, write_header};
pub use endpoint::{
    ServerAddr, bind_endpoint, consume_session, load_or_create_secret_key, provide_session,
};
pub use hostname::host_matches;

pub const CONNECTOR_ALPN: &[u8] = b"tunnelrs/connector/1";
pub const ADMIN_ALPN: &[u8] = b"tunnelrs/admin/1";

pub const MAX_META_BYTES: usize = 4096;

pub type Hostname = String;
pub type Meta = BTreeMap<String, String>;
pub type ConnectorId = EndpointId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    Terminate,
    Passthrough,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposure {
    pub hostname: Hostname,
    pub tls: TlsMode,
    pub meta: Meta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteStatus {
    Accepted,
    Pending,
    Denied(String),
    Conflict(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Liveness {
    Live,
    Offline { since_unix: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolMember {
    pub connector: ConnectorId,
    pub sessions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteView {
    pub tls: TlsMode,
    pub meta: Meta,
    pub liveness: Liveness,
    pub members: Vec<PoolMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DbId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Enrollment {
    Pending,
    Approved,
    Denied,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorInfo {
    pub id: ConnectorId,
    pub enrollment: Enrollment,
    pub patterns: Vec<String>,
    pub tls_modes: Option<Vec<TlsMode>>,
    pub requested: Vec<Hostname>,
    pub sessions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub connector: ConnectorId,
    pub status: RouteStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteInfo {
    pub hostname: Hostname,
    pub view: Option<RouteView>,
    pub claims: Vec<Claim>,
}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum ApiError {
    #[error("rpc call failed: {0}")]
    Call(#[from] rtc::CallError),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("server error: {0}")]
    Internal(String),
}

pub type RouteSubscription = HashMapSubscription<Hostname, RouteView>;
pub type StatusSubscription = HashMapSubscription<Hostname, RouteStatus>;

#[rtc::remote]
pub trait Connector {
    async fn announce(&self, exposures: Vec<Exposure>) -> Result<(), ApiError>;
    async fn status(&self) -> Result<StatusSubscription, ApiError>;
}

#[rtc::remote]
pub trait Watch {
    async fn subscribe(&self) -> Result<(DbId, RouteSubscription), ApiError>;
}

#[rtc::remote]
pub trait Admin {
    async fn list(&self) -> Result<Vec<ConnectorInfo>, ApiError>;
    async fn approve(
        &self,
        id: ConnectorId,
        hosts: Option<Vec<String>>,
        tls_modes: Option<Vec<TlsMode>>,
    ) -> Result<(), ApiError>;
    async fn deny(&self, id: ConnectorId) -> Result<(), ApiError>;
    async fn revoke(&self, id: ConnectorId) -> Result<(), ApiError>;
    async fn routes(&self) -> Result<Vec<RouteInfo>, ApiError>;
    async fn forget(&self, hostname: Hostname) -> Result<(), ApiError>;
    async fn subscribe(&self) -> Result<(DbId, RouteSubscription), ApiError>;
}

#[derive(Serialize, Deserialize)]
pub enum AdminSession {
    Admin(AdminClient),
    Watch(WatchClient),
}

#[derive(Serialize, Deserialize)]
pub enum ConnectorSession {
    Accepted(ConnectorClient),
    Rejected(String),
}
