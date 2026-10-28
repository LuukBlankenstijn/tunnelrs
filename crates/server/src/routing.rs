use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use arc_swap::ArcSwap;
use hyper::{body::Incoming, client::conn::http1::SendRequest};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tunnelrs_proto::{Ack, ConnectorId, Hostname, TlsMode, read_ack, write_header};

pub type ForwardTable = ArcSwap<HashMap<Hostname, Arc<Pool>>>;

pub struct SessionHandle {
    pub id: u64,
    pub connector: ConnectorId,
    pub conn: Connection,
    pub idle_http: Mutex<HashMap<Hostname, Vec<SendRequest<Incoming>>>>,
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("opening data stream: {0}")]
    Stream(String),
    #[error("connector rejected data stream: {0:?}")]
    Rejected(Ack),
}

impl SessionHandle {
    pub fn new(id: u64, connector: ConnectorId, conn: Connection) -> Self {
        Self {
            id,
            connector,
            conn,
            idle_http: Mutex::new(HashMap::new()),
        }
    }

    pub async fn open_data_stream(
        &self,
        hostname: &str,
    ) -> Result<(SendStream, RecvStream), OpenError> {
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|err| OpenError::Stream(err.to_string()))?;
        write_header(&mut send, hostname)
            .await
            .map_err(|err| OpenError::Stream(err.to_string()))?;
        match read_ack(&mut recv)
            .await
            .map_err(|err| OpenError::Stream(err.to_string()))?
        {
            Ack::Ok => Ok((send, recv)),
            rejected => Err(OpenError::Rejected(rejected)),
        }
    }
}

pub struct Pool {
    pub tls: TlsMode,
    pub sessions: Vec<Arc<SessionHandle>>,
    next: AtomicUsize,
}

impl Pool {
    pub fn new(tls: TlsMode, sessions: Vec<Arc<SessionHandle>>) -> Self {
        Self {
            tls,
            sessions,
            next: AtomicUsize::new(0),
        }
    }

    pub fn round_robin(&self) -> impl Iterator<Item = &Arc<SessionHandle>> {
        let start = match self.sessions.len() {
            0 => 0,
            len => self.next.fetch_add(1, Ordering::Relaxed) % len,
        };
        self.sessions[start..]
            .iter()
            .chain(self.sessions[..start].iter())
    }
}

pub enum Lookup {
    Live(Arc<Pool>),
    NoLiveConnector,
    Unknown,
}

pub fn lookup(table: &ForwardTable, hostname: &str, mode: TlsMode) -> Lookup {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    match table.load().get(&hostname) {
        Some(pool) if pool.tls != mode => Lookup::Unknown,
        Some(pool) if pool.sessions.is_empty() => Lookup::NoLiveConnector,
        Some(pool) => Lookup::Live(pool.clone()),
        None => Lookup::Unknown,
    }
}
