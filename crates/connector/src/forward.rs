use std::{io, sync::Arc, time::Duration};

use iroh::endpoint::{Connection, ConnectionError, RecvStream, SendStream};
use tokio::{net::TcpStream, sync::watch};
use tracing::{debug, warn};
use tunnelrs_proto::{Ack, read_header, write_ack};

use crate::config::{Targets, normalize_hostname};

const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn accept_streams(
    conn: &Connection,
    targets: watch::Receiver<Arc<Targets>>,
) -> ConnectionError {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let targets = targets.clone();
                tokio::spawn(async move {
                    if let Err(err) = forward(send, recv, &targets).await {
                        debug!(error = %err, "data stream ended with an error");
                    }
                });
            }
            Err(err) => return err,
        }
    }
}

async fn forward(
    mut send: SendStream,
    mut recv: RecvStream,
    targets: &watch::Receiver<Arc<Targets>>,
) -> io::Result<()> {
    let hostname = normalize_hostname(&read_header(&mut recv).await?);
    let backend = targets
        .borrow()
        .get(&hostname)
        .map(|target| target.backend.clone());
    let Some(backend) = backend else {
        warn!(%hostname, "server forwarded a hostname that is not exposed");
        return write_ack(&mut send, Ack::UnknownHostname).await;
    };
    let connect = tokio::time::timeout(
        BACKEND_CONNECT_TIMEOUT,
        TcpStream::connect(backend.as_str()),
    );
    let mut tcp = match connect
        .await
        .map_err(io::Error::from)
        .and_then(|result| result)
    {
        Ok(tcp) => tcp,
        Err(err) => {
            warn!(%hostname, %backend, error = %err, "backend unreachable");
            return write_ack(&mut send, Ack::BackendUnreachable).await;
        }
    };
    write_ack(&mut send, Ack::Ok).await?;
    tcp.set_nodelay(true)?;
    let mut stream = tokio::io::join(recv, send);
    let (to_backend, from_backend) = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await?;
    debug!(%hostname, to_backend, from_backend, "data stream finished");
    Ok(())
}
