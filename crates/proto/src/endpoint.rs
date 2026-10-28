use std::{net::SocketAddr, path::Path};

use anyhow::{Context, bail};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey,
    endpoint::{Connection, QuicTransportConfig, presets},
};
use remoc::{ConnectExt, RemoteSend};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerAddr {
    pub id: EndpointId,
    #[serde(default)]
    pub relays: Vec<RelayUrl>,
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
}

impl ServerAddr {
    pub fn endpoint_addr(&self) -> EndpointAddr {
        let addr = self
            .relays
            .iter()
            .cloned()
            .fold(EndpointAddr::new(self.id), EndpointAddr::with_relay_url);
        self.addrs
            .iter()
            .copied()
            .fold(addr, EndpointAddr::with_ip_addr)
    }
}

pub async fn bind_endpoint(
    secret_key: SecretKey,
    relays: &[RelayUrl],
    bind: Option<SocketAddr>,
    alpns: Vec<Vec<u8>>,
    transport: Option<QuicTransportConfig>,
) -> anyhow::Result<Endpoint> {
    let relay_mode = if relays.is_empty() {
        RelayMode::Disabled
    } else {
        RelayMode::Custom(relays.iter().cloned().collect())
    };
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .relay_mode(relay_mode)
        .alpns(alpns);
    if let Some(bind) = bind {
        builder = builder.bind_addr(bind)?;
    }
    if let Some(transport) = transport {
        builder = builder.transport_config(transport);
    }
    Ok(builder.bind().await?)
}

pub fn load_or_create_secret_key(path: &Path) -> anyhow::Result<SecretKey> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse_secret_key(text.trim())
            .with_context(|| format!("invalid secret key in {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            write_private(path, &encode_hex(&key.to_bytes()))
                .with_context(|| format!("writing secret key to {}", path.display()))?;
            Ok(key)
        }
        Err(err) => Err(err).with_context(|| format!("reading secret key {}", path.display())),
    }
}

fn parse_secret_key(hex: &str) -> anyhow::Result<SecretKey> {
    if hex.len() != 64 {
        bail!("expected 64 hex characters");
    }
    let mut bytes = [0u8; 32];
    for (byte, chunk) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(SecretKey::from_bytes(&bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

pub async fn provide_session<T: RemoteSend>(conn: &Connection, value: T) -> anyhow::Result<()> {
    let (send, recv) = conn.accept_bi().await?;
    remoc::Connect::io(remoc::Cfg::default(), recv, send)
        .provide(value)
        .await
        .map_err(|err| anyhow::anyhow!("providing session: {err}"))
}

pub async fn consume_session<T: RemoteSend>(conn: &Connection) -> anyhow::Result<T> {
    let (send, recv) = conn.open_bi().await?;
    remoc::Connect::io(remoc::Cfg::default(), recv, send)
        .consume()
        .await
        .map_err(|err| anyhow::anyhow!("consuming session: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_hex_round_trips() {
        let key = SecretKey::generate();
        let parsed = parse_secret_key(&encode_hex(&key.to_bytes())).unwrap();
        assert_eq!(parsed.public(), key.public());
    }
}
