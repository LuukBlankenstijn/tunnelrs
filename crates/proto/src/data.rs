use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_HOSTNAME_LEN: usize = 253;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ack {
    Ok = 0,
    UnknownHostname = 1,
    BackendUnreachable = 2,
}

impl TryFrom<u8> for Ack {
    type Error = io::Error;

    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::UnknownHostname),
            2 => Ok(Self::BackendUnreachable),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown ack code {other}"),
            )),
        }
    }
}

pub async fn write_header(out: &mut (impl AsyncWrite + Unpin), hostname: &str) -> io::Result<()> {
    if hostname.len() > MAX_HOSTNAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hostname too long",
        ));
    }
    out.write_u8(hostname.len() as u8).await?;
    out.write_all(hostname.as_bytes()).await
}

pub async fn read_header(input: &mut (impl AsyncRead + Unpin)) -> io::Result<String> {
    let len = usize::from(input.read_u8().await?);
    if len > MAX_HOSTNAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hostname too long",
        ));
    }
    let mut buf = vec![0; len];
    input.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub async fn write_ack(out: &mut (impl AsyncWrite + Unpin), ack: Ack) -> io::Result<()> {
    out.write_u8(ack as u8).await?;
    out.flush().await
}

pub async fn read_ack(input: &mut (impl AsyncRead + Unpin)) -> io::Result<Ack> {
    Ack::try_from(input.read_u8().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn header_round_trips_and_rejects_overlong_hostnames() {
        let mut buf = Vec::new();
        write_header(&mut buf, "app.example.com").await.unwrap();
        assert_eq!(
            read_header(&mut buf.as_slice()).await.unwrap(),
            "app.example.com"
        );

        let long = "a".repeat(MAX_HOSTNAME_LEN + 1);
        assert!(write_header(&mut Vec::new(), &long).await.is_err());
    }
}
