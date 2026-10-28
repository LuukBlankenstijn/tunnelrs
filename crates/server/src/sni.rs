const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXTENSION_SERVER_NAME: u16 = 0;
const NAME_TYPE_HOST_NAME: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SniError {
    #[error("ClientHello is incomplete")]
    Incomplete,
    #[error("not a TLS ClientHello")]
    Invalid,
}

pub fn server_name(buf: &[u8]) -> Result<Option<String>, SniError> {
    let mut handshake = Vec::new();
    let mut records = buf;
    loop {
        if let Some(body) = complete_handshake(&handshake)? {
            return parse_client_hello(body);
        }
        if records.len() < RECORD_HEADER_LEN {
            return Err(SniError::Incomplete);
        }
        if records[0] != CONTENT_TYPE_HANDSHAKE || records[1] != 3 {
            return Err(SniError::Invalid);
        }
        let len = usize::from(u16::from_be_bytes([records[3], records[4]]));
        if len == 0 {
            return Err(SniError::Invalid);
        }
        let Some(fragment) = records.get(RECORD_HEADER_LEN..RECORD_HEADER_LEN + len) else {
            return Err(SniError::Incomplete);
        };
        handshake.extend_from_slice(fragment);
        records = &records[RECORD_HEADER_LEN + len..];
    }
}

fn complete_handshake(handshake: &[u8]) -> Result<Option<&[u8]>, SniError> {
    let Some(header) = handshake.get(..HANDSHAKE_HEADER_LEN) else {
        return Ok(None);
    };
    if header[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(SniError::Invalid);
    }
    let len = usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
    Ok(handshake.get(HANDSHAKE_HEADER_LEN..HANDSHAKE_HEADER_LEN + len))
}

fn parse_client_hello(body: &[u8]) -> Result<Option<String>, SniError> {
    let mut hello = Reader(body);
    hello.take(2 + 32)?;
    hello.vec8()?;
    hello.vec16()?;
    hello.vec8()?;
    if hello.0.is_empty() {
        return Ok(None);
    }
    let mut extensions = Reader(hello.vec16()?);
    while !extensions.0.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        if kind == EXTENSION_SERVER_NAME {
            return parse_server_name_extension(data);
        }
    }
    Ok(None)
}

fn parse_server_name_extension(data: &[u8]) -> Result<Option<String>, SniError> {
    let mut names = Reader(Reader(data).vec16()?);
    while !names.0.is_empty() {
        let name_type = names.u8()?;
        let name = names.vec16()?;
        if name_type == NAME_TYPE_HOST_NAME {
            return normalize(name).map(Some);
        }
    }
    Ok(None)
}

fn normalize(name: &[u8]) -> Result<String, SniError> {
    let name = std::str::from_utf8(name).map_err(|_| SniError::Invalid)?;
    let name = name.trim_end_matches('.');
    if name.is_empty() || !name.is_ascii() {
        return Err(SniError::Invalid);
    }
    Ok(name.to_ascii_lowercase())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], SniError> {
        if self.0.len() < len {
            return Err(SniError::Invalid);
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, SniError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, SniError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn vec8(&mut self) -> Result<&'a [u8], SniError> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    fn vec16(&mut self) -> Result<&'a [u8], SniError> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec16(data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(data);
        out
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend(vec16(data));
        out
    }

    fn sni_extension(host: &str) -> Vec<u8> {
        let mut entry = vec![NAME_TYPE_HOST_NAME];
        entry.extend(vec16(host.as_bytes()));
        extension(EXTENSION_SERVER_NAME, &vec16(&entry))
    }

    fn handshake(extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7; 32]);
        body.push(32);
        body.extend([9; 32]);
        body.extend(vec16(&[0x13, 0x01, 0x13, 0x02]));
        body.extend([1, 0]);
        body.extend(vec16(&extensions.concat()));
        let len = body.len() as u32;
        let mut out = vec![HANDSHAKE_CLIENT_HELLO];
        out.extend(&len.to_be_bytes()[1..]);
        out.extend(body);
        out
    }

    fn records(handshake: &[u8], fragment_len: usize) -> Vec<u8> {
        handshake
            .chunks(fragment_len)
            .flat_map(|fragment| {
                let mut record = vec![CONTENT_TYPE_HANDSHAKE, 3, 1];
                record.extend((fragment.len() as u16).to_be_bytes());
                record.extend(fragment);
                record
            })
            .collect()
    }

    fn hello_with_sni(host: &str) -> Vec<u8> {
        let alpn = extension(16, &vec16(&[2, b'h', b'2']));
        records(&handshake(&[alpn, sni_extension(host)]), usize::MAX)
    }

    #[test]
    fn extracts_and_lowercases_server_name() {
        assert_eq!(
            server_name(&hello_with_sni("App.Example.COM.")),
            Ok(Some("app.example.com".to_owned()))
        );
    }

    #[test]
    fn client_hello_without_server_name_has_none() {
        let alpn = extension(16, &vec16(&[2, b'h', b'2']));
        assert_eq!(
            server_name(&records(&handshake(&[alpn]), usize::MAX)),
            Ok(None)
        );
        assert_eq!(server_name(&records(&handshake(&[]), usize::MAX)), Ok(None));
    }

    #[test]
    fn client_hello_split_across_records_is_reassembled() {
        let split = records(&handshake(&[sni_extension("a.example.com")]), 7);
        assert_eq!(server_name(&split), Ok(Some("a.example.com".to_owned())));
    }

    #[test]
    fn every_truncation_is_incomplete() {
        for hello in [
            hello_with_sni("app.example.com"),
            records(&handshake(&[sni_extension("app.example.com")]), 11),
        ] {
            for len in 0..hello.len() {
                assert_eq!(
                    server_name(&hello[..len]),
                    Err(SniError::Incomplete),
                    "prefix {len}"
                );
            }
        }
    }

    #[test]
    fn rejects_non_tls_and_malformed_hellos() {
        assert_eq!(server_name(b"GET / HTTP/1.1\r\n"), Err(SniError::Invalid));

        let mut lying_extensions = handshake(&[sni_extension("app.example.com")]);
        let last = lying_extensions.len() - 1;
        lying_extensions.truncate(last);
        let len = (lying_extensions.len() - HANDSHAKE_HEADER_LEN) as u32;
        lying_extensions[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        assert_eq!(
            server_name(&records(&lying_extensions, usize::MAX)),
            Err(SniError::Invalid)
        );
    }
}
