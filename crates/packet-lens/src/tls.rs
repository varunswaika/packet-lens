//! Finds the server name in a TLS ClientHello.
//!
//! The input is the start of the client's byte stream, after TCP
//! reassembly. The ClientHello can span several records and several
//! segments, so a short stream gives `Partial` and the caller tries again
//! when more has arrived.

use crate::bytes::{be16, u8_at};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hello {
    Sni(String),
    /// A ClientHello with no server name extension.
    NoSni,
    /// Looks like TLS so far; more bytes are needed.
    Partial,
    NotHello,
}

const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_NAME: u16 = 0;

pub fn client_hello(stream: &[u8]) -> Hello {
    // Gather the handshake bytes from as many records as it takes.
    let mut handshake = Vec::new();
    let mut at = 0;
    while let (Some(kind), Some(major), Some(len)) = (
        u8_at(stream, at),
        u8_at(stream, at + 1),
        be16(stream, at + 3),
    ) {
        if kind != HANDSHAKE || major != 3 {
            return Hello::NotHello;
        }
        let start = at + 5;
        let end = (start + usize::from(len)).min(stream.len());
        handshake.extend_from_slice(&stream[start..end]);
        at = start + usize::from(len);

        if let Some(kind) = handshake.first()
            && *kind != CLIENT_HELLO
        {
            return Hello::NotHello;
        }
        if let Some(len) = handshake.get(1..4) {
            let len = u32::from_be_bytes([0, len[0], len[1], len[2]]) as usize;
            if let Some(body) = handshake.get(4..4 + len) {
                return server_name(body).unwrap_or(Hello::NotHello);
            }
        }
    }
    // Stopped inside a record header: check what there is of it.
    match (stream.get(at), stream.get(at + 1)) {
        (Some(&kind), _) if kind != HANDSHAKE => Hello::NotHello,
        (_, Some(&major)) if major != 3 => Hello::NotHello,
        _ => Hello::Partial,
    }
}

/// Walks a ClientHello body to the server_name extension. `None` if the
/// lengths do not fit.
fn server_name(body: &[u8]) -> Option<Hello> {
    // Version and random, then the session id.
    let mut at = 34;
    at += 1 + usize::from(u8_at(body, at)?);
    at += 2 + usize::from(be16(body, at)?); // cipher suites
    at += 1 + usize::from(u8_at(body, at)?); // compression methods
    if at == body.len() {
        return Some(Hello::NoSni);
    }
    let end = at + 2 + usize::from(be16(body, at)?);
    let extensions = body.get(at + 2..end)?;

    let mut at = 0;
    while at < extensions.len() {
        let kind = be16(extensions, at)?;
        let len = usize::from(be16(extensions, at + 2)?);
        let data = extensions.get(at + 4..at + 4 + len)?;
        if kind == SERVER_NAME {
            return host_name(data).map(Hello::Sni);
        }
        at += 4 + len;
    }
    Some(Hello::NoSni)
}

fn host_name(data: &[u8]) -> Option<String> {
    let list_len = usize::from(be16(data, 0)?);
    let list = data.get(2..2 + list_len)?;
    let mut at = 0;
    while at < list.len() {
        let kind = u8_at(list, at)?;
        let len = usize::from(be16(list, at + 1)?);
        let name = list.get(at + 3..at + 3 + len)?;
        if kind == 0 {
            return Some(String::from_utf8_lossy(name).into_owned());
        }
        at += 3 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut e = kind.to_be_bytes().to_vec();
        e.extend((data.len() as u16).to_be_bytes());
        e.extend(data);
        e
    }

    fn sni(name: &str) -> Vec<u8> {
        let mut entry = vec![0];
        entry.extend((name.len() as u16).to_be_bytes());
        entry.extend(name.as_bytes());
        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend(entry);
        extension(SERVER_NAME, &list)
    }

    fn hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7; 32]);
        body.extend([0]);
        body.extend([0, 4, 0x13, 0x01, 0x13, 0x02]);
        body.extend([1, 0]);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        let mut handshake = vec![CLIENT_HELLO, 0];
        handshake.extend((body.len() as u16).to_be_bytes());
        handshake.extend(body);
        handshake
    }

    fn records(handshake: &[u8], size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in handshake.chunks(size) {
            out.extend([HANDSHAKE, 3, 1]);
            out.extend((chunk.len() as u16).to_be_bytes());
            out.extend(chunk);
        }
        out
    }

    #[test]
    fn finds_the_name_among_other_extensions() {
        let mut ext = extension(0x002b, &[2, 3, 4]);
        ext.extend(sni("example.org"));
        ext.extend(extension(0x0010, b"\x00\x03\x02h2"));
        let stream = records(&hello(&ext), 1 << 14);
        assert_eq!(client_hello(&stream), Hello::Sni("example.org".into()));
    }

    #[test]
    fn hello_split_over_records_and_segments() {
        let stream = records(&hello(&sni("split.example")), 10);
        for cut in 0..stream.len() {
            assert_eq!(client_hello(&stream[..cut]), Hello::Partial, "cut at {cut}");
        }
        assert_eq!(client_hello(&stream), Hello::Sni("split.example".into()));
    }

    #[test]
    fn without_a_name() {
        let stream = records(&hello(&extension(0x002b, &[2, 3, 4])), 1 << 14);
        assert_eq!(client_hello(&stream), Hello::NoSni);
    }

    #[test]
    fn other_traffic() {
        assert_eq!(client_hello(b"GET / HTTP/1.1\r\n"), Hello::NotHello);
        // A ServerHello, as a server would send.
        assert_eq!(
            client_hello(&records(&[2, 0, 0, 1, 0], 100)),
            Hello::NotHello
        );
        // A ClientHello whose lengths overrun the message.
        let mut bad = hello(&sni("x"));
        let at = bad.len() - 8;
        bad[at] = 0xff;
        assert_eq!(client_hello(&records(&bad, 1 << 14)), Hello::NotHello);
    }
}
