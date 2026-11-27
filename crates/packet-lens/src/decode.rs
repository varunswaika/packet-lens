//! Decodes one frame down to its transport header.
//!
//! Lengths come from the headers where they can, so Ethernet padding is not
//! taken for payload. A header that is cut short makes the layer
//! `Malformed`; whatever was decoded above it still counts.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::bytes::{array, be16, be32, u8_at};
use crate::capture::LinkType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub link: &'static str,
    pub net: Net<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Net<'a> {
    Ip(Ip<'a>),
    Arp,
    /// A frame type this does not decode, such as LLDP.
    Unknown,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ip<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub transport: Transport<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport<'a> {
    Tcp(Tcp<'a>),
    Udp(Udp<'a>),
    Icmp,
    Icmpv6,
    /// A later IP fragment, which carries no transport header.
    Fragment,
    Other(u8),
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;

pub fn decode(link: LinkType, data: &[u8]) -> Packet<'_> {
    let (name, net) = match link {
        LinkType::Ethernet => ("ethernet", ethernet(data)),
        LinkType::LinuxSll => ("linux-sll", by_ethertype(be16(data, 14), data.get(16..))),
        LinkType::LinuxSll2 => ("linux-sll2", by_ethertype(be16(data, 0), data.get(20..))),
        LinkType::Null => ("loopback", null(data)),
        LinkType::Raw => ("raw-ip", raw(data)),
        LinkType::Other(_) => ("other", Net::Unknown),
    };
    Packet { link: name, net }
}

fn ethernet(data: &[u8]) -> Net<'_> {
    let mut at = 12;
    for _ in 0..3 {
        match be16(data, at) {
            Some(ETHERTYPE_VLAN | ETHERTYPE_QINQ) => at += 4,
            kind => return by_ethertype(kind, data.get(at + 2..)),
        }
    }
    Net::Malformed
}

fn by_ethertype(kind: Option<u16>, rest: Option<&[u8]>) -> Net<'_> {
    let (Some(kind), Some(rest)) = (kind, rest) else {
        return Net::Malformed;
    };
    match kind {
        ETHERTYPE_IPV4 => ipv4(rest),
        ETHERTYPE_IPV6 => ipv6(rest),
        ETHERTYPE_ARP => Net::Arp,
        _ => Net::Unknown,
    }
}

/// BSD loopback starts with the address family in the writer's byte order,
/// and the BSDs disagree on the value for IPv6.
fn null(data: &[u8]) -> Net<'_> {
    let Some(family) = array::<4>(data, 0) else {
        return Net::Malformed;
    };
    let family = u32::from_le_bytes(family).min(u32::from_be_bytes(family));
    match family {
        2 => ipv4(&data[4..]),
        24 | 28 | 30 => ipv6(&data[4..]),
        _ => Net::Unknown,
    }
}

fn raw(data: &[u8]) -> Net<'_> {
    match u8_at(data, 0).map(|b| b >> 4) {
        Some(4) => ipv4(data),
        Some(6) => ipv6(data),
        _ => Net::Malformed,
    }
}

fn ipv4(data: &[u8]) -> Net<'_> {
    let Some(header) = array::<20>(data, 0) else {
        return Net::Malformed;
    };
    let header_len = usize::from(header[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
    if header[0] >> 4 != 4 || header_len < 20 || total < header_len {
        return Net::Malformed;
    }
    // Trim Ethernet padding, but keep what was captured if the snap
    // length cut the packet short.
    let body = data
        .get(header_len..total.min(data.len()))
        .unwrap_or_default();
    let fragment_offset = u16::from_be_bytes([header[6], header[7]]) & 0x1fff;
    let src = Ipv4Addr::from(array::<4>(&header, 12).unwrap_or_default());
    let dst = Ipv4Addr::from(array::<4>(&header, 16).unwrap_or_default());
    let transport = if fragment_offset != 0 {
        Transport::Fragment
    } else {
        transport(header[9], body)
    };
    Net::Ip(Ip {
        src: src.into(),
        dst: dst.into(),
        transport,
    })
}

fn ipv6(data: &[u8]) -> Net<'_> {
    let Some(header) = array::<40>(data, 0) else {
        return Net::Malformed;
    };
    if header[0] >> 4 != 6 {
        return Net::Malformed;
    }
    let payload_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let mut body = &data[40..(40 + payload_len).min(data.len())];
    let src = Ipv6Addr::from(array::<16>(&header, 8).unwrap_or_default());
    let dst = Ipv6Addr::from(array::<16>(&header, 24).unwrap_or_default());
    let ip = |transport| {
        Net::Ip(Ip {
            src: src.into(),
            dst: dst.into(),
            transport,
        })
    };

    let mut next = header[6];
    // Walk the extension headers, giving up after a sane number.
    for _ in 0..8 {
        let len = match next {
            0 | 43 | 60 => u8_at(body, 1).map(|n| (usize::from(n) + 1) * 8),
            51 => u8_at(body, 1).map(|n| (usize::from(n) + 2) * 4),
            44 => {
                if be16(body, 2).is_some_and(|f| f >> 3 != 0) {
                    return ip(Transport::Fragment);
                }
                Some(8)
            }
            _ => return ip(transport(next, body)),
        };
        let (Some(len), Some(kind)) = (len, u8_at(body, 0)) else {
            return ip(Transport::Malformed);
        };
        let Some(rest) = body.get(len..) else {
            return ip(Transport::Malformed);
        };
        next = kind;
        body = rest;
    }
    ip(Transport::Malformed)
}

fn transport(protocol: u8, body: &[u8]) -> Transport<'_> {
    match protocol {
        6 => tcp(body),
        17 => udp(body),
        1 => Transport::Icmp,
        58 => Transport::Icmpv6,
        other => Transport::Other(other),
    }
}

fn tcp(body: &[u8]) -> Transport<'_> {
    let (Some(src_port), Some(dst_port), Some(seq), Some(offset), Some(flags)) = (
        be16(body, 0),
        be16(body, 2),
        be32(body, 4),
        u8_at(body, 12),
        u8_at(body, 13),
    ) else {
        return Transport::Malformed;
    };
    let header_len = usize::from(offset >> 4) * 4;
    if header_len < 20 {
        return Transport::Malformed;
    }
    let Some(payload) = body.get(header_len..) else {
        return Transport::Malformed;
    };
    Transport::Tcp(Tcp {
        src_port,
        dst_port,
        seq,
        flags,
        payload,
    })
}

fn udp(body: &[u8]) -> Transport<'_> {
    let (Some(src_port), Some(dst_port), Some(len)) = (be16(body, 0), be16(body, 2), be16(body, 4))
    else {
        return Transport::Malformed;
    };
    let Some(payload) = body.get(8..usize::from(len).min(body.len())) else {
        return Transport::Malformed;
    };
    Transport::Udp(Udp {
        src_port,
        dst_port,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp(payload: &[u8]) -> Vec<u8> {
        let total = (28 + payload.len()) as u16;
        let mut p = vec![0x45, 0];
        p.extend(total.to_be_bytes());
        p.extend([0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
        p.extend([0x30, 0x39, 0, 53]);
        p.extend((8 + payload.len() as u16).to_be_bytes());
        p.extend([0, 0]);
        p.extend(payload);
        p
    }

    fn ether(ethertype: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0; 12];
        f.extend(ethertype.to_be_bytes());
        f.extend(body);
        f
    }

    fn udp_payload(packet: &Packet<'_>) -> Option<Vec<u8>> {
        match &packet.net {
            Net::Ip(Ip {
                transport: Transport::Udp(u),
                ..
            }) => Some(u.payload.to_vec()),
            _ => None,
        }
    }

    #[test]
    fn ethernet_padding_is_not_payload() {
        let mut frame = ether(ETHERTYPE_IPV4, &ipv4_udp(b"hi"));
        frame.resize(60, 0xee);
        let p = decode(LinkType::Ethernet, &frame);
        assert_eq!(udp_payload(&p).unwrap(), b"hi");
    }

    #[test]
    fn short_capture_keeps_what_it_has() {
        let frame = ether(ETHERTYPE_IPV4, &ipv4_udp(b"hello"));
        let p = decode(LinkType::Ethernet, &frame[..frame.len() - 2]);
        assert_eq!(udp_payload(&p).unwrap(), b"hel");
    }

    #[test]
    fn later_fragments_have_no_ports() {
        let mut ip = ipv4_udp(b"data");
        ip[7] = 0x10;
        let Net::Ip(ip) = decode(LinkType::Raw, &ip).net else {
            panic!()
        };
        assert_eq!(ip.transport, Transport::Fragment);
    }

    #[test]
    fn ipv6_extension_headers() {
        let mut p = vec![0x60, 0, 0, 0, 0, 24, 0, 64];
        p.extend([0; 32]);
        // Hop-by-hop options, 8 bytes, then UDP.
        p.extend([17, 0, 0, 0, 0, 0, 0, 0]);
        p.extend([0, 1, 0, 2, 0, 16, 0, 0]);
        p.extend(b"ipv6ipv6");
        let packet = decode(LinkType::Raw, &p);
        assert_eq!(udp_payload(&packet).unwrap(), b"ipv6ipv6");
    }

    #[test]
    fn bad_headers() {
        let mut ip = ipv4_udp(b"");
        ip[0] = 0x44;
        assert_eq!(decode(LinkType::Raw, &ip).net, Net::Malformed);
        assert_eq!(decode(LinkType::Ethernet, &[0; 13]).net, Net::Malformed);
        assert_eq!(
            decode(LinkType::Ethernet, &ether(0x88cc, &[])).net,
            Net::Unknown
        );
        let mut tcp = ipv4_udp(&[0; 12]);
        tcp[9] = 6;
        tcp[20 + 12] = 0x40; // data offset under 5 words
        let Net::Ip(ip) = decode(LinkType::Raw, &tcp).net else {
            panic!()
        };
        assert_eq!(ip.transport, Transport::Malformed);
    }

    #[test]
    fn never_panics_on_any_cut() {
        let mut frames = vec![ether(ETHERTYPE_IPV4, &ipv4_udp(b"payload"))];
        let mut tagged = vec![0; 12];
        tagged.extend([0x81, 0, 0, 7, 0x88, 0xa8, 0, 8]);
        tagged.extend(ETHERTYPE_IPV6.to_be_bytes());
        tagged.extend([0x60, 0, 0, 0, 0, 8, 44, 64]);
        tagged.extend([0; 32]);
        tagged.extend([6, 0, 0, 0, 0, 0, 0, 0]);
        frames.push(tagged);
        for frame in &frames {
            for cut in 0..=frame.len() {
                for link in [
                    LinkType::Ethernet,
                    LinkType::LinuxSll,
                    LinkType::LinuxSll2,
                    LinkType::Null,
                    LinkType::Raw,
                ] {
                    decode(link, &frame[..cut]);
                    decode(link, &frame[cut..]);
                }
            }
        }
    }
}
