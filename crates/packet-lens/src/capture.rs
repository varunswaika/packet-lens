//! Reads frames out of pcap and pcapng files.
//!
//! Both formats are read straight from a byte slice with no copying. A file
//! that ends part way through a record gives the frames before it and then
//! one error, so a capture cut off by a full disk still reads.

use std::fmt;

use crate::bytes::Order;

/// What the first header in a frame is, from the file's link-layer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// BSD loopback: a 4-byte address family in the writer's byte order.
    Null,
    Ethernet,
    /// An IP packet with no link header.
    Raw,
    LinuxSll,
    LinuxSll2,
    Other(u32),
}

impl From<u32> for LinkType {
    fn from(value: u32) -> Self {
        match value {
            0 => LinkType::Null,
            1 => LinkType::Ethernet,
            101 | 228 | 229 => LinkType::Raw,
            113 => LinkType::LinuxSll,
            276 => LinkType::LinuxSll2,
            other => LinkType::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Nanoseconds since the Unix epoch.
    pub time_ns: u64,
    pub link: LinkType,
    /// The bytes captured, which may be fewer than were on the wire.
    pub data: &'a [u8],
    /// The length on the wire.
    pub wire_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotACapture,
    /// The file ends inside the record or block starting at this offset.
    Truncated(usize),
    /// The block at this offset has lengths that do not add up.
    BadBlock(usize),
    /// A packet at this offset names an interface the file never described.
    NoInterface(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotACapture => write!(f, "not a pcap or pcapng file"),
            Error::Truncated(at) => write!(f, "file ends inside the record at byte {at}"),
            Error::BadBlock(at) => write!(f, "malformed block at byte {at}"),
            Error::NoInterface(at) => write!(f, "packet at byte {at} names an unknown interface"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pcap,
    Pcapng,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Pcap => "pcap",
            Format::Pcapng => "pcapng",
        }
    }
}

pub struct Capture<'a> {
    bytes: &'a [u8],
    pos: usize,
    done: bool,
    kind: Kind,
}

enum Kind {
    Pcap {
        order: Order,
        nanos: bool,
        link: LinkType,
    },
    Pcapng {
        order: Order,
        interfaces: Vec<Interface>,
    },
}

#[derive(Clone, Copy)]
struct Interface {
    link: LinkType,
    resolution: Resolution,
}

/// Timestamp units: 10^-n or 2^-n seconds.
#[derive(Clone, Copy)]
enum Resolution {
    Decimal(u8),
    Binary(u8),
}

impl Resolution {
    fn to_ns(self, ticks: u64) -> u64 {
        match self {
            Resolution::Decimal(n) if n <= 9 => ticks.saturating_mul(10u64.pow(9 - u32::from(n))),
            Resolution::Decimal(n) => 10u64.checked_pow(u32::from(n) - 9).map_or(0, |d| ticks / d),
            Resolution::Binary(n) => {
                let ns = (u128::from(ticks) * 1_000_000_000) >> n.min(127);
                u64::try_from(ns).unwrap_or(u64::MAX)
            }
        }
    }
}

const PCAPNG_SECTION: u32 = 0x0A0D_0D0A;
const PCAPNG_MAGIC: u32 = 0x1A2B_3C4D;

pub fn open(bytes: &[u8]) -> Result<Capture<'_>, Error> {
    let magic = crate::bytes::array::<4>(bytes, 0).ok_or(Error::NotACapture)?;
    let kind = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => pcap_kind(bytes, Order::Little, false)?,
        [0x4d, 0x3c, 0xb2, 0xa1] => pcap_kind(bytes, Order::Little, true)?,
        [0xa1, 0xb2, 0xc3, 0xd4] => pcap_kind(bytes, Order::Big, false)?,
        [0xa1, 0xb2, 0x3c, 0x4d] => pcap_kind(bytes, Order::Big, true)?,
        [0x0a, 0x0d, 0x0d, 0x0a] => Kind::Pcapng {
            order: section_order(bytes, 0).ok_or(Error::NotACapture)?,
            interfaces: Vec::new(),
        },
        _ => return Err(Error::NotACapture),
    };
    let pos = match kind {
        Kind::Pcap { .. } => 24,
        Kind::Pcapng { .. } => 0,
    };
    Ok(Capture {
        bytes,
        pos,
        done: false,
        kind,
    })
}

fn pcap_kind(bytes: &[u8], order: Order, nanos: bool) -> Result<Kind, Error> {
    let network = order.u32(bytes, 20).ok_or(Error::Truncated(0))?;
    // The top bits can carry FCS details; the link type is the low 16.
    let link = LinkType::from(network & 0xffff);
    Ok(Kind::Pcap { order, nanos, link })
}

fn section_order(bytes: &[u8], at: usize) -> Option<Order> {
    let magic = crate::bytes::array::<4>(bytes, at + 8)?;
    if u32::from_le_bytes(magic) == PCAPNG_MAGIC {
        Some(Order::Little)
    } else if u32::from_be_bytes(magic) == PCAPNG_MAGIC {
        Some(Order::Big)
    } else {
        None
    }
}

impl Capture<'_> {
    pub fn format(&self) -> Format {
        match self.kind {
            Kind::Pcap { .. } => Format::Pcap,
            Kind::Pcapng { .. } => Format::Pcapng,
        }
    }
}

impl<'a> Iterator for Capture<'a> {
    type Item = Result<Frame<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let item = match self.kind {
            Kind::Pcap { .. } => self.next_pcap(),
            Kind::Pcapng { .. } => self.next_pcapng(),
        };
        if !matches!(item, Some(Ok(_))) {
            self.done = true;
        }
        item
    }
}

impl<'a> Capture<'a> {
    fn next_pcap(&mut self) -> Option<Result<Frame<'a>, Error>> {
        let Kind::Pcap { order, nanos, link } = self.kind else {
            unreachable!()
        };
        let at = self.pos;
        if at == self.bytes.len() {
            return None;
        }
        let header = |off| order.u32(self.bytes, at + off);
        let (Some(secs), Some(frac), Some(caught), Some(wire_len)) =
            (header(0), header(4), header(8), header(12))
        else {
            return Some(Err(Error::Truncated(at)));
        };
        let start = at + 16;
        let end = start.checked_add(caught as usize);
        let Some(data) = end.and_then(|end| self.bytes.get(start..end)) else {
            return Some(Err(Error::Truncated(at)));
        };
        self.pos = start + data.len();
        let frac_ns = if nanos {
            frac
        } else {
            frac.saturating_mul(1000)
        };
        Some(Ok(Frame {
            time_ns: u64::from(secs) * 1_000_000_000 + u64::from(frac_ns),
            link,
            data,
            wire_len,
        }))
    }

    fn next_pcapng(&mut self) -> Option<Result<Frame<'a>, Error>> {
        loop {
            let at = self.pos;
            if at == self.bytes.len() {
                return None;
            }
            let block_type = crate::bytes::array::<4>(self.bytes, at);
            if block_type.map(u32::from_le_bytes) == Some(PCAPNG_SECTION) {
                // A new section can switch byte order and starts a fresh
                // list of interfaces.
                let Some(order) = section_order(self.bytes, at) else {
                    return Some(Err(Error::BadBlock(at)));
                };
                self.kind = Kind::Pcapng {
                    order,
                    interfaces: Vec::new(),
                };
            }
            let Kind::Pcapng { order, .. } = self.kind else {
                unreachable!()
            };
            let (Some(kind), Some(len)) =
                (order.u32(self.bytes, at), order.u32(self.bytes, at + 4))
            else {
                return Some(Err(Error::Truncated(at)));
            };
            let len = len as usize;
            if len < 12 || !len.is_multiple_of(4) {
                return Some(Err(Error::BadBlock(at)));
            }
            let Some(block) = at.checked_add(len).and_then(|end| self.bytes.get(at..end)) else {
                return Some(Err(Error::Truncated(at)));
            };
            self.pos = at + len;
            match self.block(at, order, kind, block) {
                Ok(Some(frame)) => return Some(Ok(frame)),
                Ok(None) => continue,
                Err(e) => return Some(Err(e)),
            }
        }
    }

    /// Reads one pcapng block. Returns a frame for packet blocks and
    /// nothing for the rest.
    fn block(
        &mut self,
        at: usize,
        order: Order,
        kind: u32,
        block: &'a [u8],
    ) -> Result<Option<Frame<'a>>, Error> {
        let Kind::Pcapng { interfaces, .. } = &mut self.kind else {
            unreachable!()
        };
        let bad = Error::BadBlock(at);
        let body_end = block.len() - 4;
        match kind {
            // Interface description.
            1 => {
                let link = order.u16(block, 8).ok_or(bad)?;
                let options = block.get(16..body_end).unwrap_or_default();
                interfaces.push(Interface {
                    link: LinkType::from(u32::from(link)),
                    resolution: resolution(options, order),
                });
                Ok(None)
            }
            // Enhanced packet, and the obsolete packet block it replaced.
            2 | 6 => {
                let id = if kind == 6 {
                    order.u32(block, 8).ok_or(bad)?
                } else {
                    u32::from(order.u16(block, 8).ok_or(bad)?)
                };
                let iface = *interfaces.get(id as usize).ok_or(Error::NoInterface(at))?;
                let field = |off| order.u32(block, off).ok_or(bad);
                let ticks = (u64::from(field(12)?) << 32) | u64::from(field(16)?);
                let caught = field(20)? as usize;
                let wire_len = field(24)?;
                let end = 28usize.checked_add(caught).filter(|&end| end <= body_end);
                Ok(Some(Frame {
                    time_ns: iface.resolution.to_ns(ticks),
                    link: iface.link,
                    data: &block[28..end.ok_or(bad)?],
                    wire_len,
                }))
            }
            // Simple packet: no timestamp, always interface 0, and the
            // captured length is whatever fits in the block.
            3 => {
                let iface = *interfaces.first().ok_or(Error::NoInterface(at))?;
                let wire_len = order.u32(block, 8).ok_or(bad)?;
                let room = body_end.checked_sub(12).ok_or(bad)?;
                let caught = room.min(wire_len as usize);
                Ok(Some(Frame {
                    time_ns: 0,
                    link: iface.link,
                    data: &block[12..12 + caught],
                    wire_len,
                }))
            }
            _ => Ok(None),
        }
    }
}

/// Finds `if_tsresol` in an interface's options. Microseconds by default.
fn resolution(mut options: &[u8], order: Order) -> Resolution {
    while let (Some(code), Some(len)) = (order.u16(options, 0), order.u16(options, 2)) {
        let len = usize::from(len);
        if code == 0 {
            break;
        }
        if let (9, 1, Some(&value)) = (code, len, options.get(4)) {
            return if value & 0x80 == 0 {
                Resolution::Decimal(value)
            } else {
                Resolution::Binary(value & 0x7f)
            };
        }
        let Some(rest) = options.get(4 + len.next_multiple_of(4)..) else {
            break;
        };
        options = rest;
    }
    Resolution::Decimal(6)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcapng_block(kind: u32, body: &[u8]) -> Vec<u8> {
        let len = (12 + body.len().next_multiple_of(4)) as u32;
        let mut b = Vec::new();
        b.extend(kind.to_le_bytes());
        b.extend(len.to_le_bytes());
        b.extend(body);
        b.resize(len as usize - 4, 0);
        b.extend(len.to_le_bytes());
        b
    }

    fn section() -> Vec<u8> {
        let mut body = PCAPNG_MAGIC.to_le_bytes().to_vec();
        body.extend([1, 0, 0, 0]);
        body.extend(u64::MAX.to_le_bytes());
        pcapng_block(PCAPNG_SECTION, &body)
    }

    fn interface(link: u16, tsresol: Option<u8>) -> Vec<u8> {
        let mut body = link.to_le_bytes().to_vec();
        body.extend([0, 0]);
        body.extend(65535u32.to_le_bytes());
        if let Some(r) = tsresol {
            body.extend([9, 0, 1, 0, r, 0, 0, 0]);
            body.extend([0, 0, 0, 0]);
        }
        pcapng_block(1, &body)
    }

    fn enhanced(iface: u32, ticks: u64, data: &[u8]) -> Vec<u8> {
        let mut body = iface.to_le_bytes().to_vec();
        body.extend(((ticks >> 32) as u32).to_le_bytes());
        body.extend((ticks as u32).to_le_bytes());
        body.extend((data.len() as u32).to_le_bytes());
        body.extend((data.len() as u32 + 10).to_le_bytes());
        body.extend(data);
        pcapng_block(6, &body)
    }

    #[test]
    fn rejects_other_files() {
        assert!(matches!(
            open(b"PK\x03\x04 a zip file"),
            Err(Error::NotACapture)
        ));
        assert!(matches!(open(b""), Err(Error::NotACapture)));
    }

    #[test]
    fn pcapng_resolution_options() {
        let mut file = section();
        file.extend(interface(1, None));
        file.extend(interface(101, Some(9)));
        file.extend(interface(1, Some(0x80 | 10)));
        file.extend(enhanced(0, 1_500_000, b"abc"));
        file.extend(enhanced(1, 1_500_000_000, b"de"));
        file.extend(enhanced(2, 3 * 1024, b"f"));
        let frames: Vec<_> = open(&file).unwrap().map(Result::unwrap).collect();
        let times: Vec<_> = frames.iter().map(|f| f.time_ns).collect();
        assert_eq!(times, [1_500_000_000, 1_500_000_000, 3_000_000_000]);
        assert_eq!(frames[1].link, LinkType::Raw);
        assert_eq!(frames[0].data, b"abc");
        assert_eq!(frames[0].wire_len, 13);
    }

    #[test]
    fn pcapng_simple_packet_and_unknown_blocks() {
        let mut file = section();
        file.extend(interface(1, None));
        file.extend(pcapng_block(0x0BAD, b"skip me"));
        let mut body = 5u32.to_le_bytes().to_vec();
        body.extend(b"hello");
        file.extend(pcapng_block(3, &body));
        let frames: Vec<_> = open(&file).unwrap().map(Result::unwrap).collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, b"hello");
    }

    #[test]
    fn pcapng_packet_before_its_interface() {
        let mut file = section();
        file.extend(enhanced(0, 0, b"x"));
        let mut capture = open(&file).unwrap();
        assert!(matches!(capture.next(), Some(Err(Error::NoInterface(_)))));
        assert!(capture.next().is_none());
    }

    #[test]
    fn pcapng_bad_lengths() {
        let mut file = section();
        file.extend(interface(1, None));
        let mut packet = enhanced(0, 0, b"abcd");
        packet[20] = 200; // captured length runs past the block
        file.extend(packet);
        let mut capture = open(&file).unwrap();
        assert!(matches!(capture.next(), Some(Err(Error::BadBlock(_)))));
    }

    #[test]
    fn resolution_extremes() {
        assert_eq!(Resolution::Decimal(12).to_ns(5_000), 5);
        assert_eq!(Resolution::Decimal(40).to_ns(u64::MAX), 0);
        assert_eq!(Resolution::Decimal(0).to_ns(u64::MAX), u64::MAX);
        assert_eq!(Resolution::Binary(127).to_ns(u64::MAX), 0);
        assert_eq!(Resolution::Binary(0).to_ns(u64::MAX), u64::MAX);
    }
}
