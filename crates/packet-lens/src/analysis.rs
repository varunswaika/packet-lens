//! Turns frames into the report: protocol counts, top talkers, flows and
//! the DNS log.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use serde::Serialize;

use crate::capture::{Format, Frame};
use crate::decode::{self, ACK, FIN, Net, RST, SYN, Transport};
use crate::dns;
use crate::stream::{Stream, StreamStats};
use crate::tls::{self, Hello};

// The report keeps the biggest of each list. The counts say how many
// there were in all.
const MAX_TALKERS: usize = 100;
const MAX_FLOWS: usize = 1000;
const MAX_DNS: usize = 5000;

#[derive(Debug, Serialize)]
pub struct Report {
    pub format: &'static str,
    pub packets: u64,
    /// Bytes on the wire, which can be more than were captured.
    pub bytes: u64,
    pub start_us: Option<u64>,
    pub end_us: Option<u64>,
    /// Why reading stopped before the end of the file, if it did.
    pub error: Option<String>,
    pub protocols: Vec<Protocol>,
    pub talker_count: usize,
    pub talkers: Vec<Talker>,
    pub flow_count: usize,
    pub flows: Vec<FlowSummary>,
    pub dns_count: usize,
    pub dns: Vec<DnsEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Protocol {
    pub layer: &'static str,
    pub name: &'static str,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Talker {
    pub addr: IpAddr,
    pub sent: Traffic,
    pub received: Traffic,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Traffic {
    pub packets: u64,
    pub bytes: u64,
}

impl Traffic {
    fn add(&mut self, bytes: u64) {
        self.packets += 1;
        self.bytes += bytes;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowSummary {
    pub protocol: &'static str,
    pub client: IpAddr,
    pub client_port: u16,
    pub server: IpAddr,
    pub server_port: u16,
    pub start_us: u64,
    pub end_us: u64,
    pub to_server: Traffic,
    pub to_client: Traffic,
    /// "dns" or "tls" when the payload showed it.
    pub app: Option<&'static str>,
    pub sni: Option<String>,
    pub tcp: Option<TcpSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TcpSummary {
    /// The client's SYN is in the capture.
    pub syn: bool,
    /// "fin" or "rst", or none if the capture ends with it open.
    pub end: Option<&'static str>,
    pub to_server: StreamStats,
    pub to_client: StreamStats,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsEntry {
    pub time_us: u64,
    pub client: IpAddr,
    pub server: IpAddr,
    pub id: u16,
    pub name: String,
    pub kind: &'static str,
    /// None until a response is seen.
    pub rcode: Option<&'static str>,
    pub answers: Vec<String>,
    pub latency_us: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    protocol: u8,
    low: (IpAddr, u16),
    high: (IpAddr, u16),
}

impl Key {
    fn new(protocol: u8, a: (IpAddr, u16), b: (IpAddr, u16)) -> Self {
        let (low, high) = if a <= b { (a, b) } else { (b, a) };
        Key {
            protocol,
            low,
            high,
        }
    }
}

struct Flow {
    protocol: &'static str,
    client: (IpAddr, u16),
    server: (IpAddr, u16),
    first_ns: u64,
    last_ns: u64,
    to_server: Traffic,
    to_client: Traffic,
    app: Option<&'static str>,
    sni: Option<String>,
    tcp: Option<TcpState>,
}

struct TcpState {
    syn: bool,
    fin: bool,
    rst: bool,
    to_server: Stream,
    to_client: Stream,
    /// Still looking for a ClientHello at the start of the client's stream.
    looking: bool,
}

/// One packet's place in its flow, as the flow needs it.
struct Seen<'a> {
    protocol: &'static str,
    number: u8,
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
    tcp: Option<&'a decode::Tcp<'a>>,
}

pub struct Analyser {
    format: Format,
    packets: u64,
    bytes: u64,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
    error: Option<String>,
    protocols: BTreeMap<(u8, &'static str), Traffic>,
    talkers: HashMap<IpAddr, Talker>,
    flows: HashMap<Key, Flow>,
    dns: Vec<DnsEntry>,
    dns_count: usize,
    /// Queries waiting for a response: (client, client port, id) to their
    /// place in the log.
    pending: HashMap<(IpAddr, u16, u16), usize>,
}

const LAYERS: [&str; 4] = ["link", "network", "transport", "application"];

impl Analyser {
    pub fn new(format: Format) -> Self {
        Analyser {
            format,
            packets: 0,
            bytes: 0,
            start_ns: None,
            end_ns: None,
            error: None,
            protocols: BTreeMap::new(),
            talkers: HashMap::new(),
            flows: HashMap::new(),
            dns: Vec::new(),
            dns_count: 0,
            pending: HashMap::new(),
        }
    }

    /// Notes that reading stopped early.
    pub fn stopped(&mut self, why: String) {
        self.error = Some(why);
    }

    pub fn add(&mut self, frame: &Frame<'_>) {
        let bytes = u64::from(frame.wire_len);
        let time = frame.time_ns;
        self.packets += 1;
        self.bytes += bytes;
        // Simple packet blocks in pcapng carry no time at all.
        if time != 0 {
            self.start_ns = Some(self.start_ns.map_or(time, |t| t.min(time)));
            self.end_ns = Some(self.end_ns.map_or(time, |t| t.max(time)));
        }

        let packet = decode::decode(frame.link, frame.data);
        self.count(0, packet.link, bytes);
        let ip = match &packet.net {
            Net::Ip(ip) => ip,
            Net::Arp => return self.count(1, "arp", bytes),
            Net::Unknown => return self.count(1, "other", bytes),
            Net::Malformed => return self.count(1, "malformed", bytes),
        };
        self.count(1, if ip.src.is_ipv4() { "ipv4" } else { "ipv6" }, bytes);
        self.talker(ip.src).sent.add(bytes);
        self.talker(ip.dst).received.add(bytes);

        let (protocol, number, ports, tcp, udp_payload) = match &ip.transport {
            Transport::Tcp(t) => ("tcp", 6, (t.src_port, t.dst_port), Some(t), None),
            Transport::Udp(u) => ("udp", 17, (u.src_port, u.dst_port), None, Some(u.payload)),
            Transport::Icmp => ("icmp", 1, (0, 0), None, None),
            Transport::Icmpv6 => ("icmpv6", 58, (0, 0), None, None),
            Transport::Fragment => return self.count(2, "fragment", bytes),
            Transport::Other(_) => return self.count(2, "other", bytes),
            Transport::Malformed => return self.count(2, "malformed", bytes),
        };
        let seen = Seen {
            protocol,
            number,
            src: (ip.src, ports.0),
            dst: (ip.dst, ports.1),
            tcp,
        };
        self.count(2, seen.protocol, bytes);
        let is_dns = match udp_payload {
            Some(payload) if seen.src.1 == 53 || seen.dst.1 == 53 => {
                self.dns_message(time, seen.src, seen.dst, payload)
            }
            _ => false,
        };
        let flow = self.flow(&seen, time);
        if is_dns {
            flow.app = Some("dns");
        }
        flow.add(&seen, time, bytes);
    }

    pub fn finish(mut self) -> Report {
        let mut flows: Vec<FlowSummary> = Vec::with_capacity(self.flows.len());
        for flow in self.flows.into_values() {
            if let Some(app) = flow.app {
                let total = Traffic {
                    packets: flow.to_server.packets + flow.to_client.packets,
                    bytes: flow.to_server.bytes + flow.to_client.bytes,
                };
                let count = self.protocols.entry((3, app)).or_default();
                count.packets += total.packets;
                count.bytes += total.bytes;
            }
            flows.push(flow.summary());
        }
        flows.sort_by(|a, b| {
            let size = |f: &FlowSummary| f.to_server.bytes + f.to_client.bytes;
            size(b).cmp(&size(a)).then(a.start_us.cmp(&b.start_us))
        });
        let flow_count = flows.len();
        flows.truncate(MAX_FLOWS);

        let mut talkers: Vec<Talker> = self.talkers.into_values().collect();
        talkers.sort_by(|a, b| {
            let size = |t: &Talker| t.sent.bytes + t.received.bytes;
            size(b).cmp(&size(a)).then(a.addr.cmp(&b.addr))
        });
        let talker_count = talkers.len();
        talkers.truncate(MAX_TALKERS);

        let protocols = self
            .protocols
            .into_iter()
            .map(|((layer, name), count)| Protocol {
                layer: LAYERS[usize::from(layer)],
                name,
                packets: count.packets,
                bytes: count.bytes,
            })
            .collect();

        Report {
            format: self.format.name(),
            packets: self.packets,
            bytes: self.bytes,
            start_us: self.start_ns.map(|t| t / 1000),
            end_us: self.end_ns.map(|t| t / 1000),
            error: self.error,
            protocols,
            talker_count,
            talkers,
            flow_count,
            flows,
            dns_count: self.dns_count,
            dns: self.dns,
        }
    }

    fn count(&mut self, layer: u8, name: &'static str, bytes: u64) {
        self.protocols.entry((layer, name)).or_default().add(bytes);
    }

    fn talker(&mut self, addr: IpAddr) -> &mut Talker {
        self.talkers.entry(addr).or_insert_with(|| Talker {
            addr,
            sent: Traffic::default(),
            received: Traffic::default(),
        })
    }

    fn flow(&mut self, seen: &Seen<'_>, time: u64) -> &mut Flow {
        let key = Key::new(seen.number, seen.src, seen.dst);
        self.flows
            .entry(key)
            .or_insert_with(|| Flow::new(seen, time))
    }

    /// Adds a DNS query or response to the log. False if the payload is
    /// not DNS.
    fn dns_message(
        &mut self,
        time: u64,
        src: (IpAddr, u16),
        dst: (IpAddr, u16),
        payload: &[u8],
    ) -> bool {
        let Some(message) = dns::parse(payload) else {
            return false;
        };
        let Some(question) = message.questions.first() else {
            return true;
        };
        let answers: Vec<String> = message.answers.iter().map(dns::Answer::describe).collect();
        if message.response {
            let waiting = self.pending.remove(&(dst.0, dst.1, message.id));
            if let Some(entry) = waiting.and_then(|i| self.dns.get_mut(i)) {
                entry.rcode = Some(dns::rcode_name(message.rcode));
                entry.answers = answers;
                entry.latency_us = Some(time.saturating_sub(entry.time_us * 1000) / 1000);
                return true;
            }
        }
        self.dns_count += 1;
        if self.dns.len() == MAX_DNS {
            return true;
        }
        let (client, server) = if message.response {
            (dst, src)
        } else {
            (src, dst)
        };
        if !message.response {
            self.pending
                .insert((client.0, client.1, message.id), self.dns.len());
        }
        self.dns.push(DnsEntry {
            time_us: time / 1000,
            client: client.0,
            server: server.0,
            id: message.id,
            name: question.name.clone(),
            kind: dns::kind_name(question.kind),
            rcode: message.response.then(|| dns::rcode_name(message.rcode)),
            answers,
            latency_us: None,
        });
        true
    }
}

impl Flow {
    fn new(seen: &Seen<'_>, time: u64) -> Self {
        // The first packet usually comes from the client. A SYN-ACK, or a
        // packet from a well-known port to a high one, comes from the server.
        let syn_ack = seen.tcp.is_some_and(|t| t.flags & (SYN | ACK) == SYN | ACK);
        let from_server = syn_ack || (seen.src.1 < 1024 && seen.dst.1 >= 1024);
        let (client, server) = if from_server {
            (seen.dst, seen.src)
        } else {
            (seen.src, seen.dst)
        };
        Flow {
            protocol: seen.protocol,
            client,
            server,
            first_ns: time,
            last_ns: time,
            to_server: Traffic::default(),
            to_client: Traffic::default(),
            app: None,
            sni: None,
            tcp: seen.tcp.map(|_| TcpState {
                syn: false,
                fin: false,
                rst: false,
                to_server: Stream::new(true),
                to_client: Stream::new(false),
                looking: true,
            }),
        }
    }

    fn add(&mut self, seen: &Seen<'_>, time: u64, bytes: u64) {
        self.first_ns = self.first_ns.min(time);
        self.last_ns = self.last_ns.max(time);
        let upstream = seen.src == self.client;
        if upstream {
            self.to_server.add(bytes);
        } else {
            self.to_client.add(bytes);
        }
        let (Some(state), Some(tcp)) = (&mut self.tcp, seen.tcp) else {
            return;
        };
        state.fin |= tcp.flags & FIN != 0;
        state.rst |= tcp.flags & RST != 0;
        let stream = if upstream {
            &mut state.to_server
        } else {
            &mut state.to_client
        };
        if tcp.flags & SYN != 0 {
            stream.syn(tcp.seq);
            state.syn |= upstream && tcp.flags & ACK == 0;
        }
        stream.segment(tcp.seq, tcp.payload);
        if upstream && state.looking && !state.to_server.prefix().is_empty() {
            self.look_for_hello();
        }
    }

    fn look_for_hello(&mut self) {
        let Some(state) = &mut self.tcp else {
            return;
        };
        match tls::client_hello(state.to_server.prefix()) {
            Hello::Partial if !state.to_server.prefix_is_full() => return,
            Hello::Sni(name) => {
                self.app = Some("tls");
                self.sni = Some(name);
            }
            Hello::NoSni => self.app = Some("tls"),
            Hello::Partial | Hello::NotHello => {}
        }
        state.looking = false;
        state.to_server.drop_prefix();
    }

    fn summary(self) -> FlowSummary {
        let tcp = self.tcp.map(|mut s| TcpSummary {
            syn: s.syn,
            end: if s.rst {
                Some("rst")
            } else if s.fin {
                Some("fin")
            } else {
                None
            },
            to_server: s.to_server.finish(),
            to_client: s.to_client.finish(),
        });
        FlowSummary {
            protocol: self.protocol,
            client: self.client.0,
            client_port: self.client.1,
            server: self.server.0,
            server_port: self.server.1,
            start_us: self.first_ns / 1000,
            end_us: self.last_ns / 1000,
            to_server: self.to_server,
            to_client: self.to_client,
            app: self.app,
            sni: self.sni,
            tcp,
        }
    }
}
