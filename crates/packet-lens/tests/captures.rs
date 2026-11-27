//! Runs the captures written by tests/fixtures/make.py through the whole
//! analysis and checks the report against what the script put in them.

use std::net::IpAddr;
use std::path::PathBuf;

use packet_lens::analysis::{FlowSummary, Protocol};
use packet_lens::{Report, analyse};

const START_US: u64 = 1_790_000_000_000_000;

fn read(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn report(name: &str) -> Report {
    analyse(&read(name)).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn protocol(r: &Report, name: &str) -> u64 {
    r.protocols
        .iter()
        .filter(|p| p.name == name)
        .map(|p: &Protocol| p.packets)
        .sum()
}

fn flow(r: &Report, port: u16) -> &FlowSummary {
    r.flows.iter().find(|f| f.server_port == port).unwrap()
}

#[test]
fn mixed_traffic() {
    let r = report("mixed.pcap");
    assert_eq!(r.format, "pcap");
    assert_eq!(r.error, None);
    assert_eq!(r.packets, 21);
    assert_eq!(
        (r.start_us, r.end_us),
        (Some(START_US), Some(START_US + 1_400_000))
    );

    let counts = [
        ("ethernet", 21),
        ("arp", 1),
        ("ipv4", 17),
        ("ipv6", 3),
        ("tcp", 10),
        ("udp", 7),
        ("icmp", 2),
        ("icmpv6", 1),
        ("dns", 6),
        ("tls", 0),
    ];
    for (name, packets) in counts {
        assert_eq!(protocol(&r, name), packets, "{name}");
    }

    assert_eq!(r.talkers[0].addr, ip("10.0.0.2"));
    assert_eq!(r.talker_count, 8);
    assert_eq!(r.flow_count, 7);
}

#[test]
fn tcp_connection_with_a_resend() {
    let r = report("mixed.pcap");
    let http = flow(&r, 80);
    assert_eq!(&r.flows[0], http, "the biggest flow comes first");
    assert_eq!((http.client, http.client_port), (ip("10.0.0.2"), 40000));
    assert_eq!(http.server, ip("93.184.216.34"));
    assert_eq!((http.to_server.packets, http.to_client.packets), (5, 5));
    assert_eq!(http.end_us - http.start_us, 340_000);
    let tcp = http.tcp.as_ref().unwrap();
    assert!(tcp.syn);
    assert_eq!(tcp.end, Some("fin"));
    assert_eq!(tcp.to_server.bytes, 37);
    assert_eq!(tcp.to_client.bytes, 59);
    assert_eq!(tcp.to_client.retransmitted, 39);
    assert_eq!(tcp.to_client.out_of_order + tcp.to_client.missing, 0);
}

#[test]
fn dns_log() {
    let r = report("mixed.pcap");
    let log: Vec<_> = r
        .dns
        .iter()
        .map(|d| {
            (
                d.name.as_str(),
                d.kind,
                d.rcode,
                d.answers.join(", "),
                d.latency_us,
            )
        })
        .collect();
    assert_eq!(
        log,
        [
            (
                "www.example.com",
                "A",
                Some("NOERROR"),
                "CNAME example.com, 93.184.216.34".to_string(),
                Some(12_000)
            ),
            (
                "example.com",
                "AAAA",
                Some("NOERROR"),
                "2606:2800:220:1:248:1893:25c8:1946".to_string(),
                Some(12_000)
            ),
            (
                "nope.invalid",
                "A",
                Some("NXDOMAIN"),
                String::new(),
                Some(12_000)
            ),
        ]
    );
    assert_eq!(r.dns[1].client, ip("fd00::2"));
    assert_eq!(r.dns[0].time_us, START_US + 100_000);
}

#[test]
fn every_file_format_gives_the_same_report() {
    let pcap = report("mixed.pcap");
    for name in ["mixed-be.pcap", "mixed-ns.pcap", "mixed.pcapng"] {
        let mut other = report(name);
        other.format = pcap.format;
        assert_eq!(other, pcap, "{name}");
    }
    assert_eq!(report("mixed.pcapng").format, "pcapng");
}

#[test]
fn tls_server_name_from_reordered_segments() {
    let r = report("tls.pcap");
    let f = flow(&r, 443);
    assert_eq!(f.app, Some("tls"));
    assert_eq!(f.sni.as_deref(), Some("packet-lens.test"));
    let tcp = f.tcp.as_ref().unwrap();
    assert_eq!(tcp.end, Some("rst"));
    // The script sends the second half, then the first, then the first again.
    let hello = tcp.to_server;
    assert!(hello.bytes > 200);
    assert_eq!(hello.retransmitted, hello.bytes / 2);
    assert_eq!((hello.out_of_order, hello.missing), (1, 0));
    assert_eq!(protocol(&r, "tls"), 7);
}

#[test]
fn other_link_types() {
    for (file, link) in [
        ("sll.pcap", "linux-sll"),
        ("sll2.pcap", "linux-sll2"),
        ("null.pcap", "loopback"),
        ("raw.pcap", "raw-ip"),
    ] {
        let r = report(file);
        assert_eq!(protocol(&r, link), 1, "{file}");
        let name = file.replace(".pcap", ".test");
        assert_eq!(r.dns[0].name, name, "{file}");
        assert_eq!(r.dns[0].rcode, None, "{file}: no response was sent");
    }
}

#[test]
fn cut_files_report_what_came_before() {
    let bytes = read("mixed.pcap");
    let r = analyse(&bytes[..bytes.len() - 10]).unwrap();
    assert_eq!(r.packets, 20);
    assert!(r.error.unwrap().contains("ends inside"));
    assert!(analyse(b"not a capture").is_err());
}

#[test]
fn never_panics_on_cut_or_damaged_files() {
    for name in ["mixed.pcap", "mixed.pcapng", "tls.pcap", "sll2.pcap"] {
        let bytes = read(name);
        for cut in 0..bytes.len() {
            let _ = analyse(&bytes[..cut]);
        }
        let mut damaged = bytes.clone();
        for i in 0..bytes.len() {
            for value in [0x00, 0xff] {
                damaged[i] = value;
                let _ = analyse(&damaged);
            }
            damaged[i] = bytes[i];
        }
    }
}
