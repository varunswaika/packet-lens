//! A capture bigger than the report's lists: the lists stop at their caps
//! but the totals keep counting.

use packet_lens::analyse;

const LINKTYPE_RAW: u32 = 101;

fn pcap(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = 0xa1b2_c3d4_u32.to_le_bytes().to_vec();
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    for word in [0, 0, 65535, LINKTYPE_RAW] {
        out.extend(word.to_le_bytes());
    }
    for (i, p) in packets.iter().enumerate() {
        let len = p.len() as u32;
        for word in [1_790_000_000, i as u32, len, len] {
            out.extend(word.to_le_bytes());
        }
        out.extend(p);
    }
    out
}

fn udp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    let total = (20 + 8 + payload.len()) as u16;
    let mut p = vec![0x45, 0];
    p.extend(total.to_be_bytes());
    p.extend([0, 0, 0, 0, 64, 17, 0, 0]);
    p.extend(src);
    p.extend(dst);
    p.extend(sport.to_be_bytes());
    p.extend(dport.to_be_bytes());
    p.extend((8 + payload.len() as u16).to_be_bytes());
    p.extend([0, 0]);
    p.extend(payload);
    p
}

fn dns(id: u16, response: bool) -> Vec<u8> {
    let flags: u16 = if response { 0x8180 } else { 0x0100 };
    let mut m = id.to_be_bytes().to_vec();
    m.extend(flags.to_be_bytes());
    m.extend([0, 1, 0, 0, 0, 0, 0, 0]);
    m.extend(b"\x04host\x04test\x00");
    m.extend([0, 1, 0, 1]);
    m
}

#[test]
fn totals_stay_exact_past_the_caps() {
    const QUERIES: u16 = 5100;
    let server = [10, 0, 0, 1];
    let mut packets = Vec::new();
    for i in 0..QUERIES {
        let [hi, lo] = i.to_be_bytes();
        let client = [10, 1, hi, lo];
        packets.push(udp(client, 40000, server, 53, &dns(i, false)));
        packets.push(udp(server, 53, client, 40000, &dns(i, true)));
    }

    let r = analyse(&pcap(&packets)).unwrap();
    assert_eq!(r.packets, 2 * u64::from(QUERIES));
    assert_eq!(r.dns_count, usize::from(QUERIES));
    assert_eq!(r.dns.len(), 5000);
    assert!(r.dns.iter().all(|d| d.rcode == Some("NOERROR")));
    assert_eq!(r.flow_count, usize::from(QUERIES));
    assert_eq!(r.flows.len(), 1000);
    assert_eq!(r.talker_count, usize::from(QUERIES) + 1);
    assert_eq!(r.talkers.len(), 100);
}
