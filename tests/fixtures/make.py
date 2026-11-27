"""Writes the test captures in this folder.

Run from the repository root with: uv run --with scapy tests/fixtures/make.py

The packets are built here so the tests know exactly what is in each file.
The TLS ClientHello comes from the local OpenSSL, so its bytes change from
run to run, but the server name and lengths the tests check do not.
"""

import ssl
from decimal import Decimal
from pathlib import Path

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    CookedLinux,
    CookedLinuxV2,
    Dot1Q,
    Ether,
    ICMPv6EchoRequest,
    IPv6,
    Loopback,
    PcapNgWriter,
    PcapWriter,
    Raw,
)

HERE = Path(__file__).parent
START = Decimal("1790000000")
CLIENT_MAC = "02:00:00:00:00:02"
ROUTER_MAC = "02:00:00:00:00:01"


def at(packet, seconds):
    packet.time = START + Decimal(seconds)
    return packet


def eth(payload):
    return Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / payload


def eth_back(payload):
    return Ether(src=ROUTER_MAC, dst=CLIENT_MAC) / payload


def http_flow(t):
    """A whole TCP connection with one retransmitted server segment."""
    c, s = "10.0.0.2", "93.184.216.34"
    cp, sp = 40000, 80
    request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    body1 = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n"
    body2 = b"x" * 20
    ci, si = 1000, 5000
    up = lambda **kw: eth(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, **kw))
    down = lambda **kw: eth_back(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, **kw))
    return [
        at(up(flags="S", seq=ci), t),
        at(down(flags="SA", seq=si, ack=ci + 1), t + Decimal("0.020")),
        at(up(flags="A", seq=ci + 1, ack=si + 1), t + Decimal("0.040")),
        at(up(flags="PA", seq=ci + 1, ack=si + 1) / request, t + Decimal("0.041")),
        at(down(flags="A", seq=si + 1, ack=ci + 1 + len(request)) / body1, t + Decimal("0.060")),
        at(down(flags="A", seq=si + 1, ack=ci + 1 + len(request)) / body1, t + Decimal("0.260")),
        at(down(flags="PA", seq=si + 1 + len(body1), ack=ci + 1 + len(request)) / body2, t + Decimal("0.261")),
        at(up(flags="FA", seq=ci + 1 + len(request), ack=si + 1 + len(body1) + len(body2)), t + Decimal("0.300")),
        at(down(flags="FA", seq=si + 1 + len(body1) + len(body2), ack=ci + 2 + len(request)), t + Decimal("0.320")),
        at(up(flags="A", seq=ci + 2 + len(request), ack=si + 2 + len(body1) + len(body2)), t + Decimal("0.340")),
    ]


def dns_exchange(t, src, dst, sport, query_id, name, qtype, answers=(), rcode=0):
    ip = IPv6 if ":" in src else IP
    question = DNSQR(qname=name, qtype=qtype)
    query = eth(ip(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(id=query_id, rd=1, qd=question))
    reply = DNS(id=query_id, qr=1, rd=1, ra=1, rcode=rcode, qd=question)
    if answers:
        reply.an = answers
    response = eth_back(ip(src=dst, dst=src) / UDP(sport=53, dport=sport) / reply)
    return [at(query, t), at(response, t + Decimal("0.012"))]


def mixed():
    packets = [at(eth(ARP(psrc="10.0.0.2", pdst="10.0.0.1")), 0)]
    packets += dns_exchange(
        Decimal("0.100"), "10.0.0.2", "10.0.0.1", 53000, 0x1234, "www.example.com", "A",
        DNSRR(rrname="www.example.com", type="CNAME", rdata="example.com", ttl=300)
        / DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300),
    )
    packets += http_flow(Decimal("0.200"))
    packets += dns_exchange(
        Decimal("1.000"), "fd00::2", "fd00::1", 53001, 0x5678, "example.com", "AAAA",
        DNSRR(rrname="example.com", type="AAAA", rdata="2606:2800:220:1:248:1893:25c8:1946", ttl=60),
    )
    packets += dns_exchange(
        Decimal("1.100"), "10.0.0.2", "10.0.0.1", 53002, 0x0bad, "nope.invalid", "A", rcode=3,
    )
    packets += [
        at(eth(IP(src="10.0.0.2", dst="1.1.1.1") / ICMP(type=8, id=1, seq=1)), Decimal("1.200")),
        at(eth_back(IP(src="1.1.1.1", dst="10.0.0.2") / ICMP(type=0, id=1, seq=1)), Decimal("1.210")),
        at(eth(IPv6(src="fd00::2", dst="fd00::1") / ICMPv6EchoRequest(id=1, seq=1)), Decimal("1.300")),
        at(
            Ether(src=CLIENT_MAC, dst=ROUTER_MAC)
            / Dot1Q(vlan=7)
            / IP(src="10.0.1.5", dst="10.0.1.6")
            / UDP(sport=1234, dport=5678)
            / Raw(b"v" * 100),
            Decimal("1.400"),
        ),
    ]
    return packets


def client_hello(server_name):
    context = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def tls():
    """A ClientHello split in two segments that arrive out of order, then
    the first half again."""
    c, s, cp = "10.0.0.2", "10.0.0.9", 41000
    hello = client_hello("packet-lens.test")
    half = len(hello) // 2
    up = lambda **kw: eth(IP(src=c, dst=s) / TCP(sport=cp, dport=443, **kw))
    down = lambda **kw: eth_back(IP(src=s, dst=c) / TCP(sport=443, dport=cp, **kw))
    ci, si = 0xFFFFFF00, 7000  # the client's sequence numbers wrap
    first, second = hello[:half], hello[half:]
    return [
        at(up(flags="S", seq=ci), 0),
        at(down(flags="SA", seq=si, ack=ci + 1), Decimal("0.010")),
        at(up(flags="A", seq=ci + 1, ack=si + 1), Decimal("0.020")),
        at(up(flags="PA", seq=(ci + 1 + half) % 2**32, ack=si + 1) / second, Decimal("0.021")),
        at(up(flags="A", seq=ci + 1, ack=si + 1) / first, Decimal("0.022")),
        at(up(flags="A", seq=ci + 1, ack=si + 1) / first, Decimal("0.222")),
        at(down(flags="R", seq=si + 1), Decimal("0.300")),
    ], len(hello), len(first)


def one_query(link, name):
    query = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=5353, dport=53) / DNS(id=1, qd=DNSQR(qname=name))
    return [at(link / query if link is not None else query, 0)]


def write_pcap(name, packets, **options):
    with PcapWriter(str(HERE / name), sync=True, **options) as w:
        for p in packets:
            w.write(p)


def main():
    packets = mixed()
    write_pcap("mixed.pcap", packets, endianness="<")
    write_pcap("mixed-be.pcap", packets, endianness=">")
    write_pcap("mixed-ns.pcap", packets, nano=True)
    with PcapNgWriter(str(HERE / "mixed.pcapng")) as w:
        for p in packets:
            w.write(p)

    packets, hello_len, half = tls()
    write_pcap("tls.pcap", packets)
    print(f"tls.pcap: ClientHello {hello_len} bytes, first half {half}")

    write_pcap("sll.pcap", one_query(CookedLinux(proto=0x0800), "sll.test"))
    write_pcap("sll2.pcap", one_query(CookedLinuxV2(proto=0x0800), "sll2.test"))
    write_pcap("null.pcap", one_query(Loopback(type=2), "null.test"))
    write_pcap("raw.pcap", one_query(None, "raw.test"), linktype=101)


if __name__ == "__main__":
    main()
