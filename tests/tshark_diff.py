"""Compare packet-lens with tshark on the test captures.

For each capture it compares three things:

- flows: TCP and UDP conversations, as a protocol and an unordered pair of
  address and port;
- TLS server names: the name each conversation's ClientHello asks for;
- DNS answers: each reply's query id, name, result code and its A, AAAA and
  CNAME answers.

Agreement is the share of items both tools report, out of all items either
reports. It prints a Markdown table, and exits with status 1 if anything
differs. tshark runs with out-of-order TCP reassembly on, which is off by
default; without it, tshark misses the TLS name in the two captures whose
ClientHello arrives out of order.

Usage: python3 tests/tshark_diff.py [packet-lens binary] [capture...]
"""

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def tshark(capture, display_filter, fields):
    command = ["tshark", "-n", "-r", str(capture), "-Y", display_filter, "-T", "fields"]
    # tshark leaves segments that arrive early out of its reassembly by default.
    command += ["-o", "tcp.reassemble_out_of_order:TRUE"]
    command += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for field in fields:
        command += ["-e", field]
    out = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    return [line.split("\t") for line in out.splitlines()]


def pair(protocol, a, pa, b, pb):
    return (protocol, frozenset({(a, int(pa)), (b, int(pb))}))


def from_tshark(capture):
    plain = "not icmp and not icmpv6"
    flows, names, dns = set(), set(), set()
    fields = ["ip.src", "ipv6.src", "ip.dst", "ipv6.dst"]
    for protocol in ("tcp", "udp"):
        rows = tshark(
            capture,
            f"{protocol} and {plain}",
            fields + [f"{protocol}.srcport", f"{protocol}.dstport"],
        )
        for s4, s6, d4, d6, sp, dp in rows:
            flows.add(pair(protocol, s4 or s6, sp, d4 or d6, dp))
    rows = tshark(
        capture,
        f"tls.handshake.type == 1 and {plain}",
        fields + ["tcp.srcport", "tcp.dstport", "tls.handshake.extensions_server_name"],
    )
    for s4, s6, d4, d6, sp, dp, name in rows:
        if name:
            names.add((pair("tcp", s4 or s6, sp, d4 or d6, dp), name))
    rows = tshark(
        capture,
        f"dns.flags.response == 1 and {plain}",
        ["dns.id", "dns.qry.name", "dns.flags.rcode", "dns.cname", "dns.a", "dns.aaaa"],
    )
    for qid, name, rcode, cname, a, aaaa in rows:
        answers = frozenset(v for v in f"{cname},{a},{aaaa}".split(",") if v)
        dns.add((int(qid, 0), name.rstrip("."), RCODES.get(int(rcode), rcode), answers))
    return flows, names, dns


def from_lens(binary, capture):
    out = subprocess.run(
        [binary, str(capture), "--json"], check=True, capture_output=True, text=True
    ).stdout
    report = json.loads(out)
    flows, names, dns = set(), set(), set()
    for f in report["flows"]:
        if f["protocol"] not in ("tcp", "udp"):
            continue
        key = pair(
            f["protocol"], f["client"], f["client_port"], f["server"], f["server_port"]
        )
        flows.add(key)
        if f.get("sni"):
            names.add((key, f["sni"]))
    for d in report["dns"]:
        if d.get("rcode") is None:
            continue  # a query with no reply
        answers = set()
        for answer in d.get("answers") or []:
            kind, _, value = answer.rpartition(" ")
            if kind in ("", "CNAME"):
                answers.add(value.rstrip("."))
        dns.add((d["id"], d["name"].rstrip("."), d["rcode"], frozenset(answers)))
    return flows, names, dns


def main():
    args = sys.argv[1:]
    binary = args[0] if args else str(ROOT / "target/release/packet-lens")
    captures = [pathlib.Path(a) for a in args[1:]] or sorted(
        (ROOT / "tests/fixtures").glob("*.pcap*")
    )
    kinds = ("flows", "TLS names", "DNS answers")
    both = dict.fromkeys(kinds, 0)
    either = dict.fromkeys(kinds, 0)
    differences = []
    for capture in captures:
        for kind, ours, theirs in zip(
            kinds, from_lens(binary, capture), from_tshark(capture), strict=True
        ):
            both[kind] += len(ours & theirs)
            either[kind] += len(ours | theirs)
            for item in sorted(map(repr, ours - theirs)):
                differences.append(
                    f"{capture.name}: {kind} only in packet-lens: {item}"
                )
            for item in sorted(map(repr, theirs - ours)):
                differences.append(f"{capture.name}: {kind} only in tshark: {item}")
    print(f"{len(captures)} captures\n")
    print("| Compared | Both | Either | Agreement |")
    print("|---|---|---|---|")
    for kind in kinds:
        share = f"{100 * both[kind] / either[kind]:.1f}%" if either[kind] else "n/a"
        print(f"| {kind} | {both[kind]} | {either[kind]} | {share} |")
    for line in differences:
        print(line)
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
