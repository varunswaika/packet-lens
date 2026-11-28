# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-28

### Added

- Reads pcap (either byte order, micro or nanosecond times) and pcapng (several sections and interfaces).
- Links: Ethernet with VLAN and QinQ tags, Linux cooked v1 and v2, BSD loopback and raw IP.
- Decodes IPv4, IPv6 with extension headers, ARP, TCP, UDP, ICMP and ICMPv6.
- TCP reassembly per direction, with resent bytes, early segments and gaps.
- TLS server names from the ClientHello, after reassembly.
- DNS queries matched to replies, with result codes, answers and reply times.
- A cut or damaged file gives what could be read and where it stopped, never a panic.
- The `packet-lens` command: a text report, longer lists with `-n`, or JSON with `--json`.
- Release binaries for Linux, macOS and Windows, installable with `cargo binstall`.

[0.1.0]: https://github.com/varunswaika/packet-lens/releases/tag/v0.1.0
