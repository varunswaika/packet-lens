<p align="center"><img src="docs/banner.png" alt="Pixel art: a magnifying glass over packets on a wire shows their layers, beside a chart of top talkers" width="100%"></p>

# packet-lens

Reads a pcap or pcapng capture and sums up what is in it: protocols, top talkers, flows with TCP reassembly, TLS server names and DNS. One small Rust binary, with no Wireshark or libpcap. The same code runs in [a web page](https://varunswaika.github.io/packet-lens/) where the file never leaves the browser.

## Install

```sh
cargo binstall packet-lens-cli   # a release binary for Linux, macOS or Windows
cargo install packet-lens-cli    # or build it
```

Binaries are also on the [releases page](https://github.com/varunswaika/packet-lens/releases). The library is the `packet-lens` crate.

## Use

```sh
packet-lens capture.pcapng          # text report
packet-lens capture.pcapng -n 25    # longer lists
packet-lens capture.pcapng --json   # the full report
```

A cut or damaged file gives what could be read and where it stopped.

## Speed

hyperfine on a GitHub ubuntu-24.04 runner, 28 November 2026 (`make bench`, or the Bench workflow):

| Run | Mean |
|---|---|
| `packet-lens --version` (start-up) | 0.48 ms |
| a 2 kB capture | 0.57 ms |
| a 100 MB capture, about 1.1 million packets | 453 ms (220 MB/s) |

The 100 MB capture repeats the test captures with new ports, so each copy is new flows.

## Build and test

```sh
make build    # target/release/packet-lens
make check    # Rust tests, then the wasm module in node
make lint     # rustfmt, clippy, Biome and ruff
```

CI also compares the report with tshark on the test captures. Releases: [CHANGELOG.md](CHANGELOG.md). Status: [STATUS.md](STATUS.md). MIT licence.
