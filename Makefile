CARGO_FLAGS ?= -j2
RUFF ?= uvx ruff
WASM := target/wasm32-unknown-unknown/release/packet_lens_wasm.wasm

build:
	cargo build $(CARGO_FLAGS) --release -p packet-lens-cli

check: web
	cargo test $(CARGO_FLAGS)
	node --test tests/web.test.mjs

lint:
	cargo fmt --all --check
	cargo clippy $(CARGO_FLAGS) --all-targets -- -D warnings
	npx -y @biomejs/biome@2 check
	$(RUFF) check tests/fixtures
	$(RUFF) format --check tests/fixtures

# Builds the WebAssembly module into web/ with a sample capture beside it.
web:
	cargo build $(CARGO_FLAGS) --release --target wasm32-unknown-unknown -p packet-lens-wasm
	cp $(WASM) web/packet_lens.wasm
	cp tests/fixtures/sample.pcap web/sample.pcap

serve: web
	python3 -m http.server -d web 8000

# Needs uv. Rewrites the captures in tests/fixtures.
fixtures:
	uv run --no-project --with scapy tests/fixtures/make.py

# Times startup and throughput with hyperfine. The big capture repeats the
# test captures with new ports, so each copy is new flows.
BIN := target/release/packet-lens
bench: build
	python3 bench/big.py tests/fixtures/mixed.pcap target/bench.pcap 100
	hyperfine -N --warmup 20 --export-markdown target/bench-start.md "$(BIN) --version" "$(BIN) tests/fixtures/sample.pcap"
	hyperfine -N --warmup 2 --export-markdown target/bench-big.md "$(BIN) target/bench.pcap"
	cat target/bench-start.md target/bench-big.md > target/bench.md

.PHONY: build check lint web serve fixtures bench
