CARGO_FLAGS ?= -j2
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

.PHONY: build check lint web serve fixtures
