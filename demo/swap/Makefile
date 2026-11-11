# The Swap. `make build` makes the three wasm files that are deployed (wasm/ and wasm/SHA256SUMS), `make reports`
# runs the scanner over the two chameleon sources, `make test` runs the sandbox tests. See README.md.

# The compiler comes from rust-toolchain.toml; an exported RUSTUP_TOOLCHAIN would silently override it.
unexport RUSTUP_TOOLCHAIN
MAKEFLAGS += --no-print-directory

ROOT := $(abspath ../..)
CARGO_HOME_DIR := $(or $(CARGO_HOME),$(HOME)/.cargo)
# The same two flags ../../.cargo/config.toml sets for wasm (`--cfg near`, strip symbols), plus path remapping: a panic
# message embeds the path of the source file, so without it the wasm, and its hash, would depend on where the
# checkout and the cargo registry sit on the machine that builds it. RUSTFLAGS replaces the config's flags, it does not add to them.
WASM_FLAGS := --cfg near -C link-arg=-s --remap-path-prefix=$(ROOT)=/preflight --remap-path-prefix=$(CARGO_HOME_DIR)=/cargo
CONTRACTS := chameleon_vulnerable chameleon_patched swap_switch
# Its own target dir, so the remapped build never rebuilds what the other workspaces share.
TARGET := $(abspath target)

.PHONY: build reports test check

build:
	RUSTFLAGS='$(WASM_FLAGS)' CARGO_TARGET_DIR='$(TARGET)' cargo build --locked --release --target wasm32-unknown-unknown -p chameleon-vulnerable -p chameleon-patched -p swap-switch
	mkdir -p wasm
	for name in $(CONTRACTS); do cp '$(TARGET)/wasm32-unknown-unknown/release/'$$name.wasm wasm/; done
	cd wasm && sha256sum $(addsuffix .wasm,$(CONTRACTS)) > SHA256SUMS

# The scanner's report for each build, the files the registry's verdicts point at (report_sha256 is the hash of the file).
# The scanner exits 1 when it finds something: the vulnerable build must, the patched one must not.
reports:
	mkdir -p reports
	cd '$(ROOT)' && cargo run --locked --quiet -p preflight -- --json demo/swap/chameleon/vulnerable > demo/swap/reports/chameleon-vulnerable.json; test $$? -eq 1
	cd '$(ROOT)' && cargo run --locked --quiet -p preflight -- --json demo/swap/chameleon/patched > demo/swap/reports/chameleon-patched.json

test:
	cargo test --locked

check:
	./check.sh
