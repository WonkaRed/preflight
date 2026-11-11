# `make test` is the one command a fresh clone needs: it builds the scanner, the fixture contracts and the
# registry, starts a local NEAR sandbox, and checks every exploit. See README.md.

# The compiler comes from rust-toolchain.toml; an exported RUSTUP_TOOLCHAIN would silently override it.
unexport RUSTUP_TOOLCHAIN
MAKEFLAGS += --no-print-directory

PREFLIGHT = cargo run --locked --quiet -p preflight --
WASM = --release --target wasm32-unknown-unknown

.PHONY: build test demo

build:
	cargo build --locked --workspace
	cargo build --locked --manifest-path fixtures/Cargo.toml --workspace $(WASM)
	$(MAKE) -C registry build
	$(MAKE) -C guard build
	$(MAKE) -C web build

test:
	cargo test --locked --workspace
	$(MAKE) -C registry test
	$(MAKE) -C guard test
	$(MAKE) -C web test

# Scan the PF001 fixture pair (vulnerable: exit 1 with a finding; patched: exit 0), then run its exploit.
demo:
	@echo '$$ preflight fixtures/pf001_callback/vulnerable'
	@$(PREFLIGHT) fixtures/pf001_callback/vulnerable; test $$? -eq 1
	@echo
	@echo '$$ preflight fixtures/pf001_callback/patched'
	@$(PREFLIGHT) fixtures/pf001_callback/patched
	@echo
	@echo '$$ cargo test -p exploits --test pf001_callback'
	@cargo test --locked -p exploits --test pf001_callback
