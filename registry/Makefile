.PHONY: build test

build:
	cargo build --locked --release --target wasm32-unknown-unknown

# Native unit tests (near-sdk is a `unit-testing` dev-dependency, the only way it compiles for the host) and the
# sandbox tests in tests/sandbox.rs, which build the wasm and run it in a local NEAR node.
test:
	cargo test --locked
