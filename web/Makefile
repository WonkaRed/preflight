# `make build` compiles the scanner to WebAssembly and assembles dist/, a self-contained folder any static host can
# serve as is (the wasm is a build output, so it is not committed). `make serve` previews it, `make test` checks it.
# The compiler comes from rust-toolchain.toml; an exported RUSTUP_TOOLCHAIN would silently override it.
unexport RUSTUP_TOOLCHAIN
MAKEFLAGS += --no-print-directory

PORT ?= 8000

.PHONY: build dist test serve

build:
	cargo build --locked --quiet -p preflight-web --profile web --target wasm32-unknown-unknown
	node tools/build.mjs

dist: build

test: build
	node --test "test/*.test.mjs"

serve: build
	@echo 'http://127.0.0.1:$(PORT)/'
	python3 -m http.server --bind 127.0.0.1 --directory dist $(PORT)
