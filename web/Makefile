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

# The account check's test runs the guard itself (../guard), so the guard's dependencies must be installed.
../guard/node_modules/.package-lock.json: ../guard/package.json ../guard/package-lock.json
	$(MAKE) -C ../guard node_modules/.package-lock.json

test: build ../guard/node_modules/.package-lock.json
	node --disable-warning=ExperimentalWarning --test "test/*.test.mjs"

serve: build
	@echo 'http://127.0.0.1:$(PORT)/'
	python3 -m http.server --bind 127.0.0.1 --directory dist $(PORT)
