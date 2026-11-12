# Getting started

Everything the README's top section leaves out: what to install, the long outputs, scanning your own contract and the deployed-contract check.

## Requirements

- Linux on x86-64 with glibc 2.39 or newer (for example Ubuntu 24.04 or Debian 13). The NEAR sandbox binary the exploit tests use needs it; no other platform was tried.
- [rustup](https://rustup.rs), `make` and a C compiler. `rust-toolchain.toml` pins Rust 1.95.0 and the `wasm32-unknown-unknown` target; rustup installs both on first use.
- Node.js 22.22.2 or newer with npm (the guard's dependencies are installed from its lockfile). `make -C web serve` also needs `python3`.
- Network access on the first run: crates, the NEAR sandbox binary, npm packages.
- `make test` took 389 s (6.5 minutes) on a fresh clone for a reviewer whose cargo registry was already warm. With nothing cached it also downloads the crates, the NEAR sandbox binary and the npm packages: an earlier estimate for that case is 15 to 25 minutes, not re-measured. Linking needs several GB of free RAM.
- Docker is optional: `docker build -t preflight .` runs `make test` in a Debian 13 image, with no Rust or Node on the host.

## Check the testnet deployment with no key

The registry and the guard run on NEAR testnet. This reads the chain, read-only, and checks that the guard decides as recorded:

```sh
git clone https://github.com/WonkaRed/preflight.git && cd preflight
make -C guard testnet-verify
```

It needs `make`, Node.js 22.22.2 or newer with npm, and network access: `npm ci` installs 86 packages from the guard's lockfile, then the script makes read-only RPC calls to `https://test.rpc.fastnear.com`. No Rust. It took 7 seconds from a copy with no `node_modules` and an empty npm cache. It ends:

```
What the guard decides about each shop now (the expected decision, the one the guard gave, then its first reason):
OK  shop-vulnerable.preflight-guard.testnet: expected block, got block (registry verdict Unsafe (PF001): published by auditor.preflight-guard.testnet, report https://github.com/WonkaRed/preflight/blob/main/docs/testnet-reports/shop-vulnerable.json)
OK  shop-patched.preflight-guard.testnet: expected allow, got allow (registry verdict Safe: published by auditor.preflight-guard.testnet, report https://github.com/WonkaRed/preflight/blob/main/docs/testnet-reports/shop-patched.json)
OK  shop-swapped.preflight-guard.testnet: expected warn, got warn (code hash 7uZs6XN2c9HsGHDPco6tHt28SEjkr5V23UKu8EHs2xSX has no verdict in the registry: unaudited code, or code changed since its audit)
All checks passed.
```

The guard's policy is to never transact with code that carries an Unsafe verdict. On `shop-vulnerable` (PF001), anyone can mark an order released without paying it, which freezes the funds escrowed there.

## Quick start

```sh
git clone https://github.com/WonkaRed/preflight.git
cd preflight
make test
make demo
```

`make test` builds the scanner, the fixture contracts and the registry, starts a local NEAR sandbox, runs every exploit test, then typechecks and tests the guard (against a fake NEAR RPC node) and tests the web page. It exits 0 when all pass.

`make demo` scans the PF001 fixture pair and runs its exploit test (cargo's compile output is elided below):

```
$ preflight fixtures/pf001_callback/vulnerable
fixtures/pf001_callback/vulnerable/src/lib.rs:60:12: PF001 [high] Callback not marked #[private]
    `Escrow::on_release` is scheduled on the contract itself with `ext(..)` but is not marked `#[private]`, so any account can call it directly
    fix: add #[private] to the callback so only the contract itself can call it
1 finding in 1 file scanned (1 high)

$ preflight fixtures/pf001_callback/patched
No findings (1 file scanned)

$ cargo test -p exploits --test pf001_callback
...
running 2 tests
test vulnerable_escrow_lets_an_outsider_settle_an_order_that_was_never_paid ... ok
test patched_escrow_rejects_the_outsider_and_still_settles_a_real_release ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 21.98s
```
## Scan your own contract

```sh
cargo run -p preflight -- path/to/your/contract         # a directory or one .rs file
cargo run -p preflight -- --json path/to/your/contract  # machine-readable report
```

Exit status: 0 no findings, 1 findings, 2 the scan could not run. The text and JSON layouts are in [SPEC.md](../SPEC.md).
## Check a deployed contract

When there is no source to scan, `preflight account` reads a contract that is already on chain, by account id. Here it reads one of this project's own testnet contracts (see [guard-and-key.md](guard-and-key.md)):

```sh
cargo run -p preflight -- account shop-vulnerable.preflight-guard.testnet --rpc https://test.rpc.fastnear.com
```

```
shop-vulnerable.preflight-guard.testnet at block 277167263 (https://test.rpc.fastnear.com, read-only)
  code 8pqFHzB4UP7wR25AD7cSgyXGimPbEFBSKuKCc9ZRh8wT: 137901 bytes, 6 exported functions
  balance 2.0488 NEAR (0.0000 NEAR locked), storage 138265 bytes

PFW01 [medium] Access keys that can change the contract
    shop-vulnerable.preflight-guard.testnet
    this account has 1 full-access key: ed25519:4DJPwDebCLivBDDajxrLWrDd1c2K1d2YptSFUvGxeCGS. Whoever holds one can replace the contract's code, delete the account, or add more keys
    read: RPC query view_access_key_list for the account (every page), at the block shown in the report
    limits: It shows that a key exists, not who holds it or how it is guarded: a multisig, a DAO or a timelock may sit behind it. A contract can be upgradable through such a key or through its own methods (see PFW02), and it reads no code.
    fix: If the contract must not change, delete the full-access keys so the account holds no key that can deploy code; if it must, say who holds the key and keep it in a multisig or governance contract

PFW03 [info] NEP-330 source metadata
    shop-vulnerable.preflight-guard.testnet
    the contract declares version 0.1.0 and link (none). This is self-declared and was not verified against the code hash
    read: RPC query view_code (is contract_source_metadata exported) and, if so, RPC query call_function contract_source_metadata, a read-only view call that changes no state
    limits: The metadata is written by the contract itself and Preflight does not check it against the deployed code: it can be stale or wrong. Its absence does not mean the contract is unsafe, only that this account's code cannot be tied to published source from chain data alone.
    fix: Build with cargo-near so the contract exports NEP-330 metadata with the version and a link to the exact source commit

2 findings (1 medium, 1 info)
```

The block height, and the balance if the account is used, will differ. The exit status here is 1 (a finding of severity low or above; `info` findings are printed but do not count).

It is read-only: only public JSON-RPC views, all pinned to one block shown in the report. It holds no key, signs nothing and sends no transaction. Six checks, PFW01 to PFW06 (access keys, upgrade-style exports, NEP-330 metadata, an uninitialized contract, the storage balance floor, the shape of a NEP-141 token), each say what was read and what it does not prove. The exact reads, `--json`, the default endpoint and the exit statuses are in [check-a-deployed-contract.md](check-a-deployed-contract.md).

It was run once over 142 mainnet contracts (tokens, NFT contracts, DAOs and staking pools from public listings): no crash, no read error, 32 (22.5 percent) hold a full-access key, 95 (66.9 percent) export no source metadata. Counts only, no account is named: [mainnet-sweep.md](mainnet-sweep.md).

## The web page

`web/` is a static page. At the top is the Swap; below it the scanner runs where you are: no server, no account. Paste Rust contract source, pick a bundled vulnerable example (and its patched twin), or enter a public GitHub repository (`owner/repo`, optionally a ref and a sub-path). Each finding names its rule's fixture pair and sandbox exploit test (each a link to that path in this repository on GitHub).

```sh
make -C web serve   # build, then serve it at http://127.0.0.1:8000/
```

`make -C web build` assembles `web/dist/` (the whole site, any static host will do) and `make -C web test` runs the page's tests against the real wasm. Browsers will not load WebAssembly from `file://`, so open it through `serve`. The page runs the same rules as the command line and its output matches `--json` byte for byte, apart from limits (deeply nested code, a single pasted file, no sandbox exploits, no `preflight account` check of a deployed contract (the page's account check only reads its code hash, its full-access keys and the registry's verdict), GitHub's rate limit) listed in [web-page-limits.md](web-page-limits.md). The headline is a count of pattern matches by severity, never a verdict. More in [web/README.md](../web/README.md).

## Built on

[near-sdk](https://github.com/near/near-sdk-rs) 5.30.1 (the registry and the fixtures), [near-workspaces](https://github.com/near/near-workspaces-rs) 0.24.0 and [near-sandbox](https://github.com/near/near-sandbox-rs) 0.4.0 (a local nearcore 2.14.0 node for the exploit tests), [near-api-js](https://github.com/near/near-api-js) 7.4.0 (the guard), the [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) 2.4.0 with zod 4.6.7 (the MCP server) and NEAR JSON-RPC (`view_code`, `view_account`, `view_access_key`, `call_function`). The web page adds no library: the Swap's transaction serializer, base58 and signing are hand-written over WebCrypto, and a test checks them byte for byte against a transaction built by near-api-js 7.4.0.

## How a rule is added

A rule is a Rust type with an id, a severity and a `check` over one crate's parsed source; adding a file under `scanner/src/rules/` registers it. The interfaces and the findings' JSON shape are in [SPEC.md](../SPEC.md).
