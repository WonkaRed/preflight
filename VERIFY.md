# For reviewers and AI screeners

Preflight is a defense for AI agents that sign NEAR contract calls: before the agent signs, a guard hashes the code deployed at the address and looks the hash up in an on-chain registry of verdicts, then answers allow, warn or block. It ships a 26-rule contract scanner (each rule has a vulnerable and a patched fixture and a sandbox exploit), the registry, the guard, and an MCP server.

## Run this first

```sh
make verify    # Node.js 22.22.2 or newer and make; no Rust; about 10 s on a warm machine
```

It runs every claim in [`claims.json`](claims.json) that this machine can check and prints one line each: `PASS`, `FAIL` or `SKIP <id> <claim>` (a SKIP says why and is a claim not checked, not a pass). It exits non-zero on any FAIL and writes `verify-result.json`.

- C01 scans all 26 fixture pairs with the scanner's WebAssembly build: the vulnerable file must report its own rule, the patched file nothing. The wasm is `web/dist/preflight.wasm` if built, else the live page's copy, downloaded; its SHA-256 and origin are printed.
- C02, C03, C07 read the live NEAR testnet and the live page (network). C04, C06 run offline demos on a fake chain. C05 reads the raw record of the 10 recorded testnet model runs; it does not rerun the model.
- C08 is the full exploit suite, `make test` (Rust, about 6.5 minutes). `make verify` never runs it.
- `make verify VERIFY_ARGS=--offline` skips the network claims. `node scripts/verify.mjs C01` runs one claim.

## Where things are

- Live page (the Swap, the scanner in your browser, an account check): <https://wonkared.github.io/preflight/>
- `scanner/` the rules and the `preflight` CLI; `fixtures/` one vulnerable and one patched contract per rule; `exploits/` the sandbox exploit per rule
- `registry/` the verdict contract; `guard/` the agent-side guard, demos, and `guard/mcp` the MCP server
- `web/` the page; `web-scan/` the scanner as wasm; `demo/swap/` the Swap's contracts; `docs/` records and detail

## Limits

Read the README's [Limits](README.md#limits) before judging: the scan is syntactic, the auditor is one account the author controls, the model evidence is thin, and everything is testnet. The mainnet figures in the README come from a recorded snapshot ([docs/mainnet-sweep.md](docs/mainnet-sweep.md)) whose account list is not published, so `make verify` does not recheck them. The wasm that `make verify` scans is checked against the native scanner byte for byte only in `make test`.
