# The Swap

One testnet address, `chameleon.preflight-guard.testnet`, whose contract code flips between a vulnerable build and a patched build every time anyone signs one transaction. A check that trusts the address keeps saying "allow". Preflight keys its verdict to the SHA-256 of the deployed code, so it flips between BLOCK (PF001) and ALLOW with the code. Every flip is a real testnet transaction.

Testnet only. Nothing here touches mainnet.

## Check it in ten seconds, no key

```sh
git clone https://github.com/WonkaRed/preflight.git && cd preflight/demo/swap
./check.sh
```

Needs Node.js 22.22.2 or newer and network access. It installs the dependencies of `guard/` and of this directory from their lockfiles on first use, then makes read-only RPC calls to `https://test.rpc.fastnear.com`. It prints the switch's `status()`, the code hash the chain reports for the chameleon, and two verdicts: the address check (always ALLOW) and the guard's `checkContract` (BLOCK or ALLOW, by the code hash). Flip the chameleon on the web page, or with the public flip key below, and run it again.

## The pieces

| Account | Role |
| --- | --- |
| `chameleon.preflight-guard.testnet` | A small deposit vault. Runs build V or build P. It has no access keys (they were deleted after the first flip worked), so the only thing that can change its code is `switch`. |
| `switch.preflight-guard.testnet` | Stores both builds for good and has `flip()`. |
| `registry.preflight-guard.testnet` | The existing Preflight registry. It holds one verdict per code hash, published by `auditor.preflight-guard.testnet`. |

| Build | Code hash (base58, as NEAR shows it) | SHA-256 (hex) | Scanner | Registry verdict |
| --- | --- | --- | --- | --- |
| V, vulnerable | `HE6QGy21HDJNcGFU6N9vBiRutL52jv1R5DrgSkcA4WRa` | `f115a60b138caa907e76985a45109980a0afadb2f00161ea15cd5f977fa6dfcd` | PF001 | Unsafe, `["PF001"]` |
| P, patched | `BzFFte9Lqs9kRfZcgRmYQNckLU9oBqK6SHBNfcQMwdsj` | `a33f1873cdf26c4f7f10572ba2b6d5f69f0a1769b6c696f6371e1fd6d1a33a5e` | no findings | Safe, `[]` |

The two builds are `chameleon/vulnerable/src/lib.rs` and `chameleon/patched/src/lib.rs`. They are the same vault and differ in one line of code: P has `#[private]` on `on_deposit`, V has a comment there. A test (`the_two_chameleon_sources_differ_only_in_the_callback_guard`) keeps it that way, so the two builds read the same state and the swap needs no migration.

### The vulnerability is real

`deposit()` sends a 1% fee to the treasury and schedules `on_deposit` to credit the rest once the transfer has settled. In V, `on_deposit` is a public method, so any account can call it directly and credit itself any balance, then `withdraw` NEAR that other depositors put in. This is PF001 (a callback not marked `#[private]`). The scanner finds it from the source, and the sandbox test `the_vulnerable_chameleon_lets_an_outsider_credit_itself_and_drain_a_depositor` runs the attack against the real wasm. The same test sequence against P fails with `Method on_deposit is private` (`the_patched_chameleon_rejects_the_forged_callback_and_still_settles_a_real_deposit`). The chameleon on testnet holds no one's money; the attack is demonstrated in the sandbox only.

### The upgrade path

Both builds export `upgrade(code)`. It takes the new wasm as a Borsh `Vec<u8>` (a 4-byte little-endian length, then the bytes), requires the caller to be the switch, and runs `Promise::new(current_account_id).deploy_contract(code)`. It is an ordinary `#[near]` method with a caller check, so the scanner reads it, and P still scans clean. Nothing in the scanner was suppressed or special-cased.

`flip()` on the switch:

1. refuses before `next_flip_ms` (`too soon: the next flip is allowed from <ms>`; the minimum interval is 10 s) and with less than 100 Tgas attached;
2. sends the build that is not live to `chameleon.upgrade`;
3. in its callback `on_flipped`, which only the switch can call, records the new live build, counts the flip and logs a NEP-297 `swap` / `flipped` event. If the upgrade failed it records nothing.

The two builds are stored when the switch is initialised and nothing can write or replace them afterwards: the switch has no owner method.

## The flip key

The deployer's testnet keys directory holds `swap-flip-public.key` (mode 0600, never in the repository): the private key whose public half is `ed25519:5avhf3t11cgnAjjSrgJfAgjKjSTheAhdwhneXns19gKL`. It is a function-call key on `switch.preflight-guard.testnet`, restricted to receiver `switch.preflight-guard.testnet`, method `flip`, no deposit, with a gas allowance of 3 NEAR. It is meant to be published on the web page so a visitor's browser can sign `flip` with no wallet. Checked live: with that key, `on_flipped` is refused (`AccessKeyMethodNameMismatchActionError`), `chameleon.upgrade` is refused (`AccessKeyReceiverMismatchActionError`) and any deposit is refused (`AccessKeyDepositWithFunctionCallActionError`).

What a visitor can do with it is bounded three ways: the switch accepts one flip per 10 s, the key can only call `flip`, and its allowance runs out (below).

To sign a flip yourself: account id `switch.preflight-guard.testnet`, receiver `switch.preflight-guard.testnet`, method `flip`, args `{}`, gas 150 Tgas, deposit 0. `scripts/lib.ts` (`sendFlip`) does exactly that with near-api-js, and `npm run flip -- --key <file>` runs it.

### What a flip costs, and how to top it up

A flip burns about 27.5 Tgas (measured in the sandbox, both directions) and 0.0027 NEAR on testnet (measured live: the allowance and the switch's balance each fell by 0.0027 NEAR per flip). The gas attached beyond that is refunded.

- Allowance: 3 NEAR, about 1,100 flips. A function-call key's allowance cannot be raised in place. To renew it, add a fresh key with `guard/scripts/scope-key.ts` (it needs the switch's full-access key in `NEAR_OWNER_KEY` and prints nothing secret) and publish the new key, or delete the old key and add it back.
- Balance: `switch` holds 5.97 NEAR, of which 4.35 NEAR is locked by its storage (435,406 bytes: its own code and both builds). The spare 1.6 NEAR covers about 600 flips. To top up, send NEAR to `switch.preflight-guard.testnet` from any testnet account.

## What a page needs

Reads, JSON-RPC `query` with `request_type: "call_function"`, `finality: "final"` (args are base64 of the JSON):

- `status`, contract `switch.preflight-guard.testnet`, args `{}`. The result bytes are this JSON (all numbers are plain JSON numbers below 2^53; times are milliseconds since the Unix epoch):

```json
{
  "chameleon": "chameleon.preflight-guard.testnet",
  "live": "vulnerable",
  "vulnerable": { "code_hash": "HE6QGy21HDJNcGFU6N9vBiRutL52jv1R5DrgSkcA4WRa", "code_hash_hex": "f115a60b138caa907e76985a45109980a0afadb2f00161ea15cd5f977fa6dfcd", "size_bytes": 142476 },
  "patched": { "code_hash": "BzFFte9Lqs9kRfZcgRmYQNckLU9oBqK6SHBNfcQMwdsj", "code_hash_hex": "a33f1873cdf26c4f7f10572ba2b6d5f69f0a1769b6c696f6371e1fd6d1a33a5e", "size_bytes": 142797 },
  "flips": 8,
  "last_flip_ms": 1794421224807,
  "min_interval_ms": 10000,
  "next_flip_ms": 1794421234807
}
```

  `live` is `"vulnerable"` or `"patched"`: the build of the last flip that went through. The chain is the truth: `view_account` of the chameleon gives `code_hash`, the same base58 string as `code_hash` above.
- `get_verdict`, contract `registry.preflight-guard.testnet`, args `{"code_hash": "<base58>"}`. The result is `null` for an unknown hash, otherwise:

```json
{
  "code_hash": "HE6QGy21HDJNcGFU6N9vBiRutL52jv1R5DrgSkcA4WRa",
  "status": "Unsafe",
  "rule_ids": ["PF001"],
  "report_url": "https://github.com/WonkaRed/preflight/blob/main/demo/swap/reports/chameleon-vulnerable.json",
  "report_sha256": "d4aa7541abcff2aaaf2f949cf19c11670c67ee1e22bf3d2900b66257b22d9adb",
  "auditor": "auditor.preflight-guard.testnet",
  "published_at_ms": "1794421027132"
}
```

  For P: `"status": "Safe"`, `"rule_ids": []`. `published_at_ms` is a string (a u64). `status` `Unsafe` is the guard's `block`, `Warn` is `warn`, `Safe` is `allow`.

The guard's own `checkContract(contractId, { rpcUrl, registryId })` (`guard/src/check.ts`) does the same reading and returns `{ decision: "block" | "warn" | "allow", codeHash, verdict, reasons }`; `scripts/check.ts` calls it.

Write: the `flip` call above. A flip refused by the interval fails with `Smart contract panicked: too soon: the next flip is allowed from <ms>` and changes nothing; the page should disable its button until `next_flip_ms`. After a successful flip the chameleon's code hash changes as soon as the upgrade receipt runs; `status().live` and `flips` follow one receipt later, when `on_flipped` runs.

`recorded.json` holds four real flips (transaction hash, explorer link, block height and hash, and for each side the live build, code hash, registry verdict and guard decision) for the page to replay when the RPC is down. Every field except the explorer link was read from the chain by `scripts/record.ts`.

## Live record

Setup (explorer: `https://testnet.near.rocks/tx/<hash>`):

| Step | Transaction |
| --- | --- |
| create chameleon (1.7 NEAR) | `8EFFRP3aGcfyZnhevkVufpbNoAAx7LUohjs37F1Y7fzx` |
| create switch (6 NEAR) | `7pHiFQmZ8RGhGLZmBU6uwboSSKrMmzWTxFM7zKGiX5mr` |
| deploy V on the chameleon and `new` | `CbrKEgcbgJRNsJdNPaeHEmBqm469h2DZXe8fxpFkgMTe` |
| deploy the switch and `new` (stores both builds) | `7fGD3BWnedSe8NT8tMsKzCRh4q95VvJis3cFVN4DvHk1` |
| publish verdict for V (Unsafe, PF001) | `Ep8c8PqhNkGbzQRdftzDzCYGCKabqqfKwCLUpSZTgnpJ` |
| publish verdict for P (Safe) | `4USGVyw1DWRaRk4xuPr8oHp2EMVdDyuqTxzR9y4MRAPh` |
| add the flip key | `2z1byPikKVYfgSXCWAF67cMFfFz854TvkaHd86hfzwnV` |
| delete the chameleon's key | `7eQw3s93kY29Taz65tsW2SHRAScyhWLAqKF5Jzpr8WoN` |

The four recorded flips, signed with the flip key and nothing else:

| # | Change | Guard | Transaction |
| --- | --- | --- | --- |
| 1 | P to V | ALLOW to BLOCK | `6LcXC8ehGsaukGN9JuKe7StYTT2Us51jn5LhYwceY4bp` |
| 2 | V to P | BLOCK to ALLOW | `72WhNT2pHp1LjYLgfEZkQz4jwpXgrEmL2pzGnedmVB2a` |
| 3 | P to V | ALLOW to BLOCK | `x1okFKCXPLi6kTG8mavhKhpggZqbQ8GnezppenkMCu1` |
| 4 | V to P | BLOCK to ALLOW | `Bs7UpkMmycW2U69SCfLNUrU84DEmazZkU4s46v7wFaXK` |

More flips were sent before and after (the switch's counter says how many); the chameleon was left on V.

## Reproduce

The wasm files in `wasm/` are the ones that were scanned, hashed and deployed, and `wasm/SHA256SUMS` lists their hashes (the hex column above). The build is reproducible: `make build` remaps the checkout and cargo paths, and building from a copy of this directory at another path gave the same three hashes.

```sh
make build        # wasm/*.wasm and wasm/SHA256SUMS (pinned toolchain from rust-toolchain.toml)
make reports      # the scanner's JSON report for each build, in reports/
make test         # the sandbox tests: needs the pinned Rust toolchain, builds a local NEAR node
npm ci && npm run build   # typecheck the scripts
```

Deploying your own copy under a testnet account you control (it creates `chameleon.<you>.testnet` and `switch.<you>.testnet`; it needs the registry's auditor key, so point `--parent` at an account whose `registry` and `auditor` sub-accounts exist, or publish the verdicts yourself):

```sh
PREFLIGHT_TESTNET_KEYS=<dir with <account>.key files> \
  node --disable-warning=ExperimentalWarning scripts/deploy.ts --parent <you>.testnet --wasm-dir wasm --reports reports
# once a flip has worked, seal the chameleon (deletes its only key):
  ... scripts/deploy.ts --parent <you>.testnet --wasm-dir wasm --reports reports --seal
node --disable-warning=ExperimentalWarning scripts/record.ts --key <dir>/swap-flip-public.key
```

Every step is recorded in `deployment.json` as it happens, and a rerun skips the recorded steps. Keys are written to `<dir>` with mode 0600 and never printed.

## Limits

- `live` in `status()` is a record, not a read: the switch cannot read the chameleon's code hash on chain. It is set only after the chameleon's upgrade succeeded, and a page that wants the truth reads `view_account`.
- The 10 s interval starts when `flip` is accepted, before the upgrade lands. If an upgrade ever took longer than that, a second flip could read a stale `live` and send the same build again: harmless, since the build is the one the first flip is already installing.
- The sandbox tests build the contracts with the repository's wasm flags, not `make build`'s path remapping; the code is the same, the bytes (and hashes) differ.
- The chameleon's treasury is `preflight-guard.testnet`; the vault is a demonstration and has no way to recover funds sent to it other than `withdraw`.
