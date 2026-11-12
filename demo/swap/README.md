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
| `switch.preflight-guard.testnet` | Stores both builds and has `flip()`. |
| `registry.preflight-guard.testnet` | The existing Preflight registry. It holds one verdict per code hash, published by `auditor.preflight-guard.testnet`. |

The chameleon holds zero full-access keys, yet its code has already changed dozens of times through `switch`'s own `flip` (the live page shows the exact count). Zero keys never meant fixed code; that is exactly why Preflight checks the fingerprint instead of counting keys.

| Build | Code hash (base58, as NEAR shows it) | SHA-256 (hex) | Scanner | Registry verdict |
| --- | --- | --- | --- | --- |
| V, vulnerable | `CNtPsVA72SSm7xpTg2QdTZoyjR9K6zMmg4KKVnASwpfj` | `a90bdd6b7620881bdf98504748ff26db9e03dcd20592a975eb91fe3c84044942` | PF001 | Unsafe, `["PF001"]` |
| P, patched | `Gg8KdwiNHoP9tpzGismdHrpUiqmfNNcib3rp9iEKT4Hh` | `e8e53bd3c02aa77779d4f078f38457562b93af4355e6262dd54c7ff7b1be9cc4` | no findings | Safe, `[]` |

The two builds are `chameleon/vulnerable/src/lib.rs` and `chameleon/patched/src/lib.rs`. They are the same vault and differ in one line of code: P has `#[private]` on `on_deposit`, V has a comment there. A test (`the_two_chameleon_sources_differ_only_in_the_callback_guard`) keeps it that way, so the two builds read the same state and the swap needs no migration.

These are the second pair of builds. The first pair (V `HE6QGy21HDJNcGFU6N9vBiRutL52jv1R5DrgSkcA4WRa`, P `BzFFte9Lqs9kRfZcgRmYQNckLU9oBqK6SHBNfcQMwdsj`) let a stranger drain the chameleon's own storage money (below), which made later flips fail; their registry verdicts are still in the registry, and no account runs them any more. The report files in `reports/` are the second pair's, so a report hash recorded for the first pair no longer matches the file at its URL.

### The vulnerability is real

`deposit()` sends a 1% fee to the treasury and schedules `on_deposit` to credit the rest once the transfer has settled. In V, `on_deposit` is a public method, so any account can call it directly and credit itself any balance, then `withdraw` NEAR that other depositors put in. This is PF001 (a callback not marked `#[private]`). The scanner finds it from the source, and the sandbox test `the_vulnerable_chameleon_lets_an_outsider_credit_itself_and_drain_a_depositor` runs the attack against the real wasm. The same test sequence against P fails with `Method on_deposit is private` (`the_patched_chameleon_rejects_the_forged_callback_and_still_settles_a_real_deposit`). The chameleon on testnet holds no depositor's money; the attack is demonstrated in the sandbox, and on testnet against its spare balance (next).

### What a forged credit cannot reach

A forged credit may take what depositors put in. It must not take what keeps the contract alive: the chameleon pays for its own code and for the extra bytes of each upgrade out of its balance. The first pair of builds let the attacker withdraw that too: deposit 1 yoctoNEAR, forge a credit, withdraw the spare, and every later flip failed with `the chameleon's upgrade failed; it still runs the previous build`. Both builds now send every transfer out (`withdraw` and the refund of a failed deposit, which the same callback can reach) through one function that refuses to leave the account with less than its storage cost plus a reserve of 0.5 NEAR, computed from `env::storage_usage()` and `env::storage_byte_cost()`. A deposit must also cover the storage of the balance entry it creates, which is deducted from what it credits (`deposit` fails with `the deposit must cover the fee and the storage of your balance entry`), so a deposit never costs the contract anything. The attack is a sandbox test (`a_forged_credit_cannot_spend_the_contracts_own_money_so_the_flip_keeps_working`: forge a credit, withdraw all that is allowed, flip both ways) and it was run on testnet against the live V from a throwaway account: the forged credit was accepted (a genuine PF001), `withdraw` of 1,000 NEAR was refused with `that would spend the storage money and the reserve the contract keeps`, `withdraw` of everything allowed (0.5723 NEAR of spare above the reserve) succeeded and left the chameleon at exactly its storage cost plus 0.5 NEAR, and the next four flips with the public key all went through. So the chameleon's spare balance above 0.5 NEAR is bait by design (that is the vulnerability) and the 0.5 NEAR is not.

### The upgrade path

Both builds export `upgrade(code)`. It takes the new wasm as a Borsh `Vec<u8>` (a 4-byte little-endian length, then the bytes), requires the caller to be the switch, and runs `Promise::new(current_account_id).deploy_contract(code)`. It is an ordinary `#[near]` method with a caller check, so the scanner reads it, and P still scans clean. Nothing in the scanner was suppressed or special-cased.

`flip()` on the switch:

1. refuses before `next_flip_ms` (`too soon: the next flip is allowed from <ms>`; the minimum interval is 20 s) and with less than 100 Tgas attached;
2. sends the build that is not live to `chameleon.upgrade`;
3. in its callback `on_flipped`, which only the switch can call, records the new live build, counts the flip and logs a NEP-297 `swap` / `flipped` event. If the upgrade failed it records nothing.

The two builds are stored when the switch is initialised, and no method the page can reach writes or replaces them. Only the switch account's own full-access key (the deployer's) can initialise it again: `new` is `#[private]` and `#[init(ignore_state)]`, so a deployment can be replaced in place by one transaction that deploys the new code and calls `new` (how the second pair of builds went live; `deploy.ts --generation 2`). The flip key cannot call it.

## The flip key

The deployer's testnet keys directory holds `swap-flip-public.key` (mode 0600, never in the repository): the private key whose public half is `ed25519:5avhf3t11cgnAjjSrgJfAgjKjSTheAhdwhneXns19gKL`. It is a function-call key on `switch.preflight-guard.testnet`, restricted to receiver `switch.preflight-guard.testnet`, method `flip`, no deposit, with a gas allowance of 5 NEAR (renewed by the watchdog, below). It is meant to be published on the web page so a visitor's browser can sign `flip` with no wallet. Checked live: with that key, `on_flipped` is refused (`AccessKeyMethodNameMismatchActionError`), `chameleon.upgrade` is refused (`AccessKeyReceiverMismatchActionError`) and any deposit is refused (`AccessKeyDepositWithFunctionCallActionError`).

What a visitor can do with it is bounded three ways: the switch accepts one flip per 20 s, the key can only call `flip`, and its allowance runs out (below). Re-checked after the second deployment: `new` and `on_flipped` on the switch, `upgrade` on the chameleon, and a flip with any deposit are all refused for that key.

To sign a flip yourself: account id `switch.preflight-guard.testnet`, receiver `switch.preflight-guard.testnet`, method `flip`, args `{}`, gas 150 Tgas, deposit 0. `scripts/lib.ts` (`sendFlip`) does exactly that with near-api-js, and `npm run flip -- --key <file>` runs it.

### What it costs, and who pays

The flip key's private half is public, so anyone can spend its allowance and the switch's balance. What that costs, measured (the sandbox's burnt gas, and on testnet the fall of both the allowance and the switch's balance, which move together):

| Call | Burnt gas | Cost on testnet |
| --- | --- | --- |
| a flip that goes through (either direction) | 27.6 Tgas | about 0.0027 NEAR |
| a flip refused as too soon (a transaction that fails inside the switch) | 1.5 Tgas | 0.000146 NEAR, measured over three |

The gas attached beyond what is burnt is refunded, to the balance and to the allowance. With the 20 s interval at most 180 flips an hour go through (about 0.5 NEAR an hour); refused flips are cheaper each (about 6,800 per NEAR) but come as fast as the RPC lets a script send them, so they are the real drain: 5 NEAR of allowance is about 34,000 refused flips. The numbers on 2026-11-11: the switch holds 58.19 NEAR, of which 4.37 NEAR is locked by its storage (437,098 bytes: its own code and both builds), so 53.82 NEAR is spare, all of it from the testnet faucet and the project's own testnet accounts; the flip key's allowance is 5 NEAR (4.958 after 15 flips). That is about 100 hours of the worst case (a flip every 20 s, all accepted); the watchdog (next) is what keeps it going.

A function-call key's allowance cannot be raised in place; the watchdog replaces the key by itself (same public key, fresh allowance) in one transaction, so the page's key never changes.

### The watchdog

```sh
PREFLIGHT_TESTNET_KEYS=<dir with <account>.key files> make -C demo/swap watchdog
# or, without make: cd demo/swap && PREFLIGHT_TESTNET_KEYS=<dir> npm run --silent watchdog
```

It prints one line (`swap-watchdog <time> OK|FAIL | switch_spare=… chameleon_spare=… flip_allowance=… | live=… flips=… | repaired: … | problems: …`) and exits 0 when all three are above their floors, 1 when any is not and could not be repaired (or the chain could not be read), 2 for a usage error. Spare is balance minus what the account's storage costs. Floors and repairs, when `PREFLIGHT_TESTNET_KEYS` holds the key files:

| Reading | Floor | Repair |
| --- | --- | --- |
| switch spare | 5 NEAR | `preflight-guard.testnet` (`<dir>/preflight-guard.testnet.key`) sends NEAR up to 10 spare, as far as its own spare above 0.2 NEAR allows |
| chameleon spare | 0.3 NEAR | the same, up to 1 NEAR; the contract itself never lets it fall under 0.5 NEAR, so this floor trips only if something else is wrong |
| flip key allowance | 1 NEAR | `switch.preflight-guard.testnet` (`<dir>/switch.preflight-guard.testnet.key`) deletes and re-adds the same public key with 5 NEAR, in one transaction |

Without `PREFLIGHT_TESTNET_KEYS` it only reads and reports. The funder is the parent account, which holds 0.31 NEAR now (the rest was moved to the switch): past that, the line says FAIL and someone must send testnet NEAR to `preflight-guard.testnet` (the faucet, when it is up).

## What a page needs

Reads, JSON-RPC `query` with `request_type: "call_function"`, `finality: "final"` (args are base64 of the JSON):

- `status`, contract `switch.preflight-guard.testnet`, args `{}`. The result bytes are this JSON (all numbers are plain JSON numbers below 2^53; times are milliseconds since the Unix epoch):

```json
{
  "chameleon": "chameleon.preflight-guard.testnet",
  "live": "vulnerable",
  "vulnerable": { "code_hash": "CNtPsVA72SSm7xpTg2QdTZoyjR9K6zMmg4KKVnASwpfj", "code_hash_hex": "a90bdd6b7620881bdf98504748ff26db9e03dcd20592a975eb91fe3c84044942", "size_bytes": 143321 },
  "patched": { "code_hash": "Gg8KdwiNHoP9tpzGismdHrpUiqmfNNcib3rp9iEKT4Hh", "code_hash_hex": "e8e53bd3c02aa77779d4f078f38457562b93af4355e6262dd54c7ff7b1be9cc4", "size_bytes": 143650 },
  "flips": 9,
  "last_flip_ms": 1794425509139,
  "min_interval_ms": 20000,
  "next_flip_ms": 1794425529139
}
```

  `live` is `"vulnerable"` or `"patched"`: the build of the last flip that went through. The chain is the truth: `view_account` of the chameleon gives `code_hash`, the same base58 string as `code_hash` above.
- `get_verdict`, contract `registry.preflight-guard.testnet`, args `{"code_hash": "<base58>"}`. The result is `null` for an unknown hash, otherwise:

```json
{
  "code_hash": "CNtPsVA72SSm7xpTg2QdTZoyjR9K6zMmg4KKVnASwpfj",
  "status": "Unsafe",
  "rule_ids": ["PF001"],
  "report_url": "https://github.com/WonkaRed/preflight/blob/main/demo/swap/reports/chameleon-vulnerable.json",
  "report_sha256": "f6810d20974148854407ab37910f7c70b6e3935304672d7cdb4107b1297b92a5",
  "auditor": "auditor.preflight-guard.testnet",
  "published_at_ms": "1794421027132"
}
```

  For P: `"status": "Safe"`, `"rule_ids": []`. `published_at_ms` is a string (a u64). `status` `Unsafe` is the guard's `block`, `Warn` is `warn`, `Safe` is `allow`.

The guard's own `checkContract(contractId, { rpcUrl, registryId })` (`guard/src/check.ts`) does the same reading and returns `{ decision: "block" | "warn" | "allow", codeHash, verdict, reasons }`; `scripts/check.ts` calls it.

Write: the `flip` call above. A flip refused by the interval fails with `Smart contract panicked: too soon: the next flip is allowed from <ms>` and changes nothing; the page should disable its button until `next_flip_ms`. After a successful flip the chameleon's code hash changes as soon as the upgrade receipt runs; `status().live` and `flips` follow one receipt later, when `on_flipped` runs.

`recorded.json` holds four real flips (transaction hash, explorer link, block height and hash, and for each side the live build, code hash, registry verdict and guard decision) for the page to replay when the RPC is down. Every field except the explorer link was read from the chain by `scripts/record.ts`.

## Live record

Explorer: `https://testnet.near.rocks/tx/<hash>`. First deployment (the first pair of builds, retired):

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

Second deployment (the builds in the table above; `deployment.json` records every step as `<step>-g2`):

| Step | Transaction |
| --- | --- |
| publish verdict for V (Unsafe, PF001) | `AS4KrxGn1xE3SFqfLg1bhMFHAiXR11Ju3P4mvKBKDGa8` |
| publish verdict for P (Safe) | `FXLCGhF4wb4P2csGj9srz6EDWRa9YhwQC4fJXhKFkS2N` |
| give the chameleon 0.8 NEAR | `229Bs1wZPh4GM1biS5bjcb7EBvqhJhhYfkgoi2r7agry` |
| give the switch 7.5 NEAR | `C3hb5soJKY5jEbLj15AsAeu8AT3GvoBvZtfE3pviWe2x` |
| replace the flip key (same public key, 5 NEAR allowance), deploy the new switch, `new` | `2tRmGX3K9BGNyVUFE3UNRqvySrwde1aeogJ8xowb97Ve` |
| first flip: the old build to the new V | `3j4qVztFYaMMBBtP83EiWsGantxfBCnBDNCmbWFntDVN` |

The attack on the live V (a throwaway account, deleted afterwards): deposit 0.01 NEAR `F4CkimJwNJtrbChYDujbfDJTik7KLYgUUjnp3YHk77vX`, forged `on_deposit` of 1,000 NEAR `5eXiEVCiT7VpyXAiafSgUpWZW9VhG1rFZdrJtFjGAY6b`, `withdraw` of everything allowed `3eRecbNN77TokPKPLNLw8wX8VrPxQm2BGs79Qm9F632H` (the withdrawal of 1,000 NEAR was refused and left no transaction on chain).

The four recorded flips, signed with the flip key and nothing else, after that attack:

| # | Change | Guard | Transaction |
| --- | --- | --- | --- |
| 1 | V to P | BLOCK to ALLOW | `5efUodURtiHeAvfxJQTixSJGbUP7Y3GzBsRaeFBoYxd9` |
| 2 | P to V | ALLOW to BLOCK | `CtjfoUnJuRzRkktFFXrXyMyypVTVM3eFni4n5Bvnofzi` |
| 3 | V to P | BLOCK to ALLOW | `2j6fzVUDpMd81khAoAjaHdzpFYfCut786tJJyCjkJ7gZ` |
| 4 | P to V | ALLOW to BLOCK | `ELXAqXc3UWwxt23Nr6aep8i8Qgwih3C7tfjDLk5H3z3Y` |

More flips were sent before and after (the switch's counter says how many); the chameleon was left on V.

## Reproduce

The wasm files in `wasm/` are the ones that were scanned, hashed and deployed, and `wasm/SHA256SUMS` lists their hashes (the hex column above). The build is reproducible: `make build` remaps the checkout and cargo paths, and building from a copy of this directory at another path gave the same three hashes.

```sh
make build        # wasm/*.wasm and wasm/SHA256SUMS (pinned toolchain from rust-toolchain.toml)
make reports      # the scanner's JSON report for each build, in reports/
make test         # the sandbox tests: needs the pinned Rust toolchain, builds a local NEAR node
make watchdog     # one status line for the money, and the repairs (see above)
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

A later deployment of new builds behind the same accounts (publish their verdicts, top both accounts up, replace the switch in place, one flip) is the same command with `--generation 2 [--switch-topup 8] [--allowance 5] [--chameleon-topup 0.8]`.

Every step is recorded in `deployment.json` as it happens, and a rerun skips the recorded steps. Keys are written to `<dir>` with mode 0600 and never printed.

## Limits

- `live` in `status()` is a record, not a read: the switch cannot read the chameleon's code hash on chain. It is set only after the chameleon's upgrade succeeded, and a page that wants the truth reads `view_account`.
- The 20 s interval starts when `flip` is accepted, before the upgrade lands. If an upgrade ever took longer than that, a second flip could read a stale `live` and send the same build again: harmless, since the build is the one the first flip is already installing.
- The sandbox tests build the contracts with the repository's wasm flags, not `make build`'s path remapping; the code is the same, the bytes (and hashes) differ.
- The chameleon's treasury is `preflight-guard.testnet`; the vault is a demonstration and has no way to recover funds sent to it other than `withdraw`.

## Keeping it alive

A systemd user timer runs the watchdog every 30 minutes (persistent, so a run missed while the machine was off happens at the next boot). The units are in `systemd/` (`preflight-swap-watchdog.service` and `.timer`). Install: `cp systemd/preflight-swap-watchdog.* ~/.config/systemd/user/ && systemctl --user daemon-reload && systemctl --user enable --now preflight-swap-watchdog.timer`.

- The service points at this checkout (`WorkingDirectory=`), so move it with the checkout.
- Set `PREFLIGHT_TESTNET_KEYS` to your key directory.
- The unit's alert command, which runs when a run exits non-zero, is a placeholder for your own notifier.
- The watchdog's line is in `journalctl --user -u preflight-swap-watchdog`.
- The watchdog tops up the switch and the chameleon only from `preflight-guard.testnet`; when its line says the funder has nothing to give, fund that account first.

### The idle reset

The page works best when a visitor arrives to the patched build (both checks say ALLOW) and swaps in the vulnerable one: the address check keeps saying ALLOW, Preflight turns to BLOCK, and the page notes that the code changed since the visitor arrived. A visitor who swaps it to the vulnerable build and leaves would hand the next visitor a page that already says BLOCK, so a second timer puts it back on the patched build. `scripts/idle-reset.ts` (`npm run --silent idle-reset`, or `make -C demo/swap idle-reset`) flips the chameleon to the patched build when all of these hold, and does nothing otherwise:

- the chain reports the vulnerable build's code hash for the chameleon, and the switch records `live: vulnerable` (so a swap is not still landing);
- the switch's `last_flip_ms` is more than 10 minutes behind the chain's block time (`--idle-minutes <n>` changes the 10).

Safety against a visitor swapping at the same moment: it reads the switch and the chain twice, the second time right before it sends, at optimistic finality, and sends nothing if the second read says there is nothing to do. It sends at most one transaction per run. If a visitor's flip lands between its last read and its own, the switch refuses the second flip as too soon (its 20 s interval), which changes nothing, and the script logs it as skipped. It signs with the public flip key (`<keys dir>/swap-flip-public.key`), so a reset costs gas from that key's allowance (about 0.0027 NEAR, the table above) and nothing else; the watchdog renews the allowance. `--dry-run` reads and prints the decision and needs no key.

It prints one line per run:

```
swap-idle-reset <time> RESET to the patched build | chain=vulnerable recorded=vulnerable last_swap_s_ago=858 flips=34 | tx=<hash> https://testnet.near.rocks/tx/<hash> | now: chain=patched recorded=patched last_swap_s_ago=3 flips=35
swap-idle-reset <time> OK nothing to do | chain=patched recorded=patched last_swap_s_ago=... | the patched build is live
```

The first word after the time is `RESET`, `OK` (nothing to do, or skipped because a visitor got there first) or `FAIL` (exit 1: the chain could not be read, the key is missing, or the flip failed for another reason). The units are `systemd/preflight-swap-idle-reset.service` and `.timer`; the timer runs the service two minutes after boot and two minutes after each run finished, so a reset happens between 10 and 12 minutes after the last swap. Install: `cp systemd/preflight-swap-idle-reset.* ~/.config/systemd/user/ && systemctl --user daemon-reload && systemctl --user enable --now preflight-swap-idle-reset.timer`; the lines are in `journalctl --user -t swap-idle-reset` (by identifier, not `-u`: journald can lose the unit of a line from a process that exits at once). Same notes as the watchdog: the service points at this checkout and at your key directory. There is no alert command: a failed run shows in `systemctl --user --failed`, and the next run (two minutes later) tries again.
