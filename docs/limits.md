# Limits

The README's Limits section is the short version. This page has the full text of each limit. Per-component limits live next to the component: [guard/README.md](../guard/README.md#limits), [web-page-limits.md](web-page-limits.md), [demo/swap/README.md](../demo/swap/README.md#limits).

## The scanner

- The scanner is syntactic: it parses source with `syn`, expands no macros, resolves no types and follows calls only inside one crate, by name, where a rule needs it (PF015, for example, reads the callback a transfer schedules). It reports patterns, not proofs, and can miss a bug or flag safe code. A clean result means "no known rule fired", not "safe".
- PF001 recognises a callback by its callback argument attribute or by a `Self::ext(..)` / `Type::ext(env::current_account_id())` call chain in the same crate. A callback scheduled through a raw `Promise::function_call("name", ..)` with no callback argument is not recognised, and neither is one scheduled through a helper that only returns the `ext(..)` builder. It reports every such callback without `#[private]`, including one that checks its caller by hand.
- Every rule has a vulnerable and a patched fixture contract and a sandbox exploit that works on the first and fails on the second. That shows the bug class is real; it does not show that a finding on your code is.
- The rules cover known patterns only, and on real code most findings are not bugs. On 14 public repositories pinned by commit the scanner reports 90 findings. In 75 of them the pattern the rule names is really in the code: in 10 with nothing in view that stops it (true), in 65 where something the scanner cannot see keeps the harm out (defensible). 15 (17 percent) are wrong.
- The script reproduces the 90 findings and the per-rule counts; the per-finding triage is withheld, so the split into true, defensible and wrong is my judgment and cannot be rerun from this repository. The counts, the false-alarm shapes and the script are in [real-world.md](real-world.md).
- Files under a crate's `tests/` or `benches/` directory are skipped and counted in the report.
- The exploit tests run in a local sandbox only. Behaviour on testnet or mainnet is not tested, apart from the read-only and recorded testnet runs.

## `preflight account` (deployed contracts)

- It reads one block of one account through the RPC it is given and trusts that node's answers. It uses no HTTP proxy, whatever `HTTP_PROXY` or `ALL_PROXY` say.
- It checks the code's export names, not what the code does; PFW03's metadata is self-declared; a clean report means only that PFW01 to PFW06 found nothing.
- The mainnet sweep (142 contracts) reports counts only: [mainnet-sweep.md](mainnet-sweep.md).

## The registry and the guard

- The registry is trust-based: a verdict is only as good as the allowlisted auditor who published it, and it covers one exact wasm hash. Here the auditor is an account I control.
- The guard's check and the transaction are two steps; an owner could redeploy between them (see "Limits" in [guard/README.md](../guard/README.md#limits)).
- The guard's key check (off by default) counts full-access keys on one account and compares code hashes with the one approved before. It cannot see whether a contract can upgrade itself through one of its own methods (so zero keys does not mean fixed code), nor when the code last changed before the first time it was approved, and for an account that follows a global contract by publisher it names the publisher, not the code. It reads the key list once, unpaginated: nearcore (master, `view_access_keys` and `AccessKeyList`, read 2026-11-12) answers an unpaginated request in full or with a too-many-keys error, and sets `last_key` on a partial page, which the guard treats as a failure; I could not rule out an RPC provider that cuts a list short without `last_key`, and I did not check the nearcore version each endpoint runs. The table in [mainnet-survey.md](mainnet-survey.md) is a one-day snapshot of key counts, not a statement about any contract.

## The Swap on the web page

- The Swap is a demonstration of what each check keys on, not a measure of either. The "An address allowlist" card is a real baseline, the check agent wallets and NEAR function-call keys scoped to one contract already give you, not a model of any particular wallet or agent. The registry's auditor is an account I control.
- The key in the page is public on purpose: it is a function-call key that can only call `flip` on a demo contract, with a small gas allowance, and everything on it is NEAR testnet, read through two public RPC endpoints (FastNEAR and dRPC) that the page fails over between because either may throttle.
- When the demo key can no longer pay (allowance spent, account balance short, key removed) or the RPC is unreachable the button replays `demo/swap/recorded.json` and the page says so.
- The page signs with the browser's built-in Ed25519 (WebCrypto), which older browsers lack; there it says so and nothing is sent.

## Model runs and the testnet deployment

- **Mainnet.** Everything on chain is testnet: throwaway accounts, faucet funds.
- **Other models.** One model, and 10 testnet runs (two recorded batches of 5). The three scripted testnet runs use a script as the agent.
- **A page we did not write.** I wrote the injected page, and reworded it five times before the first batch to get the model to follow it. The record lists every attempt.
- **That the guard changed what the model chose.** After batch 1 the demo's refusal text told the model its task could go on, and in 2 of the 4 successes the demo's stock rule also named the right order; those are hints from the demo harness, not decisions of the model's, and not behavior of the guard.
- **That a verdict is right.** A verdict is only as good as the auditor who published it (see above).

The runs themselves: [model-runs.md](model-runs.md).

## Where it was run

- Linux on x86-64 with glibc 2.39 or newer. The NEAR sandbox binary the exploit tests use needs it; no other platform was tried.
- `make test` took 389 s (6.5 minutes) on a fresh clone for a reviewer whose cargo registry was already warm. With nothing cached it also downloads the crates, the NEAR sandbox binary and the npm packages: an earlier estimate for that case is 15 to 25 minutes, not re-measured. Linking needs several GB of free RAM.
