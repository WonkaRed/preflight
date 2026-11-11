# The guard, the agent's key and the testnet deployment

## What the guard decides

The guard is TypeScript ([`guard/`](../guard), API and decision table in [guard/README.md](../guard/README.md)). `checkContract` reads the deployed wasm with `view_code`, hashes it, looks the hash up in the registry and returns:

- `block` for an `Unsafe` verdict or any failure to read;
- `warn` for a hash with no verdict (unaudited, or changed since its audit);
- `allow` for `Safe`.

It also returns `allow` for an account that does not exist or has no code (nothing to audit), a call `guardedCall` refuses. `GuardedAgent.guardedCall` adds a check of the signing key's permission on chain and a local spending policy.

## Which commands need a model or a key

| Command | Model | Key | Network |
| --- | --- | --- | --- |
| `make -C guard demo` (a scripted agent obeys an injected web page; fake RPC node) | no | no | none |
| `make -C guard demo-llm-replay` (two recorded model answers, one that followed the page and one that called the audited contract, through the real guard on the fake chain; says it is a replay) | no | no | none |
| `make -C guard testnet-verify` (read-only check of the testnet deployment below against the chain) | no | no | testnet RPC, read-only |
| `make -C guard demo-llm` (a language model is the agent, on the fake chain) | yes: a model server on this machine, or an https endpoint (`PREFLIGHT_LLM_ENDPOINT`, `PREFLIGHT_LLM_MODEL`, and `PREFLIGHT_LLM_API_KEY` for a remote one) | model API key only for a remote server | the model's endpoint only |
| `make -C guard testnet-demo-llm AGENT_KEYS=<dir>` (the same model against the testnet contracts, real transactions) | yes, as above | the agent's key files, which are not in this repository: only the owner can run it | testnet RPC and the model's endpoint |

The ones that need a model, for example against a model server on this machine:

```sh
PREFLIGHT_LLM_ENDPOINT=http://127.0.0.1:18020 PREFLIGHT_LLM_MODEL=<model id> make -C guard demo-llm
```

What the model runs recorded: [model-runs.md](model-runs.md).

## The agent's key

The agent signs with a function-call access key, never a full-access key (`GuardedAgent` refuses a full-access key unless the caller opts in).

- Such a key can call one contract (`receiver_id`) and, when a method list is set, only those methods; an empty list means every method, so the scoping tool (`npm run scope-key`, in [guard/](../guard)) requires a non-empty one.
- It can attach no deposit, so it cannot transfer NEAR.
- Its allowance is a budget for gas fees, not tokens: when it is used up the key stops working.
- An account that holds only function-call keys cannot transfer NEAR, delete itself or add keys.
- What the key does not limit is the code behind the address: its owner can redeploy to the same account and the key stays valid, which is the question the guard answers.

The full list: [guard/README.md](../guard/README.md#function-call-access-keys-what-they-can-and-cannot-do).

On testnet, `agent.preflight-guard.testnet` holds three such keys, one per shop, each limited to `release` on that shop, and nothing else: its setup full-access key was deleted by one `DeleteKey` transaction ([`39A6FMANRz...`](https://testnet.near.rocks/tx/39A6FMANRzKitGaLPuACf3tGcxhZjc9grSWCQ6L2Ngdg)), and `make -C guard testnet-verify` checks on chain that the account holds no full-access key.

With it gone this account cannot fund more escrow orders: 17 are still funded (orders 9 to 25, read from the chain on 2026-11-11 after the language-model runs), enough for 17 more runs of the testnet demos; after that the way on is a copy deployed to your own accounts ([testnet-demo.md](testnet-demo.md), "Run it again").

## The testnet deployment

The registry and the guard are deployed on NEAR testnet (throwaway accounts, faucet funds, no mainnet), all under `preflight-guard.testnet`:

| Account | What it is |
| --- | --- |
| `registry.preflight-guard.testnet` | the registry; it has no access key, so nobody can redeploy it |
| `auditor.preflight-guard.testnet` | the registry's only allowlisted account |
| `shop-vulnerable.preflight-guard.testnet` | the PF001 vulnerable escrow; the registry says Unsafe (PF001) |
| `shop-patched.preflight-guard.testnet` | the PF001 patched escrow; the registry says Safe |
| `shop-swapped.preflight-guard.testnet` | audited as the patched build, then redeployed with other code: no verdict |
| `agent.preflight-guard.testnet` | the agent; it holds only one function-call key per shop, each limited to `release` (no full-access key) |

The live Swap demo adds `chameleon.preflight-guard.testnet` and `switch.preflight-guard.testnet`: see [demo/swap/README.md](../demo/swap/README.md).

In three recorded runs a scripted agent that obeys an injected web page had its release on the patched shop sent as a real testnet transaction, while the injected release on the vulnerable shop was blocked on the registry's Unsafe verdict, the swapped shop got a `warn` that was declined, and a call to a method outside the key's scope and two payments over the spending policy were refused.

Account ids, code hashes, transaction hashes, the decision log and commands that check them by hand are in [testnet-demo.md](testnet-demo.md); the recorded runs are in [`docs/testnet-runs/`](testnet-runs). Re-running the transactions needs the agent's private keys, which are not in this repository; `make -C guard testnet-verify` needs none.

The `report_url` in each testnet verdict points at the report file in this repository on GitHub, and the on-chain `report_sha256` is what binds a verdict to the files in [`docs/testnet-reports/`](testnet-reports) (`testnet-verify` checks it).
