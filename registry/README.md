# Preflight verdict registry

A NEAR smart contract (near-sdk 5.30.1) that stores one security verdict per contract code hash. A scanner
produces a report, an allowlisted auditor publishes the verdict here keyed by the SHA-256 of the deployed wasm, and
an agent's guard reads it before signing a call or payment. The interface is [SPEC.md](../SPEC.md) section 6.

Three properties make the verdicts trustworthy:

- **Only allowlisted auditors can write.** The allowlist is set once in `new` and nothing can change it: no owner,
  no setter, no upgrade method. A test reads the wasm's export table and asserts it holds exactly the five methods
  below.
- **The contract sets `auditor` and `published_at_ms` itself.** They are not arguments, so a verdict cannot be
  published in someone else's name or backdated.
- **The key is what the chain reports.** `code_hash` is the base58 SHA-256 of the deployed wasm, the same string
  NEAR RPC returns as an account's `code_hash`. A sandbox test deploys a contract, takes that string from the node,
  publishes a verdict under it and reads it back.

## Methods

| Method | Kind | Who | What it does |
| --- | --- | --- | --- |
| `new(auditors)` | init | once | Fixes the allowlist: 1 to 16 distinct account ids. Panics if the list is empty, too long or has a repeat. |
| `publish_verdict(code_hash, status, rule_ids, report_url, report_sha256)` | payable call | allowlisted auditors | Validates the input, stores the verdict (replacing any earlier one for the same `code_hash`) and logs an event. Panics for any other caller. |
| `get_verdict(code_hash)` | view | anyone | The stored `Verdict`, or `null` when none exists. |
| `get_auditors()` | view | anyone | The allowlist. |

`Verdict` as JSON: `{ "code_hash", "status": "Safe" | "Warn" | "Unsafe", "rule_ids": ["PF001"], "report_url",
"report_sha256", "auditor", "published_at_ms" }`. `published_at_ms` is a string (near-sdk `U64`), the block
timestamp in milliseconds.

### Bounds

Every argument is checked before anything is stored, and a failure panics with a message that names the field.

| Field | Rule |
| --- | --- |
| `code_hash` | At most 44 characters, base58, and it decodes to exactly 32 bytes (a SHA-256 digest). |
| `report_sha256` | Exactly 64 lowercase hex characters. |
| `report_url` | At most 256 bytes and starts with `https://` or `http://`, so a UI can link it without opening a `javascript:` URL. |
| `rule_ids` | At most 32, each exactly `PF` and three digits (`PF001`), no repeats. A `Safe` verdict must have none; a `Warn` or `Unsafe` verdict must have at least one, so the reader knows why. |
| `auditors` (in `new`) | 1 to 16 distinct accounts. |

`get_verdict` does not validate its argument: a malformed hash is simply not found.

### Storage: the auditor pays

`publish_verdict` is `#[payable]` and charges the storage the verdict adds (the change in `storage_usage` times the
protocol byte price), refunds the rest of the attached deposit, and panics if it is too little. Allowlisting already
means only trusted accounts can fill storage, but charging also means the contract's balance never pays for
anything, so it cannot be locked up by a runaway or compromised auditor, and it is the pattern the project's own
rule PF008 asks for. A verdict costs under 0.001 NEAR typically and under 0.01 NEAR at the largest sizes the bounds allow
(a unit test publishes that largest verdict with 0.01 NEAR attached); replacing a verdict with one of the same size
or smaller costs nothing, so attach a small deposit such as `0.01 NEAR` and the excess comes back.

### Event

Each publication logs a [NEP-297](https://nomicon.io/Standards/EventsFormat) event:

```
EVENT_JSON:{"standard":"preflight","version":"1.0.0","event":"verdict_published","data":{"code_hash":"...","status":"Warn","auditor":"auditor.testnet"}}
```

## Build and test

Rust 1.95 (pinned by the repository's `rust-toolchain.toml`) with the `wasm32-unknown-unknown` target; rustup
installs both on first use.

```sh
make -C registry build   # target/wasm32-unknown-unknown/release/registry.wasm
make -C registry test    # unit tests, then the sandbox tests
```

The unit tests (`src/validate.rs`, `src/tests.rs`) cover every validation branch, access control, the stored
verdict, the event and the deposit. The sandbox tests (`tests/sandbox.rs`) build the real wasm and run it on a local
NEAR node (`near-workspaces`): publish and read back, outsider rejected, replacement, unknown hash is `null`, the
code-hash keying, the deposit and refund, no re-initialisation, and the export table. The first run downloads the
nearcore sandbox binary, which needs glibc 2.39 or newer.

## Deploy to testnet

You need [near-cli-rs](https://github.com/near/near-cli-rs) 0.31 (`near`) and a testnet account with keys in your
keychain. Run from the repository root. The command chains were checked against `near ... --help` of 0.31.1.

This registry is live on testnet: [docs/testnet-demo.md](../docs/testnet-demo.md) lists its account, code hash and every
transaction. That deployment used `guard/scripts/testnet-deploy.ts` (near-api-js, the same actions as steps 3, 4 and the
key deletion below, in one script) and near-cli-rs for creating the first accounts through the faucet
(`sponsor-by-faucet-service` with `use-manually-provided-public-key`); the read-only calls of step 5 were run with
near-cli-rs 0.31.1 against it. The near-cli-rs chains for steps 3 and 4 and for the key deletion were not themselves run.

```sh
# 1. Build the wasm.
make -C registry build
WASM=target/wasm32-unknown-unknown/release/registry.wasm

# 2. Create the contract account (testnet faucet pays for it; skip if you already have one).
near account create-account sponsor-by-faucet-service preflight-registry.testnet \
  autogenerate-new-keypair save-to-keychain network-config testnet create

# 3. Deploy and initialise in ONE transaction, so nobody can call `new` between the two.
near contract deploy preflight-registry.testnet use-file $WASM \
  with-init-call new json-args '{"auditors":["preflight-auditor.testnet"]}' \
  prepaid-gas '100 Tgas' attached-deposit '0 NEAR' \
  network-config testnet sign-with-keychain send

# 4. An auditor publishes a verdict (the deposit pays for storage; the excess is refunded).
near contract call-function as-transaction preflight-registry.testnet publish_verdict \
  json-args '{"code_hash":"<base58 sha256 of the wasm>","status":"Unsafe","rule_ids":["PF001"],"report_url":"https://example.com/report.json","report_sha256":"<64 lowercase hex>"}' \
  prepaid-gas '100 Tgas' attached-deposit '0.01 NEAR' \
  sign-as preflight-auditor.testnet network-config testnet sign-with-keychain send

# 5. Anyone reads it back.
near contract call-function as-read-only preflight-registry.testnet get_verdict \
  json-args '{"code_hash":"<base58 sha256 of the wasm>"}' network-config testnet now
near contract call-function as-read-only preflight-registry.testnet get_auditors \
  json-args '{}' network-config testnet now
```

The contract has no upgrade method, but the account that hosts it can still redeploy code with its own key. To make
the registry truly immutable, delete its keys once you have checked step 5. This cannot be undone:

```sh
near account list-keys preflight-registry.testnet network-config testnet now
near account delete-keys preflight-registry.testnet public-keys <ed25519:...> \
  network-config testnet sign-with-keychain send
```
