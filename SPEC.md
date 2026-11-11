# Preflight interface contract

Every lane builds against this file. If you need it to change, tell the integrator; do not diverge silently.

## 1. Directory ownership

| Path | Owner | Rule |
| --- | --- | --- |
| `scanner/src/rules/pfNNN_*.rs`, `fixtures/pfNNN_*/`, `exploits/tests/pfNNN_*.rs` | the rule lane for `PFNNN` | Add files only; a rule is exactly these three paths plus one row in the README rules table (section 5). |
| `scanner/` (everything else), `exploits/src/`, root files (`Cargo.toml`, `Cargo.lock`, `Makefile`, `Dockerfile`, `rust-toolchain.toml`, `.cargo/`, `README.md`, `SPEC.md`) | integrator | Rule lanes touch only their README table row. |
| `registry/` | registry lane | Own `Makefile` (`build`, `test`), own `Cargo.lock`. |
| `guard/` | guard lane | Own `Makefile` (`build`, `test`). |
| `web/`, `web-scan/`, `scanner/src/memory.rs` | web lane | `web/` has its own `Makefile` (`build`, `test`). `web-scan/` is the wasm crate the page loads; `memory.rs` is `scan_files`, its entry point. |

The root `Makefile` calls `make -C registry|guard|web build|test`, so those lanes never edit it. `Cargo.lock`
files are generated: on a merge conflict take either side and rebuild. They are committed and every cargo
command in the `Makefile` uses `--locked`.

## 2. Build constraints (read before touching Rust)

- The compiler is pinned in `rust-toolchain.toml` (1.95.0, near-sdk 5.30's MSRV). rustup installs it and the
  `wasm32-unknown-unknown` target on first use. An exported `RUSTUP_TOOLCHAIN` overrides the pin; the `Makefile`
  unsets it, plain `cargo` does not.
- near-sdk refuses to compile for the host. Contract crates (`fixtures/*/*`, `registry/`) build only with
  `--target wasm32-unknown-unknown`, which is why they are separate cargo workspaces (`fixtures/Cargo.toml`,
  `registry/Cargo.toml`) and `cargo build --workspace` at the root (scanner, exploits) always works.
  Contract unit tests run natively with `near-sdk = { features = ["unit-testing"] }` as a dev-dependency.
- `.cargo/config.toml` gives every wasm32 build the flags `cargo near build` uses (`--cfg near`, `-C link-arg=-s`).
- Sandbox tests need network on first run: `near-sandbox` downloads the nearcore 2.14.0 binary during the build.
  That binary needs glibc 2.39 or newer (Ubuntu 24.04, Debian 13); on older systems the tests fail with
  "Could not startup and run sandbox node".

## 3. Scanner

### Report JSON (`preflight --json <path>`)

`schema_version` is 1. Any breaking change bumps it. Findings are sorted by `file`, `line`, `column`, `rule_id`.

```json
{
  "schema_version": 1,
  "tool": { "name": "preflight", "version": "0.1.0" },
  "target": "fixtures/pf001_callback/vulnerable",
  "summary": {
    "files_scanned": 1,
    "test_files_skipped": 0,
    "findings": 1,
    "by_severity": { "info": 0, "low": 0, "medium": 0, "high": 1, "critical": 0 }
  },
  "findings": [
    {
      "rule_id": "PF001",
      "title": "Callback not marked #[private]",
      "severity": "high",
      "file": "src/lib.rs",
      "line": 60,
      "column": 12,
      "item": "Escrow::on_release",
      "message": "`Escrow::on_release` is scheduled on the contract itself with `ext(..)` but is not marked `#[private]`, so any account can call it directly",
      "help": "add #[private] to the callback so only the contract itself can call it"
    }
  ]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `target` | string | The path that was scanned, as given on the command line. |
| `summary.by_severity` | object | All five severities are always present, zero included. |
| `findings[].rule_id` | string | `PF` and three digits. Stable forever. |
| `findings[].severity` | string | One of `info`, `low`, `medium`, `high`, `critical`. |
| `findings[].file` | string | Relative to the scanned directory (to its parent directory when `target` is a file), `/`-separated. |
| `findings[].line`, `column` | integer | 1-based; column counts characters. |
| `findings[].item` | string | The code item at fault, such as `Type::method`. |
| `findings[].message` | string | What is wrong here. Specific to this finding. |
| `findings[].help` | string | How to fix it. The same text for every finding of a rule. |

### CLI

`preflight [--json] <path>`, where `path` is a `.rs` file or a directory. Exit status: `0` no findings, `1` one or
more findings, `2` the scan could not run (unreadable path, a file that does not parse, no `.rs` file to read). A
file that does not parse fails the whole scan on purpose: a file skipped silently is a file nobody audited, and a
scan that read nothing is never a clean one.

Directories named `target` and dot-directories are skipped; symlinks are not followed. So is test code: the files
below a `tests`, `compilation_tests` or `benches` directory that is a direct child of a directory holding a
`Cargo.toml`, unless that directory (or one below it) holds a `Cargo.toml` of its own, which is a crate and is read;
a `src/tests` module is production code and is read too, and so is a file the crate's manifest names as `[lib] path` or
`[[bin]] path`. `summary.test_files_skipped` counts the skipped files. A file set
that is not on disk (the web page's pasted files and GitHub trees, `scan_files`) is cut by the same rule over the paths
given, with the `Cargo.toml` files among them: the page shows the count, and says in its result sentence that those files were skipped, when it is above zero, and a set that leaves no
`.rs` file fails the scan with the same message, never a clean report.
Files are grouped into crates by their nearest `Cargo.toml`, and a rule sees one whole crate at a time.

### The rule trait

```rust
pub trait Rule: Sync {
    fn id(&self) -> &'static str;        // "PF001"
    fn title(&self) -> &'static str;     // shown in reports
    fn severity(&self) -> Severity;      // Info | Low | Medium | High | Critical
    fn help(&self) -> &'static str;      // how to fix, one sentence
    fn check(&self, krate: &Crate) -> Vec<Finding>;
    fn finding(&self, file: &SourceFile, span: Span, item: String, message: String) -> Finding; // provided
}
```

`Crate { files: Vec<SourceFile>, manifest: Option<Manifest>, imported_macros: Vec<syn::ItemMacro> }` and `SourceFile { path: String, ast: syn::File }`.
`manifest` is the crate's parsed `Cargo.toml` plus the workspace root's (`Manifest { package, workspace_root }`, both
`toml_edit::DocumentMut`); it is `None` for a scanned single file or a directory with no `Cargo.toml`, and for
`Crate::from_sources`, where a test attaches one with `with_manifest`. `imported_macros` holds the `#[macro_export]` macros of the
crates in the same scan that this crate depends on by `path` (filled by the scan; empty for `from_sources`): definitions a rule may
follow by name, never code to report. Build findings only with
`self.finding(..)`: it fills `rule_id`, `title`, `severity`, `help` and the position from the rule, so they cannot
disagree with it. Unit-test a rule on inline source with `Crate::from_sources([("src/lib.rs", "...")])`.
`scanner/src/rules/pf001_callback.rs` is the worked example.

### Registering a rule

Add `scanner/src/rules/pfNNN_<slug>.rs` containing `pub static RULE: <your type>;`. That is the whole
registration: `scanner/build.rs` declares the module and lists `RULE` in `rules::ALL`. A file name that is not
`pfNNN_<lowercase slug>.rs` fails the build, and unit tests fail if an id does not match its file name, ids repeat,
or the README rules table has no row for the id.

### Deployed contracts (`preflight account`)

The second mode checks a contract that is already on chain, by account id, for the case where the source is not
available. Code: `scanner/src/deployed/`; entry point `preflight::deployed::check_account`.

```
preflight account <account_id> [--rpc <url>] [--json]
```

`account_id` is validated with `near-account-id` (the official rules: 2 to 64 characters, lowercase alphanumeric
parts joined by `.`, `-` or `_`) before any request. `--rpc` defaults to `https://free.rpc.fastnear.com`, a free
mainnet endpoint listed at docs.near.org/api/rpc/providers that needs no key; it must be an `http(s)` URL. Exit
status: `0` no finding of severity `low` or above, `1` at least one, `2` the account id or URL is invalid, the
account does not exist, or it has no contract code (nothing to check), `3` the chain could not be read. Findings of
severity `info` are printed and counted in the summary but leave the status at `0`. A report is printed only when
every read succeeded: a contract that could not be read is exit `2` or `3` with a message on stderr and nothing on
stdout, never an empty report. `--rpc` may carry an API key in its path; the report shows only scheme, host and port.

**Read-only.** Every request is one of: `query` with `request_type` `view_account`, `view_code`,
`view_access_key_list`, `view_state` or `call_function` (a view call the node runs without a transaction, used
only for `contract_source_metadata`), or `EXPERIMENTAL_protocol_config`. There is no transaction, key or signing
code. The first read asks for the latest `final` block; every later read is pinned to that block's hash, and a
response that does not carry that `block_hash` is rejected, so one report describes one block.

**Failure handling.** Each request has a 30 second timeout, the whole run is stopped after 120 seconds (checked
before each request, so a run can overshoot by at most one request; exit `3`), no redirects are followed, and
proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are not used. Timeouts, connection
failures, HTTP 429 (named as rate limiting), other non-200 statuses, bodies that are not valid JSON-RPC, a response
id that is not ours, a JSON-RPC `error` object (its `cause.name` shown, such as `UNKNOWN_BLOCK`), missing or
ill-typed fields, wasm that does not match the hash the node reports (SHA-256, base58; for an account that names a global contract by
hash, also that hash) or that does not parse, and
an access-key permission Preflight does not know, are all errors. Response bodies are capped (8 MiB for `view_code`:
the protocol allows 4 MiB of wasm, `max_contract_size`; 4 MiB for everything else) and an over-long body is an
error, not a truncated read. Text from the network (such as a contract's NEP-330 `link`) has control characters (Unicode category Cc), the
zero-width and direction-changing characters U+200B to U+200F, U+202A to U+202E, U+2060 to U+2069, U+061C and U+FEFF,
and the line and paragraph separators U+2028 and U+2029 replaced by `?`, and is cut, before it is printed or put in
the JSON. A rejected `--rpc` value is not echoed in the error, since its path may carry an API key.
The only conditions that are not errors are the two a check can truthfully report: a state too large for the node
to read (`not_evaluated`, below) and a contract whose metadata method fails (a PFW03 finding).

**Global contracts.** An account whose code is a global contract is checked on the code `view_code` returns, and
the two kinds the node reports in `view_account` are kept apart. `global_contract_hash`: the code is fixed by its
hash, so the read fails unless the code received hashes to it; the report says "code is the global contract with
hash X, which cannot change". `global_contract_account_id`: the code is whatever the publishing account last
published; the report says "code follows the global contract published by X; X can replace it (not checked)".
An account naming both is an error. In the JSON they are the separate fields `account.global_contract_hash` and
`account.global_contract_account_id`, each `null` when it does not apply.

#### Report JSON (`--json`)

`schema_version` is 1; any breaking change bumps it. `kind` is `"deployed"`, which no source-scan report has.

```json
{
  "schema_version": 1,
  "kind": "deployed",
  "tool": { "name": "preflight", "version": "0.1.0" },
  "target": "shop-vulnerable.preflight-guard.testnet",
  "rpc": "https://test.rpc.fastnear.com",
  "block": { "height": 277167263, "hash": "..." },
  "account": {
    "code_hash": "BXd5idTXSnC7WRfxHmi7z4crw2F5WXQJ6MZUEv8DfnnY",
    "code_bytes": 198307,
    "exported_functions": 20,
    "amount": "121366701486467892950729614",
    "locked": "0",
    "storage_usage": 2994659,
    "global_contract_hash": null,
    "global_contract_account_id": null
  },
  "summary": { "findings": 3, "by_severity": { "info": 2, "low": 0, "medium": 1, "high": 0, "critical": 0 } },
  "findings": [
    {
      "rule_id": "PFW01",
      "title": "Access keys that can change the contract",
      "severity": "medium",
      "item": "shop-vulnerable.preflight-guard.testnet",
      "message": "this account has 1 full-access key: ed25519:...",
      "read": "RPC query view_access_key_list for the account (every page), at the block shown in the report",
      "limits": "It shows that a key exists, not who holds it or how it is guarded: ...",
      "help": "If the contract must not change, delete the full-access keys ..."
    }
  ],
  "not_evaluated": []
}
```

`account.code_hash` is the SHA-256 of the wasm that was read, in the base58 form the registry uses as `code_hash`.
Amounts are decimal strings of yoctoNEAR. `findings[].read` and `limits` are the same text for every finding of a
check: what was read, and what the finding does not prove. `not_evaluated` lists `{ "rule_id", "reason" }` for each
check that reached no verdict; a clean report with entries here is not a pass for those checks.

#### Checks

| Id | Severity | Reads | A finding means | It does not prove |
| --- | --- | --- | --- | --- |
| `PFW01` | medium | `view_access_key_list`, all pages | A full-access key exists (its holder can deploy new code, delete the account or add keys); or a function-call key whose receiver is the account itself has an empty method list (it can call, with no attached deposit, any method, including ones guarded only by `#[private]`). Gas keys with full access count as full access. | Who holds the key or what guards it; intended upgradability. |
| `PFW02` | info | `view_code` export names | Exports named `upgrade`, `update_contract`, `migrate`, `state_migrate` or starting `set_owner`. | What they do or who may call them; renamed methods are missed. |
| `PFW03` | info / low | `view_code` exports, then `call_function contract_source_metadata` (NEP-330) | info: metadata declared (version, link; self-declared, not compared with the code hash). info: not exported (NEP-330 is optional, so this check cannot tie the code to published source from chain data alone). low: exported but failing or not JSON, or declaring neither version nor link. | That the declared source matches the code, or that absence is unsafe. |
| `PFW04` | medium | `view_code` exports, `view_state` with prefix `STATE` and `limit: 1` and, only if there is no `STATE` key, `view_state` with an empty prefix and `limit: 1` | An init-style export (`new`, `init`, `initialize`, `new_default_meta`) and no state at all. State present but no `STATE` key (the key near-sdk stores state under) is `not_evaluated` (a custom storage layout). If the node answers `TOO_LARGE_CONTRACT_STATE`, or the one entry exceeds the response cap, the check is `not_evaluated`, never a finding. A contract with no init-style export is not examined. | That the contract is uninitialized (one that keeps no state or writes it only on first use looks the same), or that the init method is callable by anyone. |
| `PFW05` | low | `view_account` (`amount`, `locked`, `storage_usage`), `EXPERIMENTAL_protocol_config` (`runtime_config.storage_amount_per_byte`, read from the node, 10^19 yoctoNEAR on mainnet) | `amount + locked` is below `storage_usage * storage_amount_per_byte`, the balance the protocol requires (`check_storage_stake` in nearcore), except zero-balance accounts (NEP-448, at most 770 bytes: `ZERO_BALANCE_ACCOUNT_STORAGE_LIMIT` in nearcore 2.14.0 `runtime/runtime/src/verifier.rs`, line 25), which never produce a finding. | Where the project's funds are; one account at one block. |
| `PFW06` | low / info | `view_code` export names | low: `ft_transfer_call` exported and no export contains `resolve` (NEP-141 requires a resolver but allows any name). info: `ft_transfer` exported without `storage_deposit` (NEP-145, a separate standard; the token may register accounts another way or need no registration). | That any exported method is correct. |

PFW07 (host-function imports: every sampled contract imports `deploy_contract` and friends) and PFW08 (global
contract identity) are not implemented; the ids stay unused.

Adding a check: a file `scanner/src/deployed/checks/pfwNN_<slug>.rs` with a `static CHECK` implementing `Check`
(`id`, `title`, `read`, `limits`, `help`, `check(&Snapshot)`) and one line in `checks/mod.rs`. Checks are pure
functions of a `Snapshot`, so a unit test builds one with `Snapshot::sample()` and changes a field.

#### Testing seam

All network access goes through `trait Transport { fn post(&self, request, max_bytes) -> Result<Vec<u8>, TransportError>;
fn endpoint(&self) -> &str; }`. `HttpTransport` (ureq with rustls, no system OpenSSL) is the production one. Tests
replay real mainnet responses recorded in `scanner/tests/data/*.json` through a `Transport` of their own, and
exercise `HttpTransport` and the binary against a loopback server; nothing in the test suite reaches the network.

### In the browser (`web/`)

`preflight::scan_files(target, &[(path, text)], &[Option<&str>], rules)` is `scan` for files already in memory: the
same crate grouping (nearest `Cargo.toml`), the same manifests (the crate's and its workspace root's, so PF022 sees
what it sees on disk), skip rules and ordering, so its report serializes to the same JSON byte for byte (a test
compares it with the CLI's for every fixture pair). The third argument is the `Cargo.toml` text of each directory
above the scanned one, nearest first, `None` where there is none: the on-disk scan finds a workspace root above the
target by walking up, and a caller with no disk passes what it has. Files with no `Cargo.toml` get no manifest, so
PF022 stays silent on them. `web-scan/` wraps it as a WebAssembly module with no imports
(request JSON in, report JSON or a message out) and depends on `preflight` with `default-features = false`: the
`cli` feature (the binary's `clap`, and `deployed`) and the `deployed` feature (the live-account mode and its HTTP
client), both on by default, are off, so no network or argument-parsing code is compiled into the module. The module
is linked with an 8 MiB stack (`web-scan/build.rs`), enough for about 2000 levels of nested blocks, parentheses or
`match`; deeper code ends the scan with a message that says so. `web/` is a static page, with no backend and no bundler, that loads the module and fetches public
GitHub repositories from the visitor's own browser. `make -C web build|serve|test`; `file://` is not supported
because browsers refuse to load WebAssembly from it. The page states findings by severity and never gives an
allow, warn or block verdict (that is the guard's job, `guard/`).

## 4. Naming and fixtures

| Thing | Name | Example |
| --- | --- | --- |
| Rule id | `PFNNN`, next unused number | `PF001` |
| Rule file | `scanner/src/rules/pfNNN_<slug>.rs` | `pf001_callback.rs` |
| Fixture pair | `fixtures/pfNNN_<slug>/vulnerable`, `.../patched` | `fixtures/pf001_callback/vulnerable` |
| Fixture package | `pfNNN-<slug with hyphens>-{vulnerable,patched}` | `pf001-callback-vulnerable` |
| Exploit test | `exploits/tests/pfNNN_<slug>.rs` | `exploits/tests/pf001_callback.rs` |

A fixture is a near-sdk crate (`crate-type = ["cdylib", "rlib"]`, `near-sdk.workspace = true`, package fields
inherited from `fixtures/Cargo.toml`) that joins the fixtures workspace by directory glob. The patched crate
differs from the vulnerable one by the smallest change that fixes the bug. `scanner/tests/fixtures.rs` enforces:
every rule has a pair, `vulnerable` triggers the rule, `patched` triggers nothing, and the exploit test file exists.

An exploit test builds its fixtures with `exploits::build_fixture("pfNNN_<slug>", "vulnerable")` (returns the wasm
bytes), deploys them to a `near-workspaces` sandbox, and has two outcomes: the exploit succeeds against
`vulnerable`, and fails against `patched` while the legitimate path still works. See `exploits/tests/pf001_callback.rs`.

## 5. README rules table

One row per rule in `README.md`, with the rule id in the first cell: `| PFNNN | severity | what it catches | fixture | exploit |`.

## 6. Registry contract (`registry/`, near-sdk 5.30.1)

Stores one verdict per code hash. `code_hash` everywhere is the base58 SHA-256 of the deployed wasm bytes, the
form NEAR RPC uses for an account's `code_hash`.

```rust
#[near(serializers = [borsh, json])]
pub enum VerdictStatus { Safe, Warn, Unsafe }   // JSON: "Safe" | "Warn" | "Unsafe"

#[near(serializers = [borsh, json])]
pub struct Verdict {
    pub code_hash: String,
    pub status: VerdictStatus,
    pub rule_ids: Vec<String>,        // ids of the rules that fired, e.g. ["PF001"]; empty for Safe
    pub report_url: String,           // where the full scan report JSON is published
    pub report_sha256: String,        // lowercase hex SHA-256 of that report, so a reader can check it
    pub auditor: AccountId,           // set by the contract to the caller; not an argument
    pub published_at_ms: U64,         // set by the contract from the block timestamp
}

#[near]
impl Registry {
    #[init]
    pub fn new(auditors: Vec<AccountId>) -> Self;                      // allowlist fixed at init

    /// Panics unless the caller is in the allowlist. A later verdict for the same code_hash replaces the earlier.
    /// Payable: the caller attaches at least the cost of the storage the verdict adds; the excess is refunded.
    /// `Warn` and `Unsafe` carry at least one rule id, `Safe` none. `report_url` is http(s), at most 256 bytes.
    #[payable]
    pub fn publish_verdict(&mut self, code_hash: String, status: VerdictStatus, rule_ids: Vec<String>,
                           report_url: String, report_sha256: String);

    pub fn get_verdict(&self, code_hash: String) -> Option<Verdict>;  // view
    pub fn get_auditors(&self) -> Vec<AccountId>;                      // view
}
```

## 7. Guard (`guard/`, TypeScript, `strict`)

Before an agent calls or pays a contract it calls `checkContract`; `GuardedAgent.guardedCall` wraps the whole path
(policy, key, check, approval, log, sign, send). `guard/README.md` has the user-facing detail; this section is the
interface contract and the rules the code enforces. The code is `guard/src/`, the tests `guard/test/`.

### Interface

```ts
export type Decision = "allow" | "warn" | "block";

export interface GuardConfig {
  rpcUrl: string;       // NEAR JSON-RPC endpoint (GuardedAgent requires an http: or https: URL)
  registryId: string;   // account id of the registry contract
  timeoutMs?: number;   // per RPC query, 429 retries and waits included (one deadline), whole ms from 1 to 2147483647; default 10000; a timeout is a `block`
  rateLimitBackoffMs?: readonly number[];  // waits before each retry of a query answered with HTTP 429, all within `timeoutMs`; default [500, 1000, 2000, 4000]; at most 10; still 429 after the last is a `block`
}

export interface GuardResult {
  decision: Decision;
  contractId: string;
  codeHash: string | null;   // base58 SHA-256 of the wasm; null if there is no code or it could not be read
  verdict: Verdict | null;   // the registry's Verdict as JSON, validated (below)
  reasons: string[];         // why; never empty; every unsafe character escaped (below)
}

export function checkContract(contractId: string, config: GuardConfig): Promise<GuardResult>;

export interface Policy {
  allowedContracts: readonly string[];  // the only contracts the agent may call; every entry a valid account id
  maxDepositPerCall: bigint;            // yoctoNEAR
  maxTotalDeposit: bigint;              // yoctoNEAR, over the life of the GuardedAgent object (in memory)
}

export interface GuardedAgentOptions {
  accountId: string;
  signer: Signer | ((contractId: string) => Signer);   // near-api-js Signer; a function picks one key per contract
  guard: GuardConfig;
  policy: Policy;
  logPath: string;                                      // JSON-lines decision log
  approve?: (request: ApprovalRequest, guard: Readonly<GuardResult>) => boolean | Promise<boolean>;
  approveTimeoutMs?: number;                            // default 120000, whole ms from 1 to 2147483647
  allowFullAccessKey?: boolean;                         // default false
  now?: () => Date;                                     // clock for log timestamps
}

export class GuardedAgent {
  constructor(options: GuardedAgentOptions);
  guardedCall(request: { contractId: string; method: string; args?: Record<string, unknown> | Uint8Array;
                         deposit: bigint; gas: bigint }): Promise<{ guard: GuardResult; transaction: ExecutionOutcome }>;   // near-api-js callFunctionRaw result
}
export class RefusedError extends Error { readonly entry: LogEntry }   // nothing was signed or sent
```

### `checkContract`: decision table

The guard reads `view_account` (code hash and global-contract fields) and `view_code` (the wasm), hashes the wasm,
cross-checks it, and calls the registry's `get_verdict`, all at `finality: optimistic`. First match wins:

| Situation | `decision` |
| --- | --- |
| RPC or registry unreachable, times out, errors, or answers with malformed JSON or an unexpected shape | `block` (fail closed) |
| The wasm `view_code` returns does not hash to the hash the RPC reports, or to the account's own code hash | `block` |
| `view_account` has a global-contract field that is neither a string nor null, or a malformed `global_contract_hash` | `block` |
| `view_account` has a real local `code_hash` and also a global-contract field | `block` |
| `view_code` answers `NO_CONTRACT_CODE` but `view_account` claims code (a hash or a publisher) | `block` |
| The registry answers for another code hash, or any verdict field fails validation (below) | `block` |
| `view_account` answers `UNKNOWN_ACCOUNT` (no such account) | `allow` (nothing to audit), `codeHash: null` |
| `view_code` answers `NO_CONTRACT_CODE` and `view_account` claims no code | `allow` (nothing to audit), `codeHash: null` |
| Verdict `Unsafe` | `block` |
| Verdict `Warn` | `warn` |
| No verdict for this code hash | `warn` (unaudited, or changed since its audit) |
| Verdict `Safe` | `allow` |

Global contracts (answers the question this section used to leave open): for an account that uses one, `view_account`
reports `code_hash` as the all-zero hash and carries `global_contract_hash` (by hash) or `global_contract_account_id`
(by publisher); `view_code` resolves the global contract and returns its wasm (nearcore `view_account_contract_code`,
`runtime/runtime/src/state_viewer/mod.rs`, at tag 2.14.0). "No code" comes from `view_code`'s `NO_CONTRACT_CODE`,
never from the all-zero hash. A by-publisher contract can change under the account; the lookup on the current bytes
catches that.

`checkContract` does not throw for network or registry failures; those are `block` results. It throws a `TypeError`
only for an invalid `contractId`. The caller refuses to sign on `block` and asks a human on `warn`.

### `guardedCall`: stages and refusals

In this order; the first failure ends the call:

1. Validate the request (below). Failure: `TypeError`, nothing logged, queried or committed.
2. Local policy: a contract outside `allowedContracts`, a deposit above `maxDepositPerCall`, or a total above
   `maxTotalDeposit` is a `block`, before any RPC call.
3. Key check: the signing key's permission is read from the chain (`view_access_key`, optimistic). A full-access key
   is refused unless `allowFullAccessKey`; a function-call key scoped to another contract, lacking the method, or
   given a deposit is refused.
4. `checkContract`. `block` is refused. `allow` with `codeHash: null` is refused too (a function call to an account
   without code can only fail or reach code deployed after the check). `warn` goes to `approve`, which signs only by
   returning exactly `true`; no callback, any other value, a throw or no answer within `approveTimeoutMs` declines.
5. Append the `approved` line; if that fails, nothing is signed.
6. Sign; append the `sent` line just before the transaction is handed to the network (once per attempt: near-api-js
   retries on a stale nonce); send.

The arguments become bytes once, at step 1 (`JSON.stringify`, or a copy of a `Uint8Array`); every later stage and the
signature use that snapshot, never the caller's objects. A `ApprovalRequest` carries `argsBytes` (a fresh copy) and
`args`, the parsed and deep-frozen value, only when re-encoding it reproduces the bytes exactly. A deposit stays in the
total once the `sent` line is written; a refused call, or one that fails before the hand-off, releases it.

A refusal is a thrown `RefusedError` carrying `entry`, the sanitized object that was logged. Any exception between
step 2 and the `approved` line (a signer factory or `getPublicKey` that throws, a failed key lookup, an unreadable
log, a bug) becomes a `refused` line and a `RefusedError`; if that line cannot be written either, the `RefusedError`
is still thrown and its reasons say the decision could not be logged and why. An exception after `approved` and before
the hand-off writes `not_sent` (best effort) and rethrows the original error.

### Decision log

`GuardedAgentOptions.logPath` is a JSON-lines file, one object per line, never rewritten:

```ts
interface LogEntry {
  timestamp: string;                       // ISO 8601
  contract: string;
  method: string;
  deposit: string;                         // yoctoNEAR, decimal
  codeHash: string | null;
  decision: Decision;                      // the guard's decision; `block` also for a policy or key refusal
  outcome: "approved" | "sent" | "not_sent" | "refused";
  reasons: string[];
}
```

A call that passes validation ends in a terminal line that tells the truth about its last attempt: `refused` (nothing
signed), `sent` (the transaction was handed to the network; the money may be spent; one line per attempt handed to the
node, since near-api-js retries a stale nonce) or `not_sent` (the last attempt was not handed over: a failure before the
hand-off, or a retry whose signed transaction differed from the checked request, refused with a `RefusedError` after an
earlier `sent`). `approved` is the
intermediate line written before signing. One writer builds every line: it walks every string in the entry, nested
ones and keys included, and makes each printable once; no other code writes to the file. Writes of one file share one
in-process queue, one `appendFile` per line.

### Validation and limits

- Text from outside the process (RPC answers, registry fields, caller strings) is made printable exactly once, where it
  enters a log entry or a message: C0 and C1 controls, the Unicode line and paragraph separators, bidirectional
  controls, zero-width and other invisible characters (U+200B to U+200D, U+2060, U+FEFF, U+00AD, U+E0000 to U+E007F,
  filler characters), lone surrogates and the backslash become `\uXXXX`, and the text is cut to 500 characters ending in
  `...[truncated]`; the input is cut before it is escaped. An error thrown by a callback or a signer is described by one
  helper that cannot throw, whatever was thrown.
- A log line is at most 16384 bytes: at most 16 reasons are kept and trailing ones are dropped, with a
  `...[n more reasons omitted]` marker, until it fits.
- `contractId` (guard config, request, policy entries, `registryId`, `accountId`): a NEAR account id, 2 to 64
  characters, lowercase letters and digits with single `.`, `-`, `_` separators that cannot start, end or repeat.
- `method`: `[A-Za-z_][A-Za-z0-9_]*`, at most 256 characters. 256 is the chain's `max_length_method_name` (nearcore
  2.14.0, `core/parameters/res/runtime_configs/parameters.yaml`); the chain accepts any non-empty UTF-8 name within it,
  the guard is stricter on purpose.
- `deposit`, `gas`: non-negative `bigint`; `deposit` at most 2^128-1 and `gas` at most 2^64-1, the widths of the borsh
  `u128` and `u64` (larger values wrap silently when encoded, so they throw). Timeouts: whole milliseconds from 1 to 2147483647 (a Node timer overflows
  above that and fires at once).
- The signed transaction is decoded from its own encoding and sent only if signer, public key (the one the key check
  read), receiver, exactly one function-call action, method, argument bytes, gas and deposit equal the snapshot; else
  `not_sent` and a thrown `RefusedError`. The guard does not verify the signature, nor compare nonce and block hash
  (they do not change what the call does; the chain rejects bad values).
- Every registry verdict field is validated before it is used or shown, to the shape the registry contract enforces
  (`registry/src/validate.rs`): `status` one of `Safe`, `Warn`, `Unsafe`; `rule_ids` at most 32 distinct `PFnnn`, none
  for `Safe`, at least one otherwise; `report_url` starting `https://` or `http://`, at most 256 bytes, and (stricter than
  the registry) printable ASCII without spaces; `report_sha256` 64 lowercase hex; `auditor` a valid account id;
  `published_at_ms` a decimal string fitting a `u64`; `code_hash` equal to the one asked for. Anything else is a `block`
  whose reason names the field and never repeats its value.
- Not covered: a redeploy between check and send (the guard reads at the optimistic head, which narrows the window but
  cannot close it); cross-contract calls (only the direct receiver is checked); a lying RPC endpoint or registry; two
  processes appending to one log file.
