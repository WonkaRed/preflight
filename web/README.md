# Preflight in the browser

A static page. At the top is the Swap: one NEAR testnet address whose code a button swaps between a vulnerable and a patched build, with a check that trusts the address (always ALLOW) beside Preflight, which looks the verdict up by the hash of the deployed code (BLOCK, then ALLOW). Below it the page unfolds as you scroll: a scripted agent obeying a poisoned page (it starts playing when it comes into view), how the three parts work, then the scanner, which runs where the visitor is: paste Rust contract source, pick a bundled vulnerable example
(and its patched twin), or name a public GitHub repository, and read the findings, each linked to its rule's proof (the
fixture pair and the sandbox exploit test). No server, no account, no install. The Rust scanner is compiled to
WebAssembly; the page is plain ES modules with no bundler.

```
make -C web build    # compile the scanner to wasm and assemble web/dist/
make -C web serve    # build, then serve dist/ at http://127.0.0.1:8000/ (PORT=... to change)
make -C web test     # build, then run the tests
```

`web/dist/` is the whole site: upload it to any static host as is. It is a build output, so it is not committed, and
`make -C web dist` is the same as `build`. Browsers will not load WebAssembly from `file://`; serve the folder.

## How it works

| Path | What |
| --- | --- |
| `../web-scan/` | The wasm crate (`preflight-web`). Source files in, the exact JSON `preflight --json` prints out; also the rule list. No imports, no pointer JavaScript must free. |
| `../scanner/src/memory.rs` | `scan_files`: the scanner's entry point for files already in memory (the filesystem scan's twin). |
| `src/scanner.js` | Compiles the module once and gives every scan a fresh instance, so a crash or a big repository cannot affect the next scan. |
| `src/scan-worker.js`, `src/scan-client.js` | The scan runs in a Web Worker, so the page keeps painting and Cancel works during a large scan (4 MB of source takes seconds). Cancel and a newer scan end the running one by terminating its worker. |
| `src/session.js` | What a scan start, finish or failure does to the page: the pane shows "Scanning owner/repo" at once, the newest scan owns the pane, and every failure except being replaced is shown as a problem. |
| `src/github.js` | Public repository reader: one request for the commit the ref points at and one for that commit's file list (both api.github.com), then one raw.githubusercontent.com request per `.rs` and `Cargo.toml` file, all pinned to that commit (plus the `Cargo.toml` of each folder above a sub-path, where the workspace's build profile usually is). No token. Limits are in `LIMITS` (a file over 1 MB is never downloaded, manifests included) and every cut, and every skipped Git submodule, is shown to the visitor. |
| `src/report.js` | Report validation, severity and verdict rules, and the DOM builders. Scan text reaches the page only as text nodes, after control and bidirectional characters are replaced. |
| `src/near.js` | The little of NEAR the Swap needs, with no library: base58, Borsh for one function-call transaction, and an ed25519 signature from WebCrypto. `test/near.test.mjs` checks every byte against a transaction built and signed by near-api-js 7.4.0 (`test/data/swap-vector.json`). |
| `src/swap.js` | The Swap's controller: reads the chameleon's code hash and the registry verdict over RPC (every request goes through one transport that fails over between the endpoints; see below), sends `flip`, polls, and falls back to the recording when the RPC is down or the demo key can no longer pay; reads every 5 s for two minutes after load, a click or the tab coming back, then every 15 s, and never in a hidden tab. Config validation (`readConfig`) and the recording parser (`parseRecorded`) live here. No DOM. |
| `src/swap-view.js` | `viewModel` (state to plain strings, tested directly), `paint` (writes them into the section as text) and `mountSwap`. |
| `src/swap-agent.js` | The Swap's agent panel: `agentScript` turns the code hash and registry verdict the Swap already read into a scripted agent's refused or allowed call and the guard's decision-log line (built by `guardEntry` in `swap.js`, the shape of `guard/src/log.ts`), and `mountAgent` plays it. No model runs, nothing is signed or sent. |
| `src/swap-config.js` | The one place the Swap is configured; see below. |
| `swap-recorded.json` (in `dist/`) | A copy of `../demo/swap/recorded.json`, written by `tools/build.mjs` (the JSON `null` when the file is absent). |
| `src/page.js` | Scroll reveal (a section is hidden only once an `IntersectionObserver` is watching it, never with reduced motion or without the observer), `whenSeen` (the agent waits to be on screen) and click-to-copy for hashes. Hashes show their first characters and carry the whole value in `title`. |
| `src/app.js`, `index.html`, `style.css` | The page. |
| `src/config.js` | `REPO_TREE_URL`: where the proof links point (this repository's `main` tree on GitHub). A fork sets its own; left empty, the paths show as plain text. |
| `tools/site-data.mjs` | Reads `fixtures/` and `exploits/` at build time: the bundled examples and each rule's proof paths. Add a rule with its fixtures and exploit test and its links appear with no change here. |
| `tools/build.mjs` | Assembles `dist/`. |
| `test/` | Node's test runner against the real built wasm (`scanner`), the renderer (`report`), the Swap's serializer (`near`), controller (`swap`, against a fake NEAR node in `swap-chain.mjs`) and view (`swap-view`), the GitHub reader with a fake `fetch` (`github`), the scan worker's client (`scan-client`), the page's scan lifecycle (`session`) and the built folder (`dist`). |

The tests check the wasm output against the native command line, byte for byte, for both variants of every fixture and for a
tree of several crates (`test/data/crates`: a build script, a nested workspace root, a loose file).

The one place the two differ is depth: the wasm module has an 8 MiB stack (`../web-scan/build.rs`), enough for about 2000
levels of nested blocks, parentheses or `match`. Code nested deeper ends the scan with "nested too deeply for the
in-browser build"; scan it with `preflight` on the command line.

## Configuring the Swap

Fill `src/swap-config.js`, then `make -C web build`. With `chameleonId`, `switchId`, `registryId` and `flipKey` empty (the shipped state) the page makes no network call and shows the recording, labeled as recorded.

| Field | What |
| --- | --- |
| `chameleonId` | The account whose code the button swaps. |
| `switchId` | The contract with `flip()` and `status()`. |
| `registryId` | The registry holding the verdicts for both builds (`get_verdict`). |
| `flipKey` | `ed25519:` secret key, public on purpose: a function-call key limited to `flip` with a small allowance. |
| `flipSignerId` | The account that holds that key; empty means `switchId`. |
| `flipGasTgas` | Gas attached to `flip` (default 150; the switch needs at least 100). |
| `rpcUrls` | NEAR testnet RPC endpoints, in order of preference (each origin also in the page's CSP, and each must send `Access-Control-Allow-Origin`). A request tries them in turn, starting with the one that answered last, and moves on at once after a network error, a CORS-shaped failure (a throttled 429 carries no CORS header, so the browser reports a network failure), a 5xx, or an answer that is not NEAR's JSON-RPC. Only when all fail in one round does a read pause 400 ms and go round once more; a transaction is sent as the same signed bytes to each endpoint and, when no answer comes back, looked up by its hash before anything is called failed. |
| `explorerUrl` | The explorer behind every link. |

`status()` is read as `{ vulnerable: { code_hash }, patched: { code_hash }, flips, next_flip_ms }` and the registry's `get_verdict(code_hash)` as `{ code_hash, status: Safe | Warn | Unsafe, rule_ids }` or `null`. The page checks the code hash by hashing `view_code` itself, so a wrong answer from the RPC cannot show a verdict for code that is not deployed. A hash with no verdict shows WARN, as the guard does.

## Linking to a scan

`index.html?repo=owner/name` opens the GitHub tab and scans at once; `&ref=<branch, tag or commit>` and
`&path=<folder>` narrow it, for example `?repo=near/near-sdk-rs&path=examples/lockable-fungible-token`. Without a token a
scan costs 2 of the 60 requests per hour GitHub gives each IP address on api.github.com (the file downloads come from
raw.githubusercontent.com, whose limits GitHub does not publish), so about 30 scans an hour.

## Safety

Everything a scan returns, and everything GitHub sends, is untrusted. The code has no `innerHTML`, and the page's
Content-Security-Policy allows scripts and styles from the page's own folder only and network requests to the page's
folder, `api.github.com`, `raw.githubusercontent.com` and the Swap's RPC endpoints, `test.rpc.fastnear.com` and `near-testnet.drpc.org`. No fonts, scripts or images come from anywhere else. The policy is a
`<meta>` tag, which a worker script does not inherit: a host that can set response headers should send the same policy as a
`Content-Security-Policy` header too (the worker is loaded from the page's own folder and makes no requests).

The Swap's key ships to every visitor, so it must be worth nothing: a function-call key on the switch limited to `flip`, a
small gas allowance, testnet only. Transactions are signed in the browser with WebCrypto's Ed25519 (recent browsers only); a browser without it shows that and sends nothing. Everything from the RPC and the recording reaches
the page as text, and links are built only from a validated hash or account id plus `explorerUrl`.

## What the headline says

The headline states what was found, by severity, such as "4 high findings" or "1 critical and 2 low findings". It
never says whether to pay, trust or ship a contract. The count comes from the findings, never from a report's own
summary. The panel's tint follows the worst severity (red for high or critical, amber for the rest).

| Findings | Headline |
| --- | --- |
| none | **No known rule fired.** It does not claim the contract is safe, only that no rule matched. |
| none, and no file was read | **Nothing was scanned.** Amber, never clear: for example every Rust file was over the 1 MB limit. |
| any | The count by severity, then: each is a pattern match with a proof on a test contract; read each before trusting or dismissing it. |
