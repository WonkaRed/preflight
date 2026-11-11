# Preflight in the browser

A static page that runs the scanner where the visitor is: paste Rust contract source, pick a bundled vulnerable example
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
| `src/app.js`, `index.html`, `style.css` | The page. |
| `src/config.js` | `REPO_TREE_URL`: where the proof links point (this repository's `main` tree on GitHub). A fork sets its own; left empty, the paths show as plain text. |
| `tools/site-data.mjs` | Reads `fixtures/` and `exploits/` at build time: the bundled examples and each rule's proof paths. Add a rule with its fixtures and exploit test and its links appear with no change here. |
| `tools/build.mjs` | Assembles `dist/`. |
| `test/` | Node's test runner against the real built wasm (`scanner`), the renderer (`report`), the GitHub reader with a fake `fetch` (`github`), the scan worker's client (`scan-client`), the page's scan lifecycle (`session`) and the built folder (`dist`). |

The tests check the wasm output against the native command line, byte for byte, for both variants of every fixture and for a
tree of several crates (`test/data/crates`: a build script, a nested workspace root, a loose file).

The one place the two differ is depth: the wasm module has an 8 MiB stack (`../web-scan/build.rs`), enough for about 2000
levels of nested blocks, parentheses or `match`. Code nested deeper ends the scan with "nested too deeply for the
in-browser build"; scan it with `preflight` on the command line.

## Linking to a scan

`index.html?repo=owner/name` opens the GitHub tab and scans at once; `&ref=<branch, tag or commit>` and
`&path=<folder>` narrow it, for example `?repo=near/near-sdk-rs&path=examples/lockable-fungible-token`. Without a token a
scan costs 2 of the 60 requests per hour GitHub gives each IP address on api.github.com (the file downloads come from
raw.githubusercontent.com, whose limits GitHub does not publish), so about 30 scans an hour.

## Safety

Everything a scan returns, and everything GitHub sends, is untrusted. The code has no `innerHTML`, and the page's
Content-Security-Policy allows scripts and styles from the page's own folder only and network requests to the page's
folder, `api.github.com` and `raw.githubusercontent.com`. No fonts, scripts or images come from anywhere else. The policy is a
`<meta>` tag, which a worker script does not inherit: a host that can set response headers should send the same policy as a
`Content-Security-Policy` header too (the worker is loaded from the page's own folder and makes no requests).

## What the headline says

The headline states what was found, by severity, such as "4 high findings" or "1 critical and 2 low findings". It
never says whether to pay, trust or ship a contract. The count comes from the findings, never from a report's own
summary. The panel's tint follows the worst severity (red for high or critical, amber for the rest).

| Findings | Headline |
| --- | --- |
| none | **No known rule fired.** It does not claim the contract is safe, only that no rule matched. |
| none, and no file was read | **Nothing was scanned.** Amber, never clear: for example every Rust file was over the 1 MB limit. |
| any | The count by severity, then: each is a pattern match with a proof on a test contract; read each before trusting or dismissing it. |
