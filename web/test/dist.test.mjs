// The built folder web/dist: self-contained, current, and free of anything the page's safety claims rule out.
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { test } from 'node:test';
import { REPO_TREE_URL } from '../src/config.js';
import { parseRecorded } from '../src/swap.js';
import { SWAP_CONFIG } from '../src/swap-config.js';
import { recordedSwaps, siteData } from '../tools/site-data.mjs';
import { DIST } from './helpers.mjs';

const SRC = new URL('../src/', import.meta.url);
const read = (base, name) => readFileSync(new URL(name, base), 'utf8');
const sources = readdirSync(SRC).filter((name) => /\.(html|js|css)$/.test(name));
const html = read(SRC, 'index.html');

test('dist holds every source file unchanged, the wasm module and the generated data', () => {
  assert.deepEqual(readdirSync(DIST).sort(), [...readdirSync(SRC), 'preflight.wasm', 'site-data.json', 'swap-recorded.json'].sort());
  for (const name of readdirSync(SRC)) assert.equal(read(DIST, name), read(SRC, name), `${name} is stale: run make -C web build`);
  assert.deepEqual(JSON.parse(read(DIST, 'site-data.json')), siteData(), 'site-data.json is stale: run make -C web build');
  assert.equal(read(DIST, 'swap-recorded.json'), recordedSwaps(), 'swap-recorded.json is stale: run make -C web build');
});

test('everything the page loads is in dist, and nothing is loaded from elsewhere', () => {
  const wanted = new Set([...html.matchAll(/(?:src|href)="((?!https:)[^"#]+)"/g)].map((m) => m[1]));
  for (const name of sources.filter((n) => n.endsWith('.js'))) {
    for (const m of read(SRC, name).matchAll(/from '\.\/([\w.-]+)'|(?:fetch|compileScanner)\('([\w.-]+)'|new URL\('([\w.-]+)'/g)) wanted.add(m[1] ?? m[2] ?? m[3]);
  }
  assert.ok(wanted.has('app.js') && wanted.has('preflight.wasm') && wanted.has('site-data.json') && wanted.has('scan-worker.js'));
  const present = readdirSync(DIST);
  for (const name of wanted) assert.ok(present.includes(name), `${name} is referenced but not in dist`);
  const csp = html.match(/Content-Security-Policy" content="([^"]+)"/)[1];
  const connect = csp.match(/connect-src ([^;]+);/)[1].split(' ');
  assert.deepEqual(connect, ["'self'", 'https://api.github.com', 'https://raw.githubusercontent.com', ...SWAP_CONFIG.rpcUrls.map((url) => new URL(url).origin)], 'the Swap\'s RPC origins, and only they, are allowed by the CSP');
  assert.match(csp, /^default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'/);
  for (const name of sources) {
    const hosts = [...read(SRC, name).matchAll(/https?:\/\/([\w.-]+)/g)].map((m) => m[1]);
    for (const host of hosts) assert.ok(['api.github.com', 'raw.githubusercontent.com', 'github.com', 'test.rpc.fastnear.com', 'near-testnet.drpc.org', 'testnet.near.rocks'].includes(host), `${name} mentions ${host}`);
  }
  assert.doesNotMatch(read(SRC, 'style.css'), /@import|url\(/);
});

test('no markup sinks, no inline script or style, no event-handler attributes', () => {
  for (const name of sources.filter((n) => n.endsWith('.js'))) {
    assert.doesNotMatch(read(SRC, name), /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|setTimeout\(['"`]|DOMParser|createContextualFragment/, name);
  }
  assert.deepEqual([...html.matchAll(/<script\b([^>]*)>/g)].map((m) => m[1].trim()), ['type="module" src="app.js"']);
  assert.doesNotMatch(html, /\sstyle=|<style\b|\son[a-z]+=/i);
});

test('the wasm module needs no imports and exports the documented interface', async () => {
  const module = await WebAssembly.compile(readFileSync(new URL('preflight.wasm', DIST)));
  assert.deepEqual(WebAssembly.Module.imports(module), []);
  const exported = WebAssembly.Module.exports(module);
  assert.deepEqual(exported.filter((e) => e.kind === 'function').map((e) => e.name).sort(),
    ['preflight_input', 'preflight_output_len', 'preflight_output_ptr', 'preflight_rules', 'preflight_scan']);
  assert.ok(exported.some((e) => e.kind === 'memory' && e.name === 'memory'));
  assert.ok(statSync(new URL('preflight.wasm', DIST)).size < 3 * 1024 * 1024, 'the module grew past 3 MB; every visitor downloads it');
});

test('the copy states what the scan is not and hard-codes no rule count', () => {
  assert.match(html, /Not an audit/);
  assert.match(html, /not that the contract is safe/);
  assert.doesNotMatch(html, /\b\d+\s+(syntactic\s+)?rules?\b/i);
  assert.doesNotMatch(read(SRC, 'app.js'), /\b\d+\s+(syntactic\s+)?rules?\b/i);
});

test('the page says the scan is one part of Preflight and links the repository that holds the registry and the guard', () => {
  assert.match(html, /<p>This scan is one part of Preflight\.[^<]*registry[^<]*guard[^<]*<a href="https:\/\/github\.com\/WonkaRed\/preflight">repository<\/a>/);
  assert.equal(REPO_TREE_URL.replace(/\/tree\/main$/, ''), 'https://github.com/WonkaRed/preflight');
});

test('the proof links point at this repository\'s main tree, so every bundled proof path resolves on GitHub', () => {
  assert.equal(REPO_TREE_URL, 'https://github.com/WonkaRed/preflight/tree/main');
  for (const { fixture, exploit } of Object.values(siteData().proofs)) {
    for (const path of [fixture, exploit]) assert.ok(existsSync(new URL(`../../${path}`, import.meta.url)), `${path} is linked but not in the repository`);
  }
});

test('the scan buttons ship disabled and are enabled only once the scanner has loaded', () => {
  for (const id of ['scan-source', 'scan-github', 'fill-github']) {
    assert.match(html, new RegExp(`<button[^>]*id="${id}"[^>]*\\sdisabled(\\s|>|=)`), `${id} must start disabled`);
  }
  const app = read(SRC, 'app.js');
  const failure = app.indexOf("return problem('The scanner could not be loaded'");
  const enabled = app.indexOf("$(id).disabled = false");
  assert.ok(failure > 0 && enabled > failure, 'the buttons are enabled after the load failure has returned, so a failed load leaves them disabled');
  assert.equal(app.match(/disabled = false/g).length, 1, 'nothing else enables them');
});

test('the Swap comes first on the page, and its small print says the key is public on purpose', () => {
  const at = (needle) => html.indexOf(needle);
  assert.ok(at('class="swap"') > 0 && at('class="swap"') < at('class="intro"') && at('class="intro"') < at('class="bench"'));
  assert.match(html, /The key in this page is public on purpose: it can only call <code>flip<\/code> on a demo contract/);
  assert.match(read(SRC, 'swap-config.js'), /PUBLIC ON PURPOSE/);
  assert.match(html, /<h1 id="swap-title">/);
  assert.equal([...html.matchAll(/<h1\b/g)].length, 1);
});

test('the Swap config is either empty, so the page shows the recording, or complete with a recording that parses', () => {
  const required = ['chameleonId', 'switchId', 'registryId', 'flipKey'];
  const filled = required.filter((key) => SWAP_CONFIG[key] !== '');
  assert.ok(filled.length === 0 || filled.length === required.length, `half-filled Swap config: ${filled}`);
  assert.ok(SWAP_CONFIG.rpcUrls.length >= 2 && SWAP_CONFIG.rpcUrls.every((url) => new URL(url).protocol === 'https:'), 'two or more https endpoints, so one throttled endpoint is survivable');
  if (filled.length) assert.ok(parseRecorded(JSON.parse(read(DIST, 'swap-recorded.json'))), 'a live Swap needs demo/swap/recorded.json for the fallback');
});
