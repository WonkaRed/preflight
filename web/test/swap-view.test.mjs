// The Swap section's view (src/swap-view.js): what each state shows, and that chain text only ever reaches the page as text.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSwap, parseRecorded } from '../src/swap.js';
import { mountSwap, paint, viewModel } from '../src/swap-view.js';
import { fakeDocument, walk } from './fake-dom.mjs';
import { CONFIG, fakeChain, HASH, recordedJson, UNSET_CONFIG } from './swap-chain.mjs';

const EXPLORER = 'https://testnet.near.rocks';
const recorded = parseRecorded(recordedJson);
const view = (state, now = 0) => viewModel(state, { now, explorerUrl: EXPLORER });

async function liveState(build = 'vulnerable', mutate = () => {}) {
  const chain = fakeChain();
  chain.build = build;
  mutate(chain);
  const swap = createSwap({ config: CONFIG, recorded, env: { fetch: (...a) => chain.fetch(...a), now: () => chain.nowMs, sleep: async () => {} } });
  await swap.refresh();
  return { swap, chain, state: swap.getState() };
}

test('V live: the allowlist says ALLOW, Preflight says BLOCK with PF001, the hash and what the bug lets an attacker do', async () => {
  const { state } = await liveState('vulnerable');
  const m = view(state);
  assert.equal(m.status.tone, 'live');
  assert.equal(m.address, 'chameleon.example.testnet');
  assert.equal(m.addressHref, `${EXPLORER}/account/chameleon.example.testnet`);
  assert.equal(m.trust.word, 'ALLOW');
  assert.equal(m.trust.note, 'chameleon.example.testnet is on the allowlist, so it passes.');
  assert.deepEqual([m.pf.tone, m.pf.word, m.pf.rules, m.pf.build, m.pf.hash], ['block', 'BLOCK', 'PF001', 'Vulnerable build', HASH.vulnerable]);
  assert.match(m.pf.line, /anyone can mark an order released without paying/);
  assert.deepEqual(m.button, { label: 'Swap the code', disabled: false });
  assert.equal(m.flips, 'Swaps so far: 3');
});

test('P live: the allowlist still says ALLOW and Preflight now says ALLOW too, on a different hash', async () => {
  const { state } = await liveState('patched');
  const m = view(state);
  assert.equal(m.trust.word, 'ALLOW');
  assert.deepEqual([m.pf.tone, m.pf.word, m.pf.rules, m.pf.build, m.pf.hash], ['allow', 'ALLOW', '', 'Patched build', HASH.patched]);
  assert.match(m.pf.line, /Safe verdict for this exact code/);
});

test('code with no verdict is WARN and says it is unaudited; an unknown rule falls back to a generic line', async () => {
  let { state } = await liveState('vulnerable', (chain) => { delete chain.verdicts[HASH.vulnerable]; });
  assert.deepEqual([view(state).pf.tone, view(state).pf.word], ['warn', 'WARN']);
  assert.match(view(state).pf.line, /no verdict for this code/);
  ({ state } = await liveState('vulnerable', (chain) => { chain.verdicts[HASH.vulnerable].rule_ids = ['PF009']; }));
  assert.match(view(state).pf.line, /marks this exact code unsafe \(PF009\)/);
});

test('countdown: the button is disabled and counts down in whole seconds, never an error', async () => {
  const { state, chain } = await liveState('vulnerable', (c) => { c.nextFlipMs = c.nowMs + 6000; });
  assert.deepEqual(view(state, chain.nowMs).button, { label: 'Swap again in 7 s', disabled: true });
  assert.deepEqual(view(state, chain.nowMs + 6001).button, { label: 'Swap again in 1 s', disabled: true });
  assert.deepEqual(view(state, chain.nowMs + 7000).button, { label: 'Swap the code', disabled: false });
  assert.equal(view(state, chain.nowMs).tx, null);
});

test('pending: the button is disabled while signing, sending and waiting for the deploy; the tx link appears once the hash is known', async () => {
  const { state } = await liveState('vulnerable');
  const hash = HASH.patched; // any valid hash
  const m = (tx) => view({ ...state, tx });
  assert.deepEqual(m({ stage: 'pending', hash: null, message: '' }).button, { label: 'Swapping...', disabled: true });
  assert.deepEqual(m({ stage: 'pending', hash: null, message: '' }).tx, { text: 'Signing in your browser.', link: null });
  assert.deepEqual(m({ stage: 'pending', hash, message: '' }).tx.link, { href: `${EXPLORER}/tx/${hash}`, text: 'View the transaction' });
  assert.equal(m({ stage: 'landing', hash, message: '' }).button.disabled, true);
  assert.match(m({ stage: 'landing', hash, message: '' }).tx.text, /Waiting for the new code/);
  assert.equal(m({ stage: 'done', hash, message: '' }).button.disabled, false);
  assert.equal(m({ stage: 'done', hash, message: '' }).tx.text, 'Swapped.');
  assert.match(m({ stage: 'unseen', hash, message: '' }).tx.text, /does not show the new code yet/);
});

test('a failed swap shows the message, and a transaction link only when there is a real hash', async () => {
  const { state } = await liveState('vulnerable');
  const failed = view({ ...state, tx: { stage: 'failed', hash: null, message: 'Nothing was sent. RPC block request failed: offline' } });
  assert.deepEqual(failed.tx, { text: 'Nothing was sent. RPC block request failed: offline', link: null });
  assert.equal(failed.button.disabled, false, 'the visitor can try again');
  const hostile = view({ ...state, tx: { stage: 'failed', hash: '"><script>x</script>', message: 'm' } });
  assert.equal(hostile.tx.link, null, 'a hash that is not a hash never becomes a link');
  assert.match(view({ ...state, tx: { stage: 'unconfirmed', hash: HASH.patched, message: 'RPC send_tx request failed: x' } }).tx.text, /^Sent, but the RPC did not confirm it\./);
});

test('recorded, RPC unreachable: labeled with its date, nothing claimed live, the button replays', () => {
  const swap = createSwap({ config: CONFIG, recorded });
  const state = { ...swap.getState(), mode: 'recorded', reason: 'rpc-down' };
  const m = view(state);
  assert.equal(m.status.tone, 'recorded');
  assert.equal(m.status.text, 'Recorded on 2026-11-11, RPC unreachable. Nothing below is live.');
  assert.deepEqual(m.button, { label: 'Replay a recorded swap', disabled: false });
  assert.deepEqual([m.pf.word, m.pf.rules, m.pf.build, m.flips], ['BLOCK', 'PF001', 'Vulnerable build', ''], 'the recording starts before its first swap');
  assert.deepEqual(m.tx, { text: 'The recording starts here. Each click replays one swap.', link: null });
  const second = view({ ...state, replay: 1 });
  assert.deepEqual([second.pf.word, second.pf.rules, second.pf.build, second.flips], ['ALLOW', '', 'Patched build', 'Recorded swap 1 of 4']);
  assert.deepEqual(second.tx.link, { href: `${EXPLORER}/tx/${recorded.steps[1].txHash}`, text: 'View it on the explorer' });
  assert.equal(m.trust.word, 'ALLOW', 'the allowlist says ALLOW in the replay too');
});

test('recorded because the demo key can no longer pay, or because nothing is configured: each says so', () => {
  const base = { ...createSwap({ config: UNSET_CONFIG, recorded }).getState(), mode: 'recorded' };
  assert.match(view({ ...base, reason: 'cannot-pay' }).status.text, /^Recorded on 2026-11-11\. The demo key can no longer pay for swaps, so the button replays the recording/);
  const unset = view({ ...base, reason: 'unconfigured', detail: 'Not set in swap-config.js: chameleonId' });
  assert.match(unset.status.text, /No live contract is set up in this copy of the page/);
  assert.equal(unset.detail, 'Not set in swap-config.js: chameleonId');
  assert.equal(view({ ...base, reason: 'rpc-down', detail: 'x' }).detail, '', 'RPC detail stays out of the page; only the unset-config detail is shown');
});

test('empty and loading: no verdict word is invented, and the button is off', () => {
  const swap = createSwap({ config: UNSET_CONFIG, recorded: null });
  const loading = view(swap.getState());
  assert.deepEqual([loading.status.tone, loading.pf.tone, loading.pf.word, loading.pf.hash, loading.button.disabled], ['loading', 'none', '...', '', true]);
  const empty = view({ ...swap.getState(), mode: 'empty', reason: 'unconfigured' });
  assert.deepEqual([empty.pf.word, empty.trust.word, empty.address, empty.button.disabled, empty.addressHref], ['No data', 'No data', 'no address yet', true, null]);
  assert.match(empty.status.text, /no recording is bundled/);
});

// ---- paint ---------------------------------------------------------------------------------------------------------

const IDS = ['status', 'detail', 'address', 'trustWord', 'trustNote', 'pfCard', 'pfWord', 'pfRules', 'pfLine', 'pfBuild', 'pfHash', 'button', 'flips', 'tx'];
function fakeSection() {
  const doc = fakeDocument();
  const els = Object.fromEntries(IDS.map((name) => [name, Object.assign(doc.createElement('div'), { textContent: '' })]));
  return { doc, els };
}

test('paint writes every field as text and links only with a validated href', async () => {
  const { doc, els } = fakeSection();
  const { state } = await liveState('vulnerable');
  paint(doc, els, view({ ...state, tx: { stage: 'done', hash: HASH.patched, message: '' } }));
  assert.equal(els.pfWord.textContent, 'BLOCK');
  assert.equal(els.pfCard.attrs['data-tone'], 'block');
  assert.equal(els.status.attrs['data-tone'], 'live');
  assert.equal(els.button.disabled, false);
  const links = [];
  for (const name of ['address', 'tx']) walk(els[name], (n) => { if (n.tag === 'a') links.push(n.attrs); });
  assert.deepEqual(links.map((l) => l.href), [`${EXPLORER}/account/chameleon.example.testnet`, `${EXPLORER}/tx/${HASH.patched}`]);
  assert.ok(links.every((l) => l.rel === 'noopener noreferrer' && l.target === '_blank'));
});

test('hostile chain text is a text node or textContent, never markup', async () => {
  const { doc, els } = fakeSection();
  const { state } = await liveState('vulnerable');
  const text = '<img src=x onerror=alert(1)>‮';
  paint(doc, els, view({ ...state, tx: { stage: 'failed', hash: null, message: text } }));
  assert.deepEqual(els.tx.kids, ['<img src=x onerror=alert(1)>\uFFFD'], 'one bare string, which the DOM makes a text node; the bidi override is replaced');
  const out = [];
  walk(els.tx, (n) => out.push(n.tag));
  assert.deepEqual(out.filter(Boolean), ['div'], 'no element was created from the text');
});

test('paint animates the card only when the verdict or hash changed, and only when asked', async () => {
  const { doc, els } = fakeSection();
  const calls = [];
  els.pfCard.animate = (...args) => calls.push(args);
  const v = (await liveState('vulnerable')).state;
  const p = (await liveState('patched')).state;
  paint(doc, els, view(v), { animate: true });
  paint(doc, els, view(v), { animate: true });
  assert.equal(calls.length, 1, 'only the first paint changed anything');
  paint(doc, els, view(p), { animate: true });
  assert.equal(calls.length, 2);
  paint(doc, els, view(v), { animate: false });
  assert.equal(calls.length, 2, 'reduced motion: no animation');
});

// The page's own wiring, with the globals a browser provides: a tab nobody sees does not read the chain, and showing it does.
test('mountSwap reads nothing while the tab is hidden, reads at once when it is shown, and paints what it read', async () => {
  const chain = fakeChain();
  const doc = fakeDocument();
  const els = new Map();
  const listeners = {};
  doc.getElementById = (id) => { if (!els.has(id)) els.set(id, Object.assign(doc.createElement('div'), { textContent: '' })); return els.get(id); };
  doc.addEventListener = (type, fn) => { listeners[type] = fn; };
  doc.hidden = true;
  const saved = Object.fromEntries(['document', 'fetch', 'matchMedia', 'setInterval'].map((name) => [name, globalThis[name]]));
  Object.assign(globalThis, {
    document: doc, matchMedia: () => ({ matches: true }), setInterval: () => 0,
    fetch: async (url, init) => (init ? chain.fetch(url, init) : { ok: true, json: async () => recordedJson }),
  });
  let swap;
  try {
    swap = await mountSwap(doc, CONFIG);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(chain.calls.length, 0, 'hidden: no request');
    doc.hidden = false;
    listeners.visibilitychange();
    for (let wait = 0; wait < 200 && els.get('pf-word').textContent === '...'; wait++) await new Promise((resolve) => setImmediate(resolve));
    assert.ok(chain.calls.length > 0, 'shown: it reads at once');
    assert.equal(els.get('pf-word').textContent, 'BLOCK');
  } finally {
    swap?.stop();
    for (const [name, value] of Object.entries(saved)) { if (value === undefined) delete globalThis[name]; else globalThis[name] = value; }
  }
});
