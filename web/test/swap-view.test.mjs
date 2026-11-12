// The Swap section's view (src/swap-view.js): what each state shows, and that chain text only ever reaches the page as text.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSwap, parseRecorded } from '../src/swap.js';
import { IDS as PAGE_IDS, mountSwap, paint, viewModel } from '../src/swap-view.js';
import { fakeDocument, walk } from './fake-dom.mjs';
import { CONFIG, fakeChain, flipTxResult, HASH, recordedJson, UNSET_CONFIG } from './swap-chain.mjs';

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
  assert.equal(m.trust.note, 'This address is on its safe list, so it says yes. Every time.');
  assert.equal(m.hint, 'Press it. The code behind this address changes, live.');
  assert.deepEqual([m.pf.tone, m.pf.word, m.pf.rules, m.pf.build, m.pf.hash], ['block', 'BLOCK', 'PF001', 'Vulnerable build', HASH.vulnerable]);
  assert.equal(m.pf.line, 'This code has a hole: anyone can give themselves a balance and take what other people deposited.');
  assert.match(m.pf.tech, /Any account can call the contract's callback directly, so anyone can credit themselves a balance without paying/);
  assert.deepEqual(m.button, { label: 'Swap the code', disabled: false });
  assert.equal(m.flips, 'Swaps so far: 3');
});

test('P live: the allowlist still says ALLOW and Preflight now says ALLOW too, on a different hash', async () => {
  const { state } = await liveState('patched');
  const m = view(state);
  assert.equal(m.trust.word, 'ALLOW');
  assert.deepEqual([m.pf.tone, m.pf.word, m.pf.rules, m.pf.build, m.pf.hash], ['allow', 'ALLOW', '', 'Patched build', HASH.patched]);
  assert.equal(m.pf.line, 'This is the fixed code. Preflight says yes.');
  assert.match(m.pf.tech, /Safe verdict for this exact code/);
});

test('code with no verdict is WARN and says it is unaudited; an unknown rule falls back to a generic line', async () => {
  let { state } = await liveState('vulnerable', (chain) => { delete chain.verdicts[HASH.vulnerable]; });
  assert.deepEqual([view(state).pf.tone, view(state).pf.word], ['warn', 'WARN']);
  assert.match(view(state).pf.line, /Nobody has vouched for this code/);
  assert.match(view(state).pf.tech, /no verdict for this code/);
  ({ state } = await liveState('vulnerable', (chain) => { chain.verdicts[HASH.vulnerable].rule_ids = ['PF009']; }));
  assert.equal(view(state).pf.line, 'This code is marked unsafe.');
  assert.match(view(state).pf.tech, /marks this exact code unsafe \(PF009\)/);
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
  assert.equal(m.hint, 'Press it to replay a recorded swap of the code behind this address.');
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

const IDS = ['status', 'detail', 'source', 'address', 'trustWord', 'trustNote', 'pfCard', 'pfWord', 'pfRules', 'pfLine', 'pfTech', 'pfBuild', 'pfHash', 'before', 'beforeTitle', 'beforeWord', 'beforeRules', 'beforeReason', 'beforeHash', 'beforeTx', 'button', 'hint', 'flips', 'tx'];
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
    assert.equal(els.get('agent-word').textContent, 'REFUSED', 'the agent panel plays on the same read');
    assert.equal(els.get('agent-hash').textContent, HASH.vulnerable);
  } finally {
    swap?.stop();
    for (const [name, value] of Object.entries(saved)) { if (value === undefined) delete globalThis[name]; else globalThis[name] = value; }
  }
});

test('a read that failed keeps the live data with a quiet note, and the page names the endpoint it reads through', async () => {
  const { state } = await liveState('vulnerable');
  const live = view({ ...state, endpoint: 'near-testnet.drpc.org' });
  assert.equal(live.source, 'Via near-testnet.drpc.org.');
  assert.match(live.status.text, /^Live on NEAR testnet\. Every swap/);
  const blip = view({ ...state, endpoint: 'near-testnet.drpc.org', reconnecting: true });
  assert.match(blip.status.text, /^Live on NEAR testnet\. Reconnecting; what you see is from the last read\./);
  assert.equal(blip.pf.word, 'BLOCK', 'the last live verdict stays');
  assert.equal(view({ ...state, mode: 'recorded', reason: 'rpc-down', endpoint: null, recorded }).source, '', 'a recording names no endpoint');
});

test('both builds read correctly on their own: the rule id comes with its plain words, the full hash is the title, and the swap animates card and hash', async () => {
  const vulnerable = view((await liveState('vulnerable')).state);
  const patched = view((await liveState('patched')).state);
  assert.deepEqual([vulnerable.pf.rules, vulnerable.pf.ruleWords], ['PF001', 'anyone can credit themselves a balance']);
  assert.deepEqual([patched.pf.word, patched.pf.rules, patched.pf.ruleWords, patched.trust.word], ['ALLOW', '', '', 'ALLOW'], 'the allowlist says the same in both builds');

  const { doc, els } = fakeSection();
  const animated = [];
  els.pfCard.animate = () => animated.push('card');
  els.pfHash.animate = () => animated.push('hash');
  paint(doc, els, vulnerable, { animate: true });
  assert.deepEqual([els.pfHash.textContent, els.pfHash.attrs.title, els.pfRules.attrs.title], [HASH.vulnerable, HASH.vulnerable, 'anyone can credit themselves a balance'], 'the text stays whole; the page shortens it');
  assert.deepEqual(animated, ['card', 'hash']);
  paint(doc, els, patched, { animate: true });
  assert.deepEqual([els.pfCard.attrs['data-tone'], els.pfHash.attrs.title, els.pfRules.attrs.title], ['allow', HASH.patched, ''], 'the other build, painted over the first');
  paint(doc, els, patched, { animate: true });
  assert.equal(animated.length, 4, 'a read that changed nothing animates nothing');
});

// ---- the contrast: the build that ran here before the last swap ----------------------------------------------------------

const MINUTE = 60_000;
async function fixedLive(minutes, mutate = () => {}) {
  const hash = '3541qCoM1J96ifJZ2PiYFkHUXH4TAyAHPAZjS1RtMsEp';
  const live = await liveState('patched', (chain) => { chain.lastFlipMs = chain.nowMs - minutes * MINUTE; chain.swapTx = { hash, result: flipTxResult }; mutate(chain); });
  for (let wait = 0; wait < 100 && live.swap.getState().before?.txHash === null; wait++) await new Promise((resolve) => setImmediate(resolve));
  return { ...live, state: live.swap.getState(), hash };
}

test('fixed code live: the first screen still shows the contrast, from the registry and the chain, and offers to swap it back', async () => {
  const { state, chain, hash } = await fixedLive(5);
  const m = view(state, chain.nowMs);
  assert.deepEqual([m.trust.word, m.pf.word, m.pf.line], ['ALLOW', 'ALLOW', 'This is the fixed code. Preflight says yes.']);
  assert.equal(m.button.label, 'Swap it back and watch');
  assert.equal(m.hint, 'Press it. The code behind this address changes, live.');
  assert.equal(m.before.title, 'Until 5 minutes ago, this same address ran different code.');
  assert.deepEqual([m.before.word, m.before.rules, m.before.tone], ['BLOCK', 'PF001', 'block']);
  assert.equal(m.trust.note, 'This address is on its safe list, so it says yes. Every time, even for the code before.');
  assert.equal(m.before.reason, 'That code had a hole: anyone can credit themselves a balance.');
  assert.equal(m.before.hash, HASH.vulnerable);
  assert.deepEqual(m.before.tx, { href: `${EXPLORER}/tx/${hash}`, text: 'The swap transaction' });
  assert.equal(view({ ...state, tx: null, waitUntil: chain.nowMs + 4000 }, chain.nowMs).button.label, 'Swap again in 4 s', 'the countdown still wins');
});

test('the age is in whole units rounded down, never rounded up into a claim that is not true', async () => {
  const age = async (ms) => { const { state, chain } = await fixedLive(5); return view(state, chain.nowMs - 5 * MINUTE + ms).before.title; };
  assert.equal(await age(10_000), 'Until a moment ago, this same address ran different code.');
  assert.equal(await age(MINUTE), 'Until 1 minute ago, this same address ran different code.');
  assert.equal(await age(59 * MINUTE + 59_000), 'Until 59 minutes ago, this same address ran different code.');
  assert.equal(await age(90 * MINUTE), 'Until 1 hour ago, this same address ran different code.');
  assert.equal(await age(50 * 60 * MINUTE), 'Until 2 days ago, this same address ran different code.');
  assert.equal(await age(-MINUTE), 'Until a moment ago, this same address ran different code.', 'a slow local clock never reads as negative');
});

test('the contrast has no transaction link until one is found, and is not shown when the live code is the vulnerable build or the recording plays', async () => {
  const { state, chain } = await fixedLive(5, (c) => { c.swapTx = null; });
  assert.equal(view(state, chain.nowMs).before.tx, null);
  const vulnerable = view((await liveState('vulnerable', (c) => { c.lastFlipMs = c.nowMs - MINUTE; })).state, 0);
  assert.equal(vulnerable.before, null);
  assert.equal(vulnerable.button.label, 'Swap the code');
  const replay = view({ mode: 'recorded', reason: 'rpc-down', recorded, replay: 2, address: 'chameleon.example.testnet', before: state.before, tx: null, waitUntil: null }, 0);
  assert.equal(replay.before, null);
  assert.equal(replay.button.label, 'Replay a recorded swap');
});

test('the contrast is not shown when Preflight judged both builds the same', async () => {
  const { state, chain } = await fixedLive(5, (c) => { c.verdicts[HASH.vulnerable] = { ...c.verdicts[HASH.patched], code_hash: HASH.vulnerable }; });
  assert.equal(view(state, chain.nowMs).before, null);
});

test('paint writes the contrast as text and a validated link, and hides it when there is none', async () => {
  const { doc, els } = fakeSection();
  const { state, chain, hash } = await fixedLive(5);
  paint(doc, els, view(state, chain.nowMs));
  assert.equal(els.before.hidden, false);
  assert.equal(els.beforeTitle.textContent, 'Until 5 minutes ago, this same address ran different code.');
  assert.equal(els.beforeHash.textContent, HASH.vulnerable);
  assert.deepEqual([els.beforeWord.textContent, els.beforeWord.attrs['data-tone'], els.beforeRules.textContent], ['BLOCK', 'block', 'PF001']);
  const links = [];
  walk(els.beforeTx, (n) => { if (n.tag === 'a') links.push(n.attrs); });
  assert.deepEqual(links, [{ href: `${EXPLORER}/tx/${hash}`, target: '_blank', rel: 'noopener noreferrer' }]);
  paint(doc, els, view((await liveState('vulnerable')).state));
  assert.equal(els.before.hidden, true);
});

test('every element the section paints into is in the page', async () => {
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(new URL('../src/index.html', import.meta.url), 'utf8');
  for (const id of Object.values(PAGE_IDS)) assert.match(html, new RegExp(`id="${id}"`), id);
});
