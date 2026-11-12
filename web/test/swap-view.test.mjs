// The Swap section's view (src/swap-view.js): what each state shows, and that chain text only ever reaches the page as text.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSwap, parseRecorded } from '../src/swap.js';
import { IDS as PAGE_IDS, mountSwap, paint, paintRob, ROB_IDS, robViewModel, viewModel } from '../src/swap-view.js';
import { fakeDocument, walk } from './fake-dom.mjs';
import { CONFIG, fakeChain, flipTxResult, HASH, recordedJson, UNSET_CONFIG } from './swap-chain.mjs';

const EXPLORER = 'https://testnet.near.rocks';
const recorded = parseRecorded(recordedJson);
const view = (state, now = 0) => viewModel(state, { now, explorerUrl: EXPLORER });

// A tab's session storage of its own for every state: Node's global one would carry a pin from one test into the next.
const fresh = () => { const map = new Map(); return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => { map.set(k, String(v)); } }; };

async function liveState(build = 'vulnerable', mutate = () => {}) {
  const chain = fakeChain();
  chain.build = build;
  mutate(chain);
  const swap = createSwap({ config: CONFIG, recorded, env: { fetch: (...a) => chain.fetch(...a), now: () => chain.nowMs, sleep: async () => {}, storage: fresh() } });
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
  assert.equal(m.hint, 'Someone left this contract on its bad code, so Preflight says BLOCK while the address check still says ALLOW. Swap in the fixed code, then swap the bad one back, to watch it change.');
  assert.equal(m.button.label, 'Swap in the fixed code');
  assert.deepEqual([m.pf.tone, m.pf.word, m.pf.rules, m.pf.build, m.pf.hash], ['block', 'BLOCK', 'PF001', 'Vulnerable build', HASH.vulnerable]);
  assert.equal(m.pf.line, 'This code has a hole: anyone can give themselves a balance and take what other people deposited.');
  assert.match(m.pf.tech, /Any account can call the contract's callback directly, so anyone can credit themselves a balance without paying/);
  assert.deepEqual(m.button, { label: 'Swap in the fixed code', disabled: false });
  assert.equal(m.flips, 'Swaps so far: 3');
});

test('P live: the allowlist still says ALLOW and Preflight now says ALLOW too, on a different hash', async () => {
  const { state } = await liveState('patched');
  const m = view(state);
  assert.equal(m.trust.word, 'ALLOW');
  assert.deepEqual([m.pf.tone, m.pf.word, m.pf.rules, m.pf.build, m.pf.hash], ['allow', 'ALLOW', '', 'Patched build', HASH.patched]);
  assert.equal(m.pf.line, 'This is the fixed code. Preflight says yes.');
  assert.match(m.pf.tech, /No known issue fired on this exact code \(registry status: Safe\)/);
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
  assert.deepEqual(view(state, chain.nowMs).button, { label: 'Ready in 7 s', disabled: true });
  assert.deepEqual(view(state, chain.nowMs + 6001).button, { label: 'Ready in 1 s', disabled: true });
  assert.deepEqual(view(state, chain.nowMs + 7000).button, { label: 'Swap in the fixed code', disabled: false });
  assert.equal(view(state, chain.nowMs).tx, null);
  assert.equal(view(state, chain.nowMs).hint, 'The code was just swapped. The demo rests a moment between swaps.', 'true for a visitor who never swapped');
  assert.match(view(state, chain.nowMs + 7000).hint, /^Someone left this contract on its bad code/, 'the line is gone with the countdown');
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

const IDS = ['status', 'detail', 'source', 'address', 'trustWord', 'trustNote', 'pfCard', 'pfWord', 'pfRules', 'pfLine', 'pfTech', 'pfBuild', 'pfHash', 'before', 'beforeTitle', 'beforeWord', 'beforeRules', 'beforeReason', 'beforeHash', 'beforeTx', 'pin', 'pinThen', 'pinNow', 'pinFoldThen', 'pinFoldNow', 'pinKeys', 'button', 'hint', 'flips', 'tx'];
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
    for (const until = Date.now() + 5000; Date.now() < until && els.get('pf-word').textContent === '...';) await new Promise((resolve) => setImmediate(resolve)); // time, not turns: the hash is computed off the main thread
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
  // A visitor who arrived while the vulnerable build was live: the code under them changed.
  return { ...live, state: { ...live.swap.getState(), arrival: HASH.vulnerable }, hash };
}

test('fixed code live after the code changed under the visitor: the contrast from the registry and the chain, and the offer to swap the bad code in again', async () => {
  const { state, chain, hash } = await fixedLive(5);
  const m = view(state, chain.nowMs);
  assert.deepEqual([m.trust.word, m.pf.word, m.pf.line], ['ALLOW', 'ALLOW', 'This is the fixed code. Preflight says yes.']);
  assert.equal(m.button.label, 'Swap in the bad code');
  assert.equal(m.hint, 'The fixed code is back. Swap the bad code in again and watch Preflight react.');
  assert.equal(m.before.title, 'Until 5 minutes ago, this same address ran different code.');
  assert.deepEqual([m.before.word, m.before.rules, m.before.tone], ['BLOCK', 'PF001', 'block']);
  assert.equal(m.trust.note, 'This address is on its safe list, so it says yes. Every time, even though the code behind it just changed.');
  assert.equal(m.before.reason, 'That code had a hole: anyone can credit themselves a balance.');
  assert.equal(m.before.hash, HASH.vulnerable);
  assert.deepEqual(m.before.tx, { href: `${EXPLORER}/tx/${hash}`, text: 'The swap transaction' });
  assert.equal(view({ ...state, tx: null, waitUntil: chain.nowMs + 4000 }, chain.nowMs).button.label, 'Ready in 4 s', 'the countdown still wins');
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
  assert.equal(vulnerable.button.label, 'Swap in the fixed code');
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

// ---- The auditor-free line --------------------------------------------------------------------------------------

test('the code-changed line appears only when the live code is not the code the visitor arrived to', async () => {
  const { state } = await liveState('vulnerable');
  assert.equal(view(state).pin, null, 'arrived and nothing changed');
  assert.equal(view({ ...state, arrival: null }).pin, null, 'no pin yet');
  const changed = view({ ...state, arrival: HASH.patched, keys: { full: 0, codeHash: state.codeHash } }).pin;
  assert.deepEqual([changed.then, changed.now], [HASH.patched, HASH.vulnerable]);
  assert.equal(view({ ...state, arrival: HASH.patched, mode: 'recorded', reason: 'rpc-down' }).pin, null, 'a recording is not a live read');
});

test('the note shows in both directions: whenever the live code is not the code the visitor arrived to, and clears when it is back', async () => {
  const onVulnerable = (await liveState('vulnerable')).state;
  const onPatched = (await liveState('patched')).state;
  // Arrived to the fixed build (the landing): nothing to note, then the bad code goes in.
  assert.equal(view({ ...onPatched, arrival: HASH.patched }).pin, null);
  const toBad = view({ ...onVulnerable, arrival: HASH.patched });
  assert.deepEqual([toBad.pin.then, toBad.pin.now], [HASH.patched, HASH.vulnerable]);
  assert.deepEqual([toBad.pf.word, toBad.trust.word], ['BLOCK', 'ALLOW'], 'Preflight turns to BLOCK, the address check does not move');
  assert.equal(toBad.trust.note, 'This address is on its safe list, so it says yes. Every time, even though the code behind it just changed.');
  assert.equal(view({ ...onPatched, arrival: HASH.patched }).pin, null, 'back on the arrival code: the note clears');
  // Arrived to the vulnerable build (someone else left it there): the fixed code is the change.
  assert.equal(view({ ...onVulnerable, arrival: HASH.vulnerable }).pin, null);
  const toFixed = view({ ...onPatched, arrival: HASH.vulnerable });
  assert.deepEqual([toFixed.pin.then, toFixed.pin.now], [HASH.vulnerable, HASH.patched]);
});

test('through real swaps from the fixed build: the note shows after the bad code goes in, clears on the way back, and shows again', async () => {
  const { swap, chain } = await liveState('patched');
  const note = () => view(swap.getState(), chain.nowMs).pin;
  assert.equal(note(), null);
  for (const [build, noted] of [['vulnerable', true], ['patched', false], ['vulnerable', true]]) {
    chain.nowMs += 60_000;
    chain.nonce += 1; // a new transaction, not a copy of the last
    await swap.refresh(); // the switch's rest between swaps is over
    await swap.flip();
    assert.equal(swap.getState().build, build);
    assert.equal(note() !== null, noted, `after the swap to ${build}`);
  }
});

test('the first screen: on the fixed build it invites the owner\'s swap, and shows no history; on the bad build left by someone else it still tells the story', async () => {
  const landing = view({ ...(await fixedLive(11)).state, arrival: HASH.patched }, 0);
  assert.deepEqual([landing.trust.word, landing.pf.word, landing.before, landing.pin], ['ALLOW', 'ALLOW', null, null], 'both checks say ALLOW and nothing speaks of an earlier build');
  assert.equal(landing.button.label, 'Swap in the bad code');
  assert.match(landing.hint, /^Right now this contract is fine, and both checks say yes\. A contract's owner can swap its code at any time\./);
  assert.equal(landing.trust.note, 'This address is on its safe list, so it says yes. Every time.');
  const swapped = view({ ...(await liveState('vulnerable')).state, arrival: HASH.patched });
  assert.match(swapped.hint, /^Same address, new code\. The address check cannot tell/);
  assert.equal(swapped.button.label, 'Swap in the fixed code');
  const shared = view((await liveState('vulnerable')).state);
  assert.match(shared.hint, /^Someone left this contract on its bad code, so Preflight says BLOCK while the address check still says ALLOW/);
  assert.deepEqual([shared.pin, shared.pf.word, shared.trust.word], [null, 'BLOCK', 'ALLOW']);
});

test('the key fact is the honest sentence for none, one and several keys, and says so when the list could not be read', async () => {
  const { state } = await liveState('patched');
  const pin = (keys) => view({ ...state, arrival: HASH.vulnerable, keys }).pin.keys;
  assert.equal(pin({ full: 0, codeHash: HASH.patched }), 'Read from the chain just now: this account has no full-access key, and its code still changes, through one of its own methods. That is exactly why Preflight pins the fingerprint instead of trusting keys.');
  assert.match(pin({ full: 1, codeHash: HASH.patched }), /holds 1 full-access key, and each can deploy new code to it at any time/);
  assert.match(pin({ full: 3, codeHash: HASH.patched }), /holds 3 full-access keys/);
  assert.equal(pin(null), 'The account\'s key list could not be read just now.');
  assert.equal(pin({ full: 0, codeHash: HASH.vulnerable }), 'The account\'s key list could not be read just now.', 'a count read for other code is not the fact about this code');
});

test('paint shows the line with the fingerprints as text and the full values as titles, and hides it again', async () => {
  const { doc, els } = fakeSection();
  const { state } = await liveState('patched');
  paint(doc, els, view({ ...state, arrival: HASH.vulnerable, keys: { full: 0, codeHash: HASH.patched } }));
  assert.equal(els.pin.hidden, false);
  assert.deepEqual([els.pinThen.textContent, els.pinNow.textContent, els.pinFoldThen.textContent, els.pinFoldNow.textContent], [HASH.vulnerable, HASH.patched, HASH.vulnerable, HASH.patched]);
  assert.equal(els.pinNow.attrs.title, HASH.patched);
  assert.match(els.pinKeys.textContent, /no full-access key/);
  paint(doc, els, view(state));
  assert.equal(els.pin.hidden, true);
});

test('the page says it plainly: no auditor needed, the code changed since you arrived, fingerprint then and now', async () => {
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(new URL('../src/index.html', import.meta.url), 'utf8');
  assert.match(html, /<b>The code changed since you arrived\.<\/b> No auditor needed to see that: the fingerprint is different\.<span class="pin-inline"> Fingerprint then <button[^>]*id="pin-then"[^>]*><\/button>, now <button[^>]*id="pin-now"[^>]*><\/button>\.<\/span>/);
  assert.match(html, /<details class="fold pin-fold">\s*<summary>Why no key list can tell you this<\/summary>/);
  assert.match(html, /<div class="swap-pin" id="swap-pin" hidden>/, 'hidden until there is a change to show');
});

test('the Rob it panel under each build: the narrative follows the live verdict, and an idle panel shows no leftover result', () => {
  const idle = { ok: true, canAct: true, stage: 'idle', before: null, after: null, hash: null, message: '' };
  const url = 'https://explorer.example';
  const vulnerable = robViewModel(idle, 'block', url);
  assert.deepEqual([vulnerable.narrative, vulnerable.button, vulnerable.status, vulnerable.tx, vulnerable.result], ['This is the code Preflight said BLOCK to.', { label: 'Rob it', disabled: false }, { tone: 'none', text: '' }, null, null]);
  assert.equal(vulnerable.hint, 'One click. One real transaction. No wallet.');
  assert.equal(robViewModel(idle, 'allow', url).narrative, 'This is the fixed code. Try it: the contract should refuse.');
  assert.equal(robViewModel({ ...idle, canAct: false }, 'block', url).button.disabled, true);
});

const YOCTO = 10n ** 21n; // 0.001 NEAR
const HASH_TX = '11111111111111111111111111111111';

test('a robbery is the result block: ROBBED in the block tone, the balance jump as numbers, a plain line and the transaction link', () => {
  const done = { ok: true, canAct: true, stage: 'done', before: String(3048n * YOCTO), after: String(4048n * YOCTO), hash: HASH_TX, message: '' };
  const m = robViewModel(done, 'block', 'https://explorer.example');
  assert.deepEqual(m.result, {
    tone: 'block', word: 'ROBBED', figure: { from: '3.048', to: '4.048', unit: 'testnet NEAR' }, plain: 'A real transaction just forged a balance nobody paid for.', own: '',
    link: { href: `https://explorer.example/tx/${HASH_TX}`, text: 'View the transaction' },
  });
  assert.deepEqual([m.status, m.tx], [{ tone: 'none', text: '' }, null], 'the result block replaces the small status and sentence');
  const grown = robViewModel({ ...done, before: String(57048n * YOCTO), after: String(58048n * YOCTO) }, 'block', 'https://explorer.example');
  assert.deepEqual(grown.result.figure, { from: '57.048', to: '58.048', unit: 'testnet NEAR' });
});

test('a refusal is the same block in the allow tone: REFUSED, a plain line first, the contract\'s own words second', () => {
  const refused = { ok: true, canAct: true, stage: 'refused', before: String(3048n * YOCTO), after: null, hash: HASH_TX, message: 'Method on_deposit is private' };
  const m = robViewModel(refused, 'allow', 'https://explorer.example');
  assert.deepEqual(m.result, {
    tone: 'allow', word: 'REFUSED', figure: null, plain: 'The fixed code said no. Only the contract itself may run this step.', own: 'The contract\'s own words: "Method on_deposit is private"',
    link: { href: `https://explorer.example/tx/${HASH_TX}`, text: 'View the transaction' },
  });
  assert.deepEqual([m.status, m.tx], [{ tone: 'none', text: '' }, null]);
});

test('every other rob state stays quiet: small status text, no result block', () => {
  const base = { ok: true, canAct: true, before: null, after: null, hash: null, message: '' };
  for (const stage of ['reading', 'pending', 'cannot-pay', 'failed', 'unconfirmed']) assert.equal(robViewModel({ ...base, stage }, 'block', 'https://explorer.example').result, null, stage);
  assert.equal(robViewModel({ ...base, stage: 'failed', message: 'Nothing was sent.' }, 'block', 'https://explorer.example').tx.text, 'Nothing was sent.');
});

test('paintRob writes the result as text, builds the numbers as separate spans, hides the block when there is none, and animates only a new result', () => {
  const doc = fakeDocument();
  const els = Object.fromEntries(Object.keys(ROB_IDS).map((name) => [name, Object.assign(doc.createElement('div'), { textContent: '', hidden: true })]));
  const animations = [];
  els.robCard.animate = (...args) => { animations.push(args); };
  const done = { ok: true, canAct: true, stage: 'done', before: String(57048n * YOCTO), after: String(58048n * YOCTO), hash: HASH_TX, message: '' };
  const model = robViewModel(done, 'block', EXPLORER);
  paintRob(doc, els, model, { animate: true });
  assert.equal(els.robCard.hidden, false);
  assert.equal(els.robCard.attrs['data-tone'], 'block');
  assert.equal(els.robWord.textContent, 'ROBBED');
  assert.deepEqual(els.robFigure.kids.map((k) => k.kids[0].text), ['57.048', '\u2192', '58.048', 'testnet NEAR']);
  const links = [];
  walk(els.robLink, (n) => { if (n.tag === 'a') links.push(n.attrs); });
  assert.deepEqual(links, [{ href: `${EXPLORER}/tx/${HASH_TX}`, target: '_blank', rel: 'noopener noreferrer' }]);
  paintRob(doc, els, model, { animate: true });
  assert.equal(animations.length, 1, 'a repaint of the same result does not replay the entrance');
  assert.ok(animations[0][1].duration < 300);
  paintRob(doc, els, robViewModel({ ...done, stage: 'pending' }, 'block', EXPLORER), { animate: true });
  assert.equal(els.robCard.hidden, true);
  paintRob(doc, els, robViewModel({ ...done, stage: 'refused', message: '<img src=x onerror=alert(1)>' }, 'allow', EXPLORER), { animate: false });
  assert.equal(animations.length, 1, 'no entrance without animate');
  assert.equal(els.robOwn.textContent, 'The contract\'s own words: "<img src=x onerror=alert(1)>"');
  assert.equal(els.robFigure.kids.length, 0);
  assert.equal(els.robCard.attrs['data-tone'], 'allow');
});

test('the page has exactly one element for every Rob it id', async () => {
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(new URL('../src/index.html', import.meta.url), 'utf8');
  for (const id of Object.values(ROB_IDS)) assert.equal(html.split(`id="${id}"`).length, 2, id);
});
