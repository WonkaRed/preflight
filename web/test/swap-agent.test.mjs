// The Swap's agent panel (src/swap-agent.js): what the scripted agent's check says for each verdict, that its log line has the
// guard's shape, and how the panel is staged and replayed. The panel sends nothing; there is no chain call to fake here
// except the reads the Swap already makes.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { guardEntry, createSwap, parseRecorded } from '../src/swap.js';
import { agentScript, AGENT_IDS, CALL, mountAgent, ROW_DELAYS } from '../src/swap-agent.js';
import { viewModel } from '../src/swap-view.js';
import { fakeDocument } from './fake-dom.mjs';
import { CONFIG, fakeChain, HASH, recordedJson } from './swap-chain.mjs';

const recorded = parseRecorded(recordedJson);
const AT = Date.parse('2026-11-11T20:00:00.000Z');
const ADDRESS = 'chameleon.example.testnet';

async function live(build, mutate = () => {}) {
  const chain = fakeChain();
  chain.build = build;
  mutate(chain);
  const swap = createSwap({ config: CONFIG, recorded, env: { fetch: (...a) => chain.fetch(...a), now: () => chain.nowMs, sleep: async () => {} } });
  await swap.refresh();
  return swap.getState();
}
const script = (state, at = AT) => viewModel(state, { now: at, explorerUrl: 'https://testnet.near.rocks' }).agent;

// ---- What the agent's check says -----------------------------------------------------------------------------------
// The story is always two beats: today's fixed code is ALLOWED, then the owner swaps the code and the guard REFUSES. Each beat
// is the live verdict when the code live right now has that decision, and the recorded one otherwise, and says which.

const RECORDED_BAD = { hash: 'FzLo9WN2CbEyCHZVdwLpizuSRGhp1Tkx95zsmPLp6J7i', reasons: ['registry verdict Unsafe (PF001): report https://example.com/r'] };

test('bad build live: the refusal is the live verdict, with the live hash and rule and the guard\'s log line in the guard\'s order; today\'s ALLOWED is the recording', async () => {
  const a = script(await live('vulnerable'));
  assert.deepEqual([a.swapped.word, a.swapped.tone, a.swapped.source, a.swapped.verdict, a.swapped.hash], ['REFUSED', 'block', 'live', 'Unsafe (PF001)', HASH.vulnerable]);
  assert.deepEqual([a.today.word, a.today.tone, a.today.source, a.today.hash, a.today.verdict], ['ALLOWED', 'allow', 'recorded', HASH.patched, 'Safe']);
  assert.equal(a.call, `${ADDRESS}.deposit with 0.5 NEAR`);
  const entry = JSON.parse(a.swapped.log);
  assert.deepEqual(Object.keys(entry), ['timestamp', 'contract', 'method', 'deposit', 'codeHash', 'decision', 'outcome', 'reasons']);
  assert.deepEqual(entry, {
    timestamp: '2026-11-11T20:00:00.000Z', contract: ADDRESS, method: 'deposit', deposit: CALL.deposit, codeHash: HASH.vulnerable, decision: 'block', outcome: 'refused',
    reasons: ['registry verdict Unsafe (PF001): published by auditor.example.testnet, report https://example.com/vulnerable.json'],
  });
  assert.equal(a.swapped.line, 'The guard refused the call before signing. Nothing was signed or sent.');
  assert.equal(a.swapped.why, 'On the vulnerable build anyone can credit themselves a balance without paying and withdraw what the agent deposits (PF001).');
  assert.equal(a.swapped.note, 'Composed here from the live reads above, with the guard\'s decision-log fields.');
  assert.equal(CALL.deposit, '500000000000000000000000', '0.5 NEAR in yoctoNEAR');
  assert.match(a.swapped.log, /\n  "decision": "block",\n/, 'one field per line, so the log wraps at fields and not mid-word');
});

test('fixed code live (the page\'s default): it still ends on REFUSED, from the recorded bad-build verdict, labelled recorded, with no time claimed', async () => {
  const a = script(await live('patched'));
  assert.deepEqual([a.today.word, a.today.source, a.today.hash, a.today.verdict, a.today.when, a.today.line], ['ALLOWED', 'live', HASH.patched, 'Safe', 'Today: fixed code.', 'Fixed code. Payment goes through.']);
  assert.deepEqual([a.swapped.word, a.swapped.tone, a.swapped.source, a.swapped.hash, a.swapped.verdict], ['REFUSED', 'block', 'recorded', RECORDED_BAD.hash, 'Unsafe (PF001)']);
  const entry = JSON.parse(a.swapped.log);
  assert.deepEqual([entry.timestamp, entry.decision, entry.outcome, entry.codeHash, entry.reasons], [undefined, 'block', 'refused', RECORDED_BAD.hash, RECORDED_BAD.reasons]);
  assert.match(a.swapped.note, /^Composed from the recorded verdict, not a live check/);
  assert.doesNotMatch(JSON.stringify(a), /right answer for this code/, 'the long ALLOWED paragraph is gone');
});

test('the beats take the live verdict only when the live code has that decision, so the panel never says live about code that is not live', async () => {
  const safe = script(await live('patched'));
  const bad = script(await live('vulnerable'));
  assert.deepEqual([safe.today.source, safe.swapped.source, bad.today.source, bad.swapped.source], ['live', 'recorded', 'recorded', 'live']);
  assert.notEqual(safe.key, bad.key, 'the panel plays again when a swap changes which beat is live');
  assert.equal(safe.key, script(await live('patched')).key, 'and a poll that read the same code changes nothing');
  assert.equal(safe.key, script(await live('patched', (chain) => { chain.lastFlipMs = chain.nowMs - 5 * 60_000; })).key, 'a swap on record is not a different story');
});

test('code with no verdict live: both beats are the recording, and the note says a live check would decline it', async () => {
  const a = script(await live('vulnerable', (chain) => { delete chain.verdicts[HASH.vulnerable]; }));
  assert.deepEqual([a.today.source, a.today.word, a.swapped.source, a.swapped.word], ['recorded', 'ALLOWED', 'recorded', 'REFUSED']);
  assert.match(a.swapped.note, /A live check of the code deployed right now would decline it \(a Warn, or no verdict\)\.$/);
});

test('no recording and no refusal live: today is shown alone and nothing more is claimed; with no verdict at all there is only today\'s decline', async () => {
  const safe = { ...(await live('patched')), recorded: null };
  const a = script(safe);
  assert.deepEqual([a.today.word, a.today.source, a.swapped], ['ALLOWED', 'live', null]);
  const unaudited = script({ ...(await live('vulnerable', (chain) => { delete chain.verdicts[HASH.vulnerable]; })), recorded: null });
  assert.deepEqual([unaudited.today.word, unaudited.today.tone, unaudited.today.when, unaudited.swapped], ['DECLINED', 'warn', 'Today: no verdict for this code.', null]);
});

test('the same decision as the Preflight card: the panel never decides on its own', async () => {
  for (const build of ['vulnerable', 'patched']) {
    const state = await live(build);
    const m = viewModel(state, { now: AT, explorerUrl: 'https://testnet.near.rocks' });
    const [word, source] = build === 'vulnerable' ? [m.agent.swapped.word, m.agent.swapped.source] : [m.agent.today.word, m.agent.today.source];
    assert.equal(source, 'live');
    assert.equal(JSON.stringify([m.pf.word === 'BLOCK', m.pf.word === 'ALLOW']), JSON.stringify([word === 'REFUSED', word === 'ALLOWED']));
  }
});

test('chain text in the log line is validated: a bad auditor or report link is left out, and never reaches the line', async () => {
  const state = await live('vulnerable', (chain) => { Object.assign(chain.verdicts[HASH.vulnerable], { auditor: 'Not An Id <b>', report_url: 'javascript:alert(1)' }); });
  assert.deepEqual([state.verdict.auditor, state.verdict.reportUrl], [null, null]);
  assert.deepEqual(JSON.parse(script(state).swapped.log).reasons, ['registry verdict Unsafe (PF001)']);
  assert.equal(guardEntry({ contract: 'a.testnet', method: 'm', deposit: '0', codeHash: 'h', verdict: { decision: 'BLOCK', ruleIds: [], registered: true, auditor: null, reportUrl: null } }).timestamp, undefined, 'no time given: none claimed');
});

test('nothing is claimed before there is something to check: loading has no key, and no address hides the panel', async () => {
  const loading = createSwap({ config: CONFIG, recorded: null }).getState();
  assert.equal(script(loading).key, null);
  assert.equal(script(loading).show, true);
  assert.deepEqual(script({ ...loading, mode: 'empty', address: null }), { show: false, key: null });
  const state = await live('vulnerable');
  assert.equal(script({ ...state, codeHash: HASH.vulnerable, verdict: null }).key, null);
});

// ---- Recorded mode -------------------------------------------------------------------------------------------------

test('recorded: both beats are the recording whichever step it is on, with no time claimed and the note saying it is not a live check', () => {
  const base = { ...createSwap({ config: CONFIG, recorded }).getState(), mode: 'recorded', reason: 'rpc-down' };
  const first = script(base);
  const second = script({ ...base, replay: 1 });
  assert.deepEqual([first.today.source, first.swapped.source, first.today.word, first.swapped.word], ['recorded', 'recorded', 'ALLOWED', 'REFUSED']);
  assert.equal(JSON.parse(first.swapped.log).timestamp, undefined);
  assert.deepEqual(JSON.parse(first.swapped.log).reasons, RECORDED_BAD.reasons);
  assert.match(first.swapped.note, /^Composed from the recorded verdict, not a live check/);
  assert.equal(first.key, second.key, 'the story does not depend on the replay step');
});

// ---- Staging -------------------------------------------------------------------------------------------------------

function panel(options = {}) {
  const doc = fakeDocument();
  const els = new Map();
  const clicks = {};
  doc.getElementById = (id) => {
    if (!els.has(id)) els.set(id, Object.assign(doc.createElement('div'), { textContent: '', hidden: false, addEventListener: (type, fn) => { clicks[id] = fn; } }));
    return els.get(id);
  };
  const timers = [];
  let clock = 0;
  const schedule = (fn, ms) => { const timer = { fn, at: clock + ms, live: true }; timers.push(timer); return () => { timer.live = false; }; };
  const advance = (ms) => {
    clock += ms;
    for (const timer of timers.filter((t) => t.live && t.at <= clock).sort((a, b) => a.at - b.at)) { timer.live = false; timer.fn(); }
  };
  const agent = mountAgent(doc, { schedule, now: () => clock, ...options });
  const rows = () => ['task', 'page', 'call', 'check', 'out'].map((name) => els.get(`agent-row-${name}`).attrs['data-state']);
  return { agent, els, rows, advance, timers, clicks };
}

test('the agent\'s rows play on load before the chain has answered; the check and outcome follow once the verdict is in', async () => {
  const { agent, els, rows, advance } = panel();
  const loading = script(createSwap({ config: CONFIG, recorded: null }).getState());
  agent.update(loading);
  assert.deepEqual(rows(), ['on', 'off', 'off', 'off', 'off']);
  assert.equal(els.get('agent-inject').textContent, ADDRESS, 'the injected text names the address the page is about');
  advance(ROW_DELAYS[1]);
  assert.deepEqual(rows(), ['on', 'on', 'off', 'off', 'off']);
  agent.update(script(await live('vulnerable')));
  advance(ROW_DELAYS[2] - ROW_DELAYS[1]);
  assert.deepEqual(rows(), ['on', 'on', 'on', 'off', 'off']);
  advance(ROW_DELAYS[3] - ROW_DELAYS[2]);
  assert.deepEqual(rows(), ['on', 'on', 'on', 'on', 'off']);
  advance(ROW_DELAYS[4] - ROW_DELAYS[3]);
  assert.deepEqual(rows(), ['on', 'on', 'on', 'on', 'on']);
  assert.deepEqual([els.get('agent-word').textContent, els.get('agent-out').attrs['data-tone'], els.get('agent-today-word').textContent, els.get('agent-src').textContent], ['REFUSED', 'block', 'ALLOWED', 'Live read']);
  assert.ok(ROW_DELAYS.at(-1) < 5000, 'the whole play is short');
});

test('a swap replays only the check and the outcome, and the same verdict read again plays nothing', async () => {
  const { agent, els, rows, advance, timers } = panel();
  const vulnerable = script(await live('vulnerable'));
  agent.update(vulnerable);
  advance(10_000);
  assert.deepEqual([els.get('agent-word').textContent, rows().join()], ['REFUSED', 'on,on,on,on,on']);
  const scheduled = timers.length;
  agent.update({ ...vulnerable, swapped: { ...vulnerable.swapped, log: 'another timestamp' } });
  assert.equal(timers.length, scheduled, 'a poll that read the same code changes nothing');
  assert.equal(els.get('agent-log').textContent, vulnerable.swapped.log);
  agent.update(script(await live('patched')));
  assert.deepEqual(rows(), ['on', 'on', 'on', 'off', 'off'], 'the agent stays, the guard check starts over');
  advance(10_000);
  assert.deepEqual([els.get('agent-word').textContent, els.get('agent-out').attrs['data-tone'], els.get('agent-verdict').textContent, els.get('agent-src').textContent, els.get('agent-today-src').textContent, rows().join()],
    ['REFUSED', 'block', 'Unsafe (PF001)', 'Recorded', 'Live read', 'on,on,on,on,on'], 'the story still ends on the refusal; now the recording says so, and today is the live read');
  agent.update(vulnerable);
  advance(10_000);
  assert.deepEqual([els.get('agent-word').textContent, els.get('agent-src').textContent, els.get('agent-today-src').textContent], ['REFUSED', 'Live read', 'Recorded'], 'and back');
});

test('reduced motion: the final state at once, and no timer is ever set', async () => {
  const { agent, els, rows, timers } = panel({ calm: true });
  agent.update(script(await live('vulnerable')));
  assert.equal(rows().join(), 'on,on,on,on,on');
  assert.equal(els.get('agent-word').textContent, 'REFUSED');
  agent.update(script(await live('patched')));
  assert.deepEqual([els.get('agent-word').textContent, els.get('agent-src').textContent, rows().join()], ['REFUSED', 'Recorded', 'on,on,on,on,on']);
  assert.equal(timers.length, 0);
});

test('with no refusal to show, the outcome row is hidden and today stays', async () => {
  const { agent, els, rows, advance } = panel();
  agent.update(script({ ...(await live('patched')), recorded: null }));
  advance(10_000);
  assert.deepEqual([els.get('agent-row-out').hidden, els.get('agent-row-check').hidden, els.get('agent-today-word').textContent], [true, false, 'ALLOWED']);
  agent.update(script(await live('patched')));
  assert.equal(els.get('agent-row-out').hidden, false, 'a refusal on record brings it back');
});

test('the section hides when there is no address, shows again with one, and the replay button plays everything again', async () => {
  const { agent, els, rows, advance, clicks } = panel();
  agent.update({ show: false, key: null });
  assert.equal(els.get('swap-agent').hidden, true);
  agent.update(script(await live('vulnerable')));
  assert.equal(els.get('swap-agent').hidden, false);
  advance(10_000);
  assert.equal(rows().join(), 'on,on,on,on,on');
  clicks['agent-replay']();
  assert.equal(rows().join(), 'on,off,off,off,off', 'from the first row');
  advance(10_000);
  assert.deepEqual([rows().join(), els.get('agent-word').textContent], ['on,on,on,on,on', 'REFUSED']);
});

test('the staging waits until the panel is on screen, then plays from the first row with the verdict that is current by then', async () => {
  let seen = null;
  const { agent, els, rows, advance, timers } = panel({ seen: (el, run) => { seen = run; } });
  agent.update(script(await live('vulnerable')));
  advance(10_000);
  assert.equal(rows().join(), 'off,off,off,off,off', 'not seen: every row waits (the page ships them showing, so it reads without script) and nothing is scheduled');
  assert.equal(timers.length, 0);
  assert.equal(els.get('swap-agent').hidden, false, 'the section itself is there to be seen');
  agent.update(script(await live('patched')));
  seen();
  advance(10_000);
  assert.deepEqual([els.get('agent-today-src').textContent, els.get('agent-src').textContent, rows().join()], ['Live read', 'Recorded', 'on,on,on,on,on'], 'the latest verdict, not the one read first');
  agent.update(script(await live('vulnerable')));
  assert.equal(rows().join(), 'on,on,on,off,off', 'once seen, a swap replays the check at once');
});

test('the ids the panel looks for are all in the page', async () => {
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(new URL('../src/index.html', import.meta.url), 'utf8');
  for (const id of Object.values(AGENT_IDS)) assert.match(html, new RegExp(`id="${id}"`), id);
});
