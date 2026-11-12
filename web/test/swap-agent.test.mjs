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

test('a BLOCK is REFUSED, and its log line has the guard\'s fields in the guard\'s order, with the live hash and rule', async () => {
  const a = script(await live('vulnerable'));
  assert.deepEqual([a.outcome.word, a.outcome.tone, a.verdict, a.codeHash], ['REFUSED', 'block', 'Unsafe (PF001)', HASH.vulnerable]);
  assert.equal(a.plain, 'The code at this address is the one with the hole.');
  assert.equal(a.call, `${ADDRESS}.deposit with 0.5 NEAR`);
  const entry = JSON.parse(a.log);
  assert.deepEqual(Object.keys(entry), ['timestamp', 'contract', 'method', 'deposit', 'codeHash', 'decision', 'outcome', 'reasons']);
  assert.deepEqual(entry, {
    timestamp: '2026-11-11T20:00:00.000Z', contract: ADDRESS, method: 'deposit', deposit: CALL.deposit, codeHash: HASH.vulnerable, decision: 'block', outcome: 'refused',
    reasons: ['registry verdict Unsafe (PF001): published by auditor.example.testnet, report https://example.com/vulnerable.json'],
  });
  assert.match(a.outcome.line, /Nothing was signed or sent\. On this build anyone can credit themselves a balance without paying and withdraw what the agent deposits \(PF001\)\.$/);
  assert.equal(CALL.deposit, '500000000000000000000000', '0.5 NEAR in yoctoNEAR');
  assert.match(a.log, /\n  "decision": "block",\n/, 'one field per line, so the log wraps at fields and not mid-word');
});

test('an ALLOW says the call would be signed and not sent; its log line is the one the guard writes before signing', async () => {
  const a = script(await live('patched'));
  assert.deepEqual([a.outcome.word, a.outcome.tone, a.verdict], ['ALLOWED', 'allow', 'Safe']);
  assert.equal(a.outcome.line, 'ALLOWED is the right answer for this code: it is the fixed build. Guard allows; the call would be signed (not sent in this demo). No known issue fired on this exact code (the chain stores that status under the name Safe): the vault credits the deposit to the agent, less its 1% fee, and the agent can withdraw it.');
  const entry = JSON.parse(a.log);
  assert.deepEqual([entry.decision, entry.outcome, entry.codeHash], ['allow', 'approved', HASH.patched]);
  assert.equal(entry.reasons[0], 'registry verdict Safe: published by auditor.example.testnet, report https://example.com/patched.json');
});

test('fixed code live after a swap: ALLOWED is called the right answer, and the same call on the other build is shown REFUSED, from its registry verdict', async () => {
  const state = await live('patched', (chain) => { chain.lastFlipMs = chain.nowMs - 5 * 60_000; });
  const a = script(state);
  assert.equal(a.outcome.word, 'ALLOWED');
  assert.match(a.outcome.line, /^ALLOWED is the right answer for this code: it is the fixed build\./);
  assert.deepEqual([a.contrast.word, a.contrast.tone, a.contrast.hash], ['REFUSED', 'block', HASH.vulnerable]);
  assert.equal(a.contrast.line, 'The same call on the other code that ran at this address: the registry verdict for it is Unsafe (PF001), so the guard stops the call before signing. On that code anyone can credit themselves a balance without paying and withdraw what the agent deposits (PF001).');
  assert.notEqual(a.key, script(await live('patched')).key, 'the panel plays again when the contrast appears');
  assert.equal(script(await live('patched')).contrast, null, 'no swap on record, no contrast');
  assert.equal(script(await live('vulnerable', (chain) => { chain.lastFlipMs = chain.nowMs - 60_000; })).contrast, null, 'the refusal is the story already');
});

test('code with no verdict is declined, with the two reasons the guard gives', async () => {
  const a = script(await live('vulnerable', (chain) => { delete chain.verdicts[HASH.vulnerable]; }));
  assert.deepEqual([a.outcome.word, a.outcome.tone, a.verdict], ['DECLINED', 'warn', 'none: unaudited code, or code changed since its audit']);
  assert.deepEqual(JSON.parse(a.log).reasons, [`code hash ${HASH.vulnerable} has no verdict in the registry: unaudited code, or code changed since its audit`, 'not approved by the approval callback']);
  assert.equal(JSON.parse(a.log).outcome, 'refused');
});

test('the same call on the same decision as the Preflight card: the panel never decides on its own', async () => {
  for (const build of ['vulnerable', 'patched']) {
    const state = await live(build);
    const m = viewModel(state, { now: AT, explorerUrl: 'https://testnet.near.rocks' });
    assert.equal(JSON.parse(m.agent.log).decision, m.pf.word.toLowerCase());
    assert.equal(m.agent.outcome.word === 'REFUSED', m.pf.word === 'BLOCK');
  }
});

test('chain text in the log line is validated: a bad auditor or report link is left out, and never reaches the line', async () => {
  const state = await live('vulnerable', (chain) => { Object.assign(chain.verdicts[HASH.vulnerable], { auditor: 'Not An Id <b>', report_url: 'javascript:alert(1)' }); });
  assert.deepEqual([state.verdict.auditor, state.verdict.reportUrl], [null, null]);
  assert.deepEqual(JSON.parse(script(state).log).reasons, ['registry verdict Unsafe (PF001)']);
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

test('recorded: the replay shows REFUSED, then ALLOWED, with no time claimed and the note saying it is not a live check', () => {
  const base = { ...createSwap({ config: CONFIG, recorded }).getState(), mode: 'recorded', reason: 'rpc-down' };
  const first = script(base);
  const second = script({ ...base, replay: 1 });
  assert.deepEqual([first.outcome.word, second.outcome.word], ['REFUSED', 'ALLOWED']);
  assert.equal(JSON.parse(first.log).timestamp, undefined);
  assert.deepEqual(JSON.parse(first.log).reasons, ['registry verdict Unsafe (PF001): report https://example.com/r']);
  assert.match(first.note, /^Composed from the recorded verdict, not a live check/);
  assert.notEqual(first.key, second.key, 'each recorded swap plays again');
  assert.notEqual(script({ ...base, replay: 2 }).key, second.key, 'even two steps with the same build');
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
  assert.deepEqual([els.get('agent-word').textContent, els.get('agent-out').attrs['data-tone']], ['REFUSED', 'block']);
  assert.ok(ROW_DELAYS.at(-1) < 5000, 'the whole play is short');
});

test('a swap replays only the check and the outcome, and the same verdict read again plays nothing', async () => {
  const { agent, els, rows, advance, timers } = panel();
  const vulnerable = script(await live('vulnerable'));
  agent.update(vulnerable);
  advance(10_000);
  assert.deepEqual([els.get('agent-word').textContent, rows().join()], ['REFUSED', 'on,on,on,on,on']);
  const scheduled = timers.length;
  agent.update({ ...vulnerable, log: 'another timestamp' });
  assert.equal(timers.length, scheduled, 'a poll that read the same code changes nothing');
  assert.equal(els.get('agent-log').textContent, vulnerable.log);
  agent.update(script(await live('patched')));
  assert.deepEqual(rows(), ['on', 'on', 'on', 'off', 'off'], 'the agent stays, the guard check starts over');
  advance(10_000);
  assert.deepEqual([els.get('agent-word').textContent, els.get('agent-out').attrs['data-tone'], els.get('agent-verdict').textContent, rows().join()], ['ALLOWED', 'allow', 'Safe', 'on,on,on,on,on']);
  agent.update(vulnerable);
  advance(10_000);
  assert.equal(els.get('agent-word').textContent, 'REFUSED', 'and back');
});

test('reduced motion: the final state at once, and no timer is ever set', async () => {
  const { agent, els, rows, timers } = panel({ calm: true });
  agent.update(script(await live('vulnerable')));
  assert.equal(rows().join(), 'on,on,on,on,on');
  assert.equal(els.get('agent-word').textContent, 'REFUSED');
  agent.update(script(await live('patched')));
  assert.deepEqual([els.get('agent-word').textContent, rows().join()], ['ALLOWED', 'on,on,on,on,on']);
  assert.equal(timers.length, 0);
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
  assert.deepEqual([els.get('agent-word').textContent, rows().join()], ['ALLOWED', 'on,on,on,on,on'], 'the latest verdict, not the one read first');
  agent.update(script(await live('vulnerable')));
  assert.equal(rows().join(), 'on,on,on,off,off', 'once seen, a swap replays the check at once');
});

test('the ids the panel looks for are all in the page', async () => {
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(new URL('../src/index.html', import.meta.url), 'utf8');
  for (const id of Object.values(AGENT_IDS)) assert.match(html, new RegExp(`id="${id}"`), id);
});
