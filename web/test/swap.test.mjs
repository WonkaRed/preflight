// The Swap's controller (src/swap.js) against a fake NEAR node (test/swap-chain.mjs): what it reads, what it decides,
// and what it does in every failure state. Signing is the real WebCrypto; only the network is fake.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { base58Encode } from '../src/near.js';
import { createSwap, parseRecorded, readConfig } from '../src/swap.js';
import { CONFIG, fakeChain, HASH, recordedJson, status, UNSET_CONFIG } from './swap-chain.mjs';

const recorded = parseRecorded(recordedJson);

function setup(chain, { config = CONFIG, rec = recorded, env = {} } = {}) {
  const states = [];
  const swap = createSwap({ config, recorded: rec, onChange: (s) => states.push(s), env: { fetch: (...args) => chain.fetch(...args), now: () => chain.nowMs, sleep: async () => {}, ...env } });
  return { swap, states, state: () => swap.getState() };
}
const sends = (chain) => chain.calls.filter((c) => c.method === 'send_tx');

test('an unset config starts the page on the recording and sends nothing anywhere', async () => {
  const chain = fakeChain();
  const { swap, state } = setup(chain, { config: UNSET_CONFIG });
  await swap.start();
  assert.equal(chain.calls.length, 0, 'an unset config makes no request');
  assert.deepEqual([state().mode, state().reason], ['recorded', 'unconfigured']);
  assert.match(state().detail, /chameleonId, switchId, registryId, flipKey/);
  assert.equal(state().address, 'chameleon.example.testnet', 'the recording names the address');
  swap.stop();
});

test('an unset config and no recording is the empty state, not an error', async () => {
  const { swap, state } = setup(fakeChain(), { config: UNSET_CONFIG, rec: null });
  await swap.start();
  assert.deepEqual([state().mode, state().reason, state().address], ['empty', 'unconfigured', null]);
  await swap.flip();
  assert.equal(state().mode, 'empty', 'the button does nothing');
});

test('readConfig names every empty or malformed field, defaults the signer to the switch, and converts gas', () => {
  assert.deepEqual(readConfig(UNSET_CONFIG).missing, ['chameleonId', 'switchId', 'registryId', 'flipKey']);
  assert.deepEqual(readConfig({ ...CONFIG, chameleonId: 'Not An Id', flipKey: 'ed25519:abc', rpcUrl: 'http://x', flipGasTgas: 0, flipSignerId: '..' }).missing,
    ['chameleonId', 'flipSignerId', 'flipKey', 'rpcUrl', 'flipGasTgas']);
  const ok = readConfig(CONFIG);
  assert.equal(ok.ok, true);
  assert.equal(ok.flipSignerId, CONFIG.switchId);
  assert.equal(ok.gas, 150_000_000_000_000n);
  assert.equal(readConfig({ ...CONFIG, flipSignerId: 'bot.example.testnet' }).flipSignerId, 'bot.example.testnet');
});

test('parseRecorded accepts the documented file and refuses anything else', () => {
  assert.equal(recorded.recordedAt, '2026-11-11');
  assert.equal(recorded.chameleonId, 'chameleon.example.testnet');
  assert.deepEqual(recorded.steps.map((s) => [s.build, s.decision, s.ruleIds.join(), s.txHash === null]),
    [['vulnerable', 'BLOCK', 'PF001', true], ['patched', 'ALLOW', '', false], ['vulnerable', 'BLOCK', 'PF001', false], ['patched', 'ALLOW', '', false], ['vulnerable', 'BLOCK', 'PF001', false]]);
  assert.equal(recorded.steps[1].txHash, recordedJson.flips[0].txHash);
  const bad = (mutate) => { const copy = structuredClone(recordedJson); mutate(copy); return parseRecorded(copy); };
  assert.equal(parseRecorded(null), null);
  assert.equal(parseRecorded([]), null);
  assert.equal(bad((r) => { r.flips = []; }), null, 'an empty recording is no recording');
  assert.equal(bad((r) => { r.recordedAt = 'yesterday'; }), null);
  assert.equal(bad((r) => { r.chameleon = 'A B'; }), null);
  assert.equal(bad((r) => { r.flips[0].txHash = '<script>'; }), null);
  assert.equal(bad((r) => { r.flips[0].after.live = 'other'; }), null);
  assert.equal(bad((r) => { r.flips[0].before.codeHash = 'abc'; }), null);
  assert.equal(bad((r) => { r.flips[1].after.decision = 'maybe'; }), null);
  assert.equal(bad((r) => { r.flips[1].after.verdict.status = 'Maybe'; }), null);
  assert.equal(bad((r) => { r.flips[1].after.verdict.rule_ids = ['x']; }), null);
  assert.equal(bad((r) => { delete r.flips[1].after.verdict; }), null, 'a missing verdict is not the same as no verdict (null)');
  assert.equal(bad((r) => { r.flips[1].after.verdict = null; r.flips[1].after.decision = 'warn'; }).steps[2].decision, 'WARN');
});

test('live: the vulnerable build is BLOCK with its rule, read by the hash of the code bytes', async () => {
  const chain = fakeChain();
  const { swap, state } = setup(chain);
  await swap.refresh();
  assert.equal(state().mode, 'live');
  assert.equal(state().codeHash, HASH.vulnerable);
  assert.equal(state().build, 'vulnerable');
  assert.deepEqual(state().verdict, { decision: 'BLOCK', ruleIds: ['PF001'], registered: true });
  assert.equal(state().flips, 3);
  const lookup = chain.calls.find((c) => c.params?.method_name === 'get_verdict');
  assert.deepEqual(JSON.parse(Buffer.from(lookup.params.args_base64, 'base64')), { code_hash: HASH.vulnerable }, 'the registry is asked about the hash');
  assert.ok(chain.calls.every((c) => c.url === CONFIG.rpcUrl));
});

test('live: the patched build is ALLOW', async () => {
  const chain = fakeChain();
  chain.build = 'patched';
  const { swap, state } = setup(chain);
  await swap.refresh();
  assert.deepEqual([state().build, state().verdict.decision, state().verdict.ruleIds], ['patched', 'ALLOW', []]);
});

test('live: code with no registry verdict is WARN, and a Warn verdict is WARN with its rules', async () => {
  const chain = fakeChain();
  delete chain.verdicts[HASH.vulnerable];
  const { swap, state } = setup(chain);
  await swap.refresh();
  assert.deepEqual(state().verdict, { decision: 'WARN', ruleIds: [], registered: false });
  chain.verdicts[HASH.vulnerable] = { code_hash: HASH.vulnerable, status: 'Warn', rule_ids: ['PF012'] };
  await swap.refresh();
  assert.deepEqual(state().verdict, { decision: 'WARN', ruleIds: ['PF012'], registered: true });
});

test('live: a hash that is neither build the switch knows has no build label, and the registry still decides', async () => {
  const chain = fakeChain();
  chain.statusOverride = status(1, 0, { vulnerable: HASH.patched, patched: HASH.patched });
  const { swap, state } = setup(chain);
  await swap.refresh();
  assert.equal(state().build, null);
  assert.equal(state().verdict.decision, 'BLOCK');
});

test('the code bytes are hashed once per new hash, not at every poll', async () => {
  const chain = fakeChain();
  const { swap } = setup(chain);
  await swap.refresh();
  await swap.refresh();
  assert.equal(chain.calls.filter((c) => c.params?.request_type === 'view_code').length, 1);
});

test('failures reading the chain fall back to the recording, labeled RPC unreachable, and live returns on its own', async () => {
  const chain = fakeChain();
  const { swap, state } = setup(chain);
  chain.down = true;
  await swap.refresh();
  assert.deepEqual([state().mode, state().reason], ['recorded', 'rpc-down']);
  assert.match(state().detail, /RPC .* request failed/);
  chain.down = false;
  await swap.refresh();
  assert.equal(state().mode, 'live');
  assert.equal(state().reason, null);
});

test('an RPC that answers wrongly is never a verdict: HTTP errors, JSON-RPC errors, and answers of the wrong shape all fall back', async () => {
  const cases = {
    http: (chain) => { const f = chain.fetch; chain.fetch = async (...a) => ({ ...(await f(...a)), ok: false, status: 503 }); },
    'rpc error': (chain) => { chain.fetch = async () => ({ ok: true, json: async () => ({ error: { cause: { name: 'UNKNOWN_ACCOUNT' } } }) }); },
    'status shape': (chain) => { chain.statusOverride = { flips: 1 }; },
    'status counts': (chain) => { chain.statusOverride = status(-1, 0); },
    'bad verdict': (chain) => { chain.verdicts[HASH.vulnerable] = { code_hash: HASH.patched, status: 'Safe', rule_ids: [] }; },
    'unknown status word': (chain) => { chain.verdicts[HASH.vulnerable] = { code_hash: HASH.vulnerable, status: 'Fine', rule_ids: [] }; },
    'bad rule id': (chain) => { chain.verdicts[HASH.vulnerable] = { code_hash: HASH.vulnerable, status: 'Unsafe', rule_ids: ['<b>'] }; },
    'code bytes do not match the reported hash': (chain) => { chain.codeOverride = new TextEncoder().encode('something else'); },
  };
  for (const [name, break_] of Object.entries(cases)) {
    const chain = fakeChain();
    break_(chain);
    const { swap, state } = setup(chain);
    await swap.refresh();
    assert.deepEqual([state().mode, state().reason], ['recorded', 'rpc-down'], name);
    assert.notEqual(state().verdict?.decision, 'ALLOW', name);
  }
});

test('RPC down with no recording is the empty state, saying so', async () => {
  const chain = fakeChain();
  chain.down = true;
  const { swap, state } = setup(chain, { rec: null });
  await swap.refresh();
  assert.deepEqual([state().mode, state().reason], ['empty', 'rpc-down']);
});

test('the recording replays one swap per click and wraps around, sending nothing', async () => {
  const chain = fakeChain();
  chain.down = true;
  const { swap, state } = setup(chain);
  await swap.refresh();
  const before = chain.calls.length;
  const seen = [state().replay];
  for (let i = 0; i < 5; i++) { await swap.flip(); seen.push(state().replay); }
  assert.deepEqual(seen, [0, 1, 2, 3, 4, 0]);
  assert.equal(chain.calls.length, before, 'a replay makes no request');
});

test('a swap inside the contract interval shows a countdown and sends nothing; after it, the swap goes through', async () => {
  const chain = fakeChain();
  chain.nextFlipMs = chain.nowMs + 6000; // the last flip was 4 s ago, of 10 s
  const { swap, state } = setup(chain);
  await swap.refresh();
  assert.equal(state().waitUntil, chain.nowMs + 6000 + 1000);
  await swap.flip();
  assert.equal(sends(chain).length, 0);
  chain.nowMs += 7001;
  await swap.flip();
  assert.equal(sends(chain).length, 1);
});

test('a swap signs a real transaction, waits for the new code, then re-reads hash and verdict', async () => {
  const chain = fakeChain();
  chain.lagAfterSend = 2;
  const { swap, states, state } = setup(chain);
  await swap.refresh();
  await swap.flip();
  assert.equal(sends(chain).length, 1);
  const { signed_tx_base64: b64, wait_until: wait } = sends(chain)[0].params;
  assert.equal(wait, 'EXECUTED_OPTIMISTIC');
  const bytes = Buffer.from(b64, 'base64');
  const tx = bytes.subarray(0, bytes.length - 65);
  assert.ok(tx.includes('flip') && tx.includes(CONFIG.switchId));
  assert.equal(state().tx.hash, base58Encode(createHash('sha256').update(tx).digest()), 'the shown hash is the explorer id of what was sent');
  assert.deepEqual(states.map((s) => s.tx?.stage).filter((stage, i, all) => stage !== all[i - 1]), ['pending', 'landing', 'done']);
  assert.deepEqual([state().tx.stage, state().build, state().verdict.decision, state().flips], ['done', 'patched', 'ALLOW', 4]);
  assert.ok(state().waitUntil > chain.nowMs, 'the countdown starts after a swap');
});

test('the nonce is the access key\'s nonce plus one', async () => {
  const chain = fakeChain();
  chain.nonce = 777;
  const { swap } = setup(chain);
  await swap.refresh();
  await swap.flip();
  const bytes = Buffer.from(sends(chain)[0].params.signed_tx_base64, 'base64');
  const at = 4 + CONFIG.switchId.length + 1 + 32; // signer id, key type, public key
  assert.equal(bytes.readBigUInt64LE(at), 778n);
});

test('a swap whose code never shows up says so instead of claiming success', async () => {
  const chain = fakeChain();
  chain.lagAfterSend = 1000;
  const { swap, state } = setup(chain);
  await swap.refresh();
  await swap.flip();
  assert.equal(state().tx.stage, 'unseen');
});

test('a nonce collision with another visitor reads the key again and signs again', async () => {
  const chain = fakeChain();
  chain.sendErrors = [{ name: 'HANDLER_ERROR', cause: { name: 'INVALID_TRANSACTION', info: { InvalidNonce: { tx_nonce: 1001, ak_nonce: 1005 } } } }];
  const { swap, state } = setup(chain);
  await swap.refresh();
  await swap.flip();
  assert.equal(sends(chain).length, 2);
  assert.equal(state().tx.stage, 'done');
});

test('nonce collisions that never clear end as a failed swap with the RPC\'s name for it', async () => {
  const chain = fakeChain();
  const collision = { name: 'HANDLER_ERROR', cause: { name: 'INVALID_TRANSACTION', info: { InvalidNonce: {} } } };
  chain.sendErrors = [collision, collision, collision, collision];
  const { swap, state } = setup(chain);
  await swap.refresh();
  await swap.flip();
  assert.equal(sends(chain).length, 3);
  assert.equal(state().tx.stage, 'failed');
  assert.match(state().tx.message, /INVALID_TRANSACTION/);
});

test('the contract refusing a swap (too soon, racing another visitor) shows its own words and then the countdown', async () => {
  const chain = fakeChain();
  chain.sendResult = { status: { Failure: { ActionError: { index: 0, kind: { FunctionCallError: { ExecutionError: 'Smart contract panicked: flip too soon, wait 4 s' } } } } } };
  const { swap, state } = setup(chain);
  await swap.refresh();
  await swap.flip();
  assert.equal(state().tx.stage, 'failed');
  assert.equal(state().tx.message, 'The contract refused the swap: flip too soon, wait 4 s');
  assert.ok(state().waitUntil > chain.nowMs, 'the re-read shows the new interval');
  assert.equal(state().mode, 'live');
});

test('a used-up key allowance, or a deleted key, switches to the recording and says why, for good', async () => {
  for (const spent of [
    (chain) => { chain.sendErrors = [{ name: 'HANDLER_ERROR', cause: { name: 'INVALID_TRANSACTION', info: { tx_execution_error: { InvalidTxError: { InvalidAccessKeyError: { NotEnoughAllowance: { allowance: '1', cost: '2' } } } } } } }]; },
    (chain) => { chain.accessKeyError = 'UNKNOWN_ACCESS_KEY'; },
  ]) {
    const chain = fakeChain();
    const { swap, state } = setup(chain);
    await swap.refresh();
    spent(chain);
    await swap.flip();
    assert.deepEqual([state().mode, state().reason, state().tx], ['recorded', 'allowance', null]);
    const calls = chain.calls.length;
    await swap.refresh();
    assert.equal(chain.calls.length, calls, 'it stops reading: there is nothing live left to show');
  }
});

test('a failure before anything was sent says nothing was sent; a lost answer after sending is unconfirmed, with the hash', async () => {
  const chain = fakeChain();
  const { swap, state } = setup(chain);
  await swap.refresh();
  const fetch = chain.fetch;
  chain.fetch = async (url, init) => { if (JSON.parse(init.body).method === 'block' && JSON.parse(init.body).params.finality === 'final') throw new TypeError('offline'); return fetch(url, init); };
  await swap.flip();
  assert.equal(state().tx.stage, 'failed');
  assert.equal(state().tx.hash, null);
  assert.match(state().tx.message, /^Nothing was sent\./);

  chain.fetch = async (url, init) => { if (JSON.parse(init.body).method === 'send_tx') throw new TypeError('connection reset'); return fetch(url, init); };
  await swap.flip();
  assert.equal(state().tx.stage, 'unconfirmed');
  assert.ok(state().tx.hash);
  assert.equal(sends(chain).length, 0, 'the fake node never saw it');
});

test('a browser that cannot sign ed25519 fails the click with a plain message and sends nothing', async () => {
  const chain = fakeChain();
  const subtle = { digest: (...args) => globalThis.crypto.subtle.digest(...args), importKey: async () => { throw Object.assign(new Error('x'), { name: 'NotSupportedError' }); } };
  const { swap, state } = setup(chain, { env: { subtle } });
  await swap.refresh();
  await swap.flip();
  assert.deepEqual([state().tx.stage, state().tx.message], ['failed', 'this browser cannot sign with ed25519 (WebCrypto)']);
  assert.equal(sends(chain).length, 0);
});

test('two clicks at once send one transaction', async () => {
  const chain = fakeChain();
  const { swap } = setup(chain);
  await swap.refresh();
  await Promise.all([swap.flip(), swap.flip()]);
  assert.equal(sends(chain).length, 1);
});

test('start reads at once and then on a timer, stop ends it, and a hidden tab does not read', async () => {
  const chain = fakeChain();
  const { swap, state } = setup(chain);
  await swap.start();
  assert.equal(state().mode, 'live');
  swap.stop();
  const hidden = setup(fakeChain(), { env: { hidden: () => true } });
  await hidden.swap.start();
  assert.equal(hidden.state().mode, 'loading', 'nothing is read for a tab nobody sees');
  hidden.swap.stop();
});
