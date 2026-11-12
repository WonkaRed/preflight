// The Swap's controller (src/swap.js) against a fake NEAR node (test/swap-chain.mjs): what it reads, what it decides,
// and what it does in every failure state. Signing is the real WebCrypto; only the network is fake.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { base58Encode } from '../src/near.js';
import { ACTIVE_MS, createSwap, IDLE_POLL_MS, parseRecorded, POLL_MS, readConfig } from '../src/swap.js';
import { CONFIG, fakeChain, flipTxResult, HASH, recordedJson, status, UNSET_CONFIG } from './swap-chain.mjs';

const recorded = parseRecorded(recordedJson);

function setup(chain, { config = CONFIG, rec = recorded, env = {} } = {}) {
  const states = [];
  const swap = createSwap({ config, recorded: rec, onChange: (s) => states.push(s), env: { fetch: (...args) => chain.fetch(...args), now: () => chain.nowMs, sleep: async () => {}, storage: memoryStorage(), ...env } });
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
  assert.deepEqual(readConfig({ ...CONFIG, chameleonId: 'Not An Id', flipKey: 'ed25519:abc', rpcUrls: ['http://x'], flipGasTgas: 0, flipSignerId: '..' }).missing,
    ['chameleonId', 'flipSignerId', 'flipKey', 'rpcUrls', 'flipGasTgas']);
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
  assert.deepEqual(state().verdict, { decision: 'BLOCK', ruleIds: ['PF001'], registered: true, auditor: 'auditor.example.testnet', reportUrl: 'https://example.com/vulnerable.json' });
  assert.equal(state().flips, 3);
  const lookup = chain.calls.find((c) => c.params?.method_name === 'get_verdict');
  assert.deepEqual(JSON.parse(Buffer.from(lookup.params.args_base64, 'base64')), { code_hash: HASH.vulnerable }, 'the registry is asked about the hash');
  assert.ok(chain.calls.every((c) => CONFIG.rpcUrls.includes(c.url)));
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
  assert.deepEqual(state().verdict, { decision: 'WARN', ruleIds: [], registered: false, auditor: null, reportUrl: null });
  chain.verdicts[HASH.vulnerable] = { code_hash: HASH.vulnerable, status: 'Warn', rule_ids: ['PF012'] };
  await swap.refresh();
  assert.deepEqual(state().verdict, { decision: 'WARN', ruleIds: ['PF012'], registered: true, auditor: null, reportUrl: null });
});

test('live: a hash that is neither build the switch knows has no build label, and the registry still decides', async () => {
  const chain = fakeChain();
  chain.statusOverride = status(1, 0, { vulnerable: HASH.patched, patched: HASH.patched });
  const { swap, state } = setup(chain);
  await swap.refresh();
  assert.equal(state().build, null);
  assert.equal(state().verdict.decision, 'BLOCK');
});

// ---- the build that ran here before the last swap --------------------------------------------------------------------

const settle = async (done) => { for (let i = 0; i < 100 && !done(); i++) await new Promise((resolve) => setImmediate(resolve)); };
const SWAP_TX = base58Encode(createHash('sha256').update('the last swap').digest());
/** The fixed build is live, the last swap ran `minutes` ago, and its transaction is on chain. */
function afterSwap(minutes = 5, mutate = () => {}) {
  const chain = fakeChain();
  chain.build = 'patched';
  chain.lastFlipMs = chain.nowMs - minutes * 60_000;
  chain.swapTx = { hash: SWAP_TX, result: flipTxResult };
  mutate(chain);
  return chain;
}

test('fixed code live after a swap: the other build\'s verdict is read from the registry, with when it was swapped and the swap\'s transaction found on chain', async () => {
  const chain = afterSwap(5);
  const { swap, state } = setup(chain);
  await swap.refresh();
  assert.deepEqual([state().verdict.decision, state().build], ['ALLOW', 'patched']);
  const { before } = state();
  assert.deepEqual([before.build, before.codeHash, before.verdict.decision, before.verdict.ruleIds], ['vulnerable', HASH.vulnerable, 'BLOCK', ['PF001']]);
  assert.equal(before.swappedAt, chain.nowMs - 5 * 60_000, 'the age is the chain\'s: block time minus the swap time');
  assert.equal(before.txHash, null, 'the link is looked for after the verdicts are shown');
  await settle(() => state().before.txHash !== null);
  assert.equal(state().before.txHash, SWAP_TX);
  const reads = chain.calls.length;
  await swap.refresh();
  assert.equal(state().before.txHash, SWAP_TX, 'kept across reads');
  assert.equal(chain.calls.slice(reads).filter((c) => c.method === 'EXPERIMENTAL_changes' || c.method === 'tx').length, 0, 'found once per swap, not at every poll');
});

test('the swap transaction is found whatever the block rate, over skipped heights, and when its receipt ran one block after the transaction', async () => {
  for (const [blockMs, skipped, late] of [[600, [], 0], [1300, [], 0], [600, [999_820, 999_821], 0], [1000, [], -1]]) {
    const chain = afterSwap(5, (c) => { c.blockMs = blockMs; c.lastFlipMs = c.nowMs - 300 * blockMs; c.skipped = new Set(skipped); c.swapTx.blocksLate = late; });
    const { swap, state } = setup(chain);
    await swap.refresh();
    await settle(() => state().before.txHash !== null);
    assert.equal(state().before.txHash, SWAP_TX, `block rate ${blockMs}, skipped ${skipped}, late ${late}`);
  }
});

test('no swap transaction link when the chain gives none, when it is not a successful flip, or when the lookup fails; the contrast stays', async () => {
  const cases = {
    'no change in that block': (c) => { c.swapTx = null; },
    'not a flip': (c) => { c.swapTx.result = { ...flipTxResult, transaction: { ...flipTxResult.transaction, actions: [{ FunctionCall: { method_name: 'other' } }] } }; },
    'another receiver': (c) => { c.swapTx.result = { ...flipTxResult, transaction: { ...flipTxResult.transaction, receiver_id: 'evil.testnet' } }; },
    'a failed transaction': (c) => { c.swapTx.result = { ...flipTxResult, status: { Failure: {} } }; },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const chain = afterSwap(5, mutate);
    const { swap, state } = setup(chain);
    await swap.refresh();
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(state().before.verdict.decision, 'BLOCK', name);
    assert.equal(state().before.txHash, null, name);
  }
  const chain = afterSwap(5);
  const { swap, state } = setup(chain);
  chain.skipped = new Set(Array.from({ length: 400 }, (_, i) => 999_700 + i));
  await swap.refresh();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(state().mode, 'live');
  assert.equal(state().before.txHash, null, 'a search that finds no block gives up quietly');
});

test('a failed lookup is tried again at later reads, at most three times for one swap', async () => {
  const chain = afterSwap(5, (c) => { c.swapTx = null; });
  const { swap, state } = setup(chain);
  const lookups = () => chain.calls.filter((c) => c.method === 'EXPERIMENTAL_changes').length;
  for (let read = 0; read < 5; read++) { await swap.refresh(); await new Promise((resolve) => setTimeout(resolve, 20)); }
  assert.equal(lookups(), 3 * 2, 'two blocks looked at per try');
  chain.swapTx = { hash: SWAP_TX, result: flipTxResult };
  chain.lastFlipMs -= 1000; // a new swap: its own three tries
  await swap.refresh();
  await settle(() => state().before.txHash !== null);
  assert.equal(state().before.txHash, SWAP_TX);
});

test('no contrast data when the vulnerable build is live, when nothing was ever swapped, when the switch disagrees about what is live, or when the other build cannot be read', async () => {
  const cases = {
    'vulnerable is live': (c) => { c.build = 'vulnerable'; },
    'no swap yet': (c) => { c.flips = 0; },
    'last swap time unknown': (c) => { c.lastFlipMs = 0; },
    'the switch has not caught up': (c) => { c.statusLive = 'vulnerable'; },
    'swap time in the future': (c) => { c.lastFlipMs = c.nowMs + 5000; },
    'other build has a malformed verdict': (c) => { c.verdicts[HASH.vulnerable] = { code_hash: 'x', status: 'Unsafe', rule_ids: [] }; },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const chain = afterSwap(5, mutate);
    const { swap, state } = setup(chain);
    await swap.refresh();
    assert.equal(state().mode, 'live', name);
    assert.equal(state().before, null, name);
  }
  const chain = afterSwap(5);
  const { swap, state } = setup(chain);
  chain.build = 'vulnerable';
  await swap.refresh();
  assert.equal(chain.calls.filter((c) => c.params?.method_name === 'get_verdict').length, 2, 'the live verdict and the other build\'s');
  assert.equal(state().before, null, 'a live BLOCK has no contrast');
  assert.deepEqual([state().other.build, state().other.codeHash, state().other.verdict.decision], ['patched', HASH.patched, 'ALLOW'], 'the other build is still read, for the agent panel');
});

test('the other build is read from status() and the registry whatever the swap history, and is null when it cannot be read', async () => {
  const fresh = fakeChain();
  fresh.build = 'patched';
  fresh.flips = 0;
  const first = setup(fresh);
  await first.swap.refresh();
  assert.equal(first.state().before, null, 'nothing was swapped yet');
  assert.deepEqual([first.state().other.build, first.state().other.codeHash, first.state().other.verdict.decision, first.state().other.verdict.ruleIds], ['vulnerable', HASH.vulnerable, 'BLOCK', ['PF001']]);
  const unread = fakeChain();
  unread.build = 'patched';
  delete unread.verdicts[HASH.vulnerable];
  const second = setup(unread);
  await second.swap.refresh();
  assert.equal(second.state().other.verdict.registered, false, 'no verdict is a Warn, as the card shows it');
  const broken = fakeChain();
  broken.build = 'patched';
  broken.verdicts[HASH.vulnerable] = { code_hash: 'x', status: 'Unsafe', rule_ids: [] };
  const third = setup(broken);
  await third.swap.refresh();
  assert.deepEqual([third.state().mode, third.state().other], ['live', null], 'a malformed other verdict never fails the read');
});

test('the contrast goes away when the visitor swaps back to the vulnerable build', async () => {
  const chain = afterSwap(5);
  const { swap, state } = setup(chain);
  await swap.refresh();
  assert.ok(state().before);
  await swap.flip();
  assert.equal(state().build, 'vulnerable');
  assert.equal(state().before, null);
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

test('every way the demo key can stop paying switches to the recording and says why, for good', async () => {
  const refused = (error) => (chain) => { chain.sendErrors = [{ name: 'HANDLER_ERROR', cause: { name: 'INVALID_TRANSACTION', info: { tx_execution_error: { InvalidTxError: error } } } }]; };
  const failedOnChain = (kind) => (chain) => { chain.sendResult = { status: { Failure: { ActionError: { index: 0, kind } } } }; };
  for (const spent of [
    refused({ InvalidAccessKeyError: { NotEnoughAllowance: { allowance: '1', cost: '2' } } }),
    refused({ NotEnoughBalance: { signer_id: 'switch.example.testnet', balance: '1', cost: '2' } }),
    refused({ LackBalanceForState: { signer_id: 'switch.example.testnet', amount: '1' } }),
    refused({ SignerDoesNotExist: { signer_id: 'switch.example.testnet' } }),
    refused({ InvalidAccessKeyError: { AccessKeyNotFound: { account_id: 'switch.example.testnet', public_key: 'ed25519:x' } } }),
    failedOnChain({ LackBalanceForState: { account_id: 'switch.example.testnet', amount: '1' } }),
    (chain) => { chain.accessKeyError = 'UNKNOWN_ACCESS_KEY'; },
  ]) {
    const chain = fakeChain();
    const { swap, state } = setup(chain);
    await swap.refresh();
    spent(chain);
    await swap.flip();
    assert.deepEqual([state().mode, state().reason, state().tx], ['recorded', 'cannot-pay', null]);
    const calls = chain.calls.length;
    await swap.refresh();
    assert.equal(chain.calls.length, calls, 'it stops reading: there is nothing live left to show');
  }
});

test('a flip whose upgrade failed on chain is a failed swap with its transaction, not an endless wait', async () => {
  const chain = fakeChain();
  chain.sendResult = {
    final_execution_status: 'EXECUTED_OPTIMISTIC', status: { SuccessValue: '' },
    receipts_outcome: [{ outcome: { logs: [] } }, { outcome: { logs: ['the chameleon\'s upgrade failed; it still runs the previous build'] } }],
  };
  chain.upgradeFails = true;
  const { swap, state } = setup(chain);
  await swap.refresh();
  await swap.flip();
  assert.equal(state().tx.stage, 'failed');
  assert.match(state().tx.message, /upgrade failed, so it still runs the previous build/);
  assert.ok(state().tx.hash, 'the transaction link stays');
  assert.equal(state().mode, 'live');
  assert.equal(state().build, 'vulnerable', 'the page shows what is really deployed');
});

test('a successful flip with other logs still lands normally', async () => {
  const chain = fakeChain();
  chain.sendResult = { status: { SuccessValue: '' }, receipts_outcome: [{ outcome: { logs: ['flipped'] } }, {}, { outcome: {} }] };
  const { swap, state } = setup(chain);
  await swap.refresh();
  await swap.flip();
  assert.equal(state().tx.stage, 'done');
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

test('with no hook given, a hidden browser tab is not read: the controller follows the page\'s own visibility', async () => {
  const chain = fakeChain();
  const swap = createSwap({ config: CONFIG, recorded, env: { fetch: (...args) => chain.fetch(...args), now: () => chain.nowMs, schedule: () => () => {} } });
  globalThis.document = { hidden: true };
  try {
    await swap.start();
    assert.equal(chain.calls.length, 0);
    globalThis.document.hidden = false;
    await swap.start();
    assert.ok(chain.calls.length > 0);
  } finally {
    delete globalThis.document;
  }
});

test('polling slows down two minutes after the last interaction, and a click or the tab coming back speeds it up again', async () => {
  const chain = fakeChain();
  const delays = [];
  const { swap } = setup(chain, { env: { schedule: (fn, ms) => { delays.push([fn, ms]); return () => {}; } } });
  const tick = async () => { const [fn] = delays.at(-1); await fn(); return delays.at(-1)[1]; };
  await swap.start();
  assert.equal(delays.at(-1)[1], POLL_MS);
  chain.nowMs += ACTIVE_MS - 1;
  assert.equal(await tick(), POLL_MS, 'still within the active window');
  chain.nowMs += 2;
  assert.equal(await tick(), IDLE_POLL_MS, 'quiet for two minutes: slower');
  chain.nowMs += 60_000;
  await swap.flip();
  assert.equal(await tick(), POLL_MS, 'a click: fast again');
  chain.nowMs += ACTIVE_MS + 1;
  assert.equal(await tick(), IDLE_POLL_MS);
  await swap.wake();
  assert.equal(await tick(), POLL_MS, 'the tab coming back: fast again');
});

// ---- Endpoint failover ---------------------------------------------------------------------------------------------

const [A, B] = CONFIG.rpcUrls;
const REJECTS = { cors: () => Promise.reject(new TypeError('Failed to fetch')), // a 429 has no CORS header: fetch rejects
  server: () => Promise.resolve({ ok: false, status: 503, json: async () => ({}) }),
  throttled: () => Promise.resolve({ ok: true, status: 200, json: async () => ({ message: 'Request timeout on the free plan', code: 30 }) }) };

/** A fetch that sends each request to the fake chain unless `behave(url, method, params)` names a way for it to fail ('cors', 'server', 'throttled', 'lost' = the node took it but the answer never came, or a JSON-RPC error object). */
function endpoints(chain, behave) {
  const log = [];
  const fetch = (url, init) => {
    const { method, params } = JSON.parse(init.body);
    log.push({ url, method, params });
    const how = behave(url, method, params);
    if (how === undefined) return chain.fetch(url, init);
    if (how === 'lost') return chain.fetch(url, init).then(REJECTS.cors);
    if (typeof how === 'string') return REJECTS[how]();
    return Promise.resolve({ ok: true, status: 200, json: async () => ({ jsonrpc: '2.0', id: 'x', error: how }) });
  };
  return { fetch, log, to: (url, method) => log.filter((c) => c.url === url && (!method || c.method === method)) };
}

test('an endpoint that is throttled (no CORS header), down or out of quota is skipped at once, and the one that worked is tried first next time', async () => {
  for (const how of ['cors', 'server', 'throttled', { name: 'INTERNAL_ERROR', code: -32603 }]) {
    const chain = fakeChain();
    const net = endpoints(chain, (url) => (url === A ? how : undefined));
    const { swap, state } = setup(chain, { env: { fetch: net.fetch } });
    await swap.refresh();
    assert.deepEqual([state().mode, state().build, state().endpoint], ['live', 'vulnerable', new URL(B).hostname], JSON.stringify(how));
    const triedA = net.to(A).length;
    await swap.refresh();
    assert.equal(net.to(A).length, triedA, 'the second read starts at the endpoint that worked');
  }
});

test('an answer from the chain itself is final: it is not shopped around the other endpoints', async () => {
  const chain = fakeChain();
  chain.accessKeyError = 'UNKNOWN_ACCESS_KEY';
  const net = endpoints(chain, () => undefined);
  const { swap } = setup(chain, { env: { fetch: net.fetch } });
  await swap.refresh();
  await swap.flip();
  assert.equal(net.to(B).length, 0, 'the first endpoint answered every request, even the refusal');
});

test('when every endpoint fails, reads go round once more after a pause, and only then is the RPC called unreachable', async () => {
  const chain = fakeChain();
  const net = endpoints(chain, () => 'cors');
  const sleeps = [];
  const { swap, state } = setup(chain, { env: { fetch: net.fetch, sleep: async (ms) => { sleeps.push(ms); } } });
  await swap.refresh();
  assert.deepEqual([state().mode, state().reason], ['recorded', 'rpc-down']);
  assert.ok(sleeps.length > 0 && sleeps.every((ms) => ms === 400), 'one pause per request, 400 ms');
  assert.equal(net.to(A, 'block').length, 2, 'the endpoint was tried in both rounds');
  assert.equal(net.to(B, 'block').length, 2);
});

test('live data stays on screen with a reconnecting note for two failed reads, and a third falls back to the recording', async () => {
  const chain = fakeChain();
  const { swap, state } = setup(chain);
  await swap.refresh();
  assert.equal(state().reconnecting, false);
  chain.down = true;
  await swap.refresh();
  assert.deepEqual([state().mode, state().reconnecting, state().build], ['live', true, 'vulnerable']);
  await swap.refresh();
  assert.deepEqual([state().mode, state().reconnecting], ['live', true]);
  chain.down = false;
  await swap.refresh();
  assert.deepEqual([state().mode, state().reconnecting], ['live', false], 'one good read ends the note');
  chain.down = true;
  for (let i = 0; i < 2; i++) await swap.refresh();
  assert.equal(state().mode, 'live', 'the count started over');
  await swap.refresh();
  assert.deepEqual([state().mode, state().reason, state().reconnecting], ['recorded', 'rpc-down', false]);
});

test('from the recording the page keeps trying quietly and returns to live data by itself', async () => {
  const chain = fakeChain();
  chain.down = true;
  const { swap, state, states } = setup(chain);
  await swap.refresh();
  assert.equal(state().mode, 'recorded');
  await swap.flip();
  assert.equal(state().replay, 1, 'the button replays meanwhile');
  chain.down = false;
  await swap.refresh();
  assert.deepEqual([state().mode, state().reason, state().build], ['live', null, 'vulnerable']);
  assert.ok(states.every((s) => s.reconnecting === false || s.mode === 'live'));
});

test('a swap sent while the first endpoint fails goes to the next endpoint as the identical signed bytes, signed once', async () => {
  const chain = fakeChain();
  const net = endpoints(chain, (url, method) => (url === A && method === 'send_tx' ? 'cors' : undefined));
  const { swap, state } = setup(chain, { env: { fetch: net.fetch } });
  await swap.refresh();
  await swap.flip();
  const sent = net.log.filter((c) => c.method === 'send_tx');
  assert.deepEqual(sent.map((c) => c.url), [A, B], 'tried the first endpoint, then the next');
  assert.equal(new Set(sent.map((c) => c.params.signed_tx_base64)).size, 1, 'the same bytes everywhere');
  assert.equal(net.log.filter((c) => c.method === 'query' && c.params.request_type === 'view_access_key').length, 1, 'one nonce read, one signature');
  assert.equal(state().tx.stage, 'done');
});

test('a swap whose answer was lost is looked up by its hash before anything is called failed', async () => {
  const chain = fakeChain();
  const net = endpoints(chain, (url, method) => (method === 'send_tx' ? 'lost' : undefined));
  const { swap, state } = setup(chain, { env: { fetch: net.fetch } });
  await swap.refresh();
  chain.txResult = { final_execution_status: 'EXECUTED', status: { SuccessValue: '' } };
  await swap.flip();
  assert.equal(net.log.filter((c) => c.method === 'send_tx').length, 2, 'both endpoints were given the same transaction');
  assert.ok(net.log.some((c) => c.method === 'tx' && c.params.tx_hash === state().tx.hash), 'the lookup used the transaction hash');
  assert.equal(state().tx.stage, 'done', 'it landed, so it is not reported as failed or unconfirmed');
  assert.equal(chain.flips, 4, 'sent once as far as the chain is concerned');
});

test('a lost answer with no trace on chain ends as unconfirmed, with the hash, after a few lookups', async () => {
  const chain = fakeChain();
  const net = endpoints(chain, (url, method) => (method === 'send_tx' ? 'cors' : undefined));
  const { swap, state } = setup(chain, { env: { fetch: net.fetch } });
  await swap.refresh();
  await swap.flip();
  assert.equal(state().tx.stage, 'unconfirmed');
  assert.ok(state().tx.hash);
  assert.equal(net.log.filter((c) => c.method === 'tx').length, 3);
});

test('a stale nonce right after a copy of our own transaction was taken is the transaction landing, not a reason to sign again', async () => {
  const chain = fakeChain();
  const stale = { name: 'HANDLER_ERROR', cause: { name: 'INVALID_TRANSACTION', info: { InvalidNonce: { tx_nonce: 1001, ak_nonce: 1001 } } } };
  const net = endpoints(chain, (url, method) => (method !== 'send_tx' ? undefined : url === A ? 'lost' : stale));
  const { swap, state } = setup(chain, { env: { fetch: net.fetch } });
  await swap.refresh();
  chain.txResult = { final_execution_status: 'EXECUTED', status: { SuccessValue: '' } };
  await swap.flip();
  assert.equal(state().tx.stage, 'done');
  assert.equal(net.log.filter((c) => c.method === 'query' && c.params.request_type === 'view_access_key').length, 1, 'never signed a second time');
});

// ---- The auditor-free check: the fingerprint first seen, and the account's keys ----------------------------------------

const idle = async () => { for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve)); };
const memoryStorage = () => { const map = new Map(); return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => { map.set(k, String(v)); } }; };

test('the first live read pins the fingerprint, and a swap leaves the pin and changes the code: no registry involved', async () => {
  const chain = fakeChain();
  const { swap, state } = setup(chain, { env: { storage: memoryStorage() } });
  assert.equal(state().arrival, null);
  await swap.refresh();
  assert.equal(state().arrival, HASH.vulnerable);
  await swap.flip();
  assert.equal(state().codeHash, HASH.patched);
  assert.equal(state().arrival, HASH.vulnerable, 'the pin is where the visitor arrived');
});

test('a reload in the same tab keeps the pin, even when the code changed in between', async () => {
  const storage = memoryStorage();
  const first = setup(fakeChain(), { env: { storage } });
  await first.swap.refresh();
  const chain = fakeChain();
  chain.build = 'patched';
  const second = setup(chain, { env: { storage } });
  await second.swap.refresh();
  assert.deepEqual([second.state().arrival, second.state().codeHash], [HASH.vulnerable, HASH.patched]);
});

test('the account\'s full-access keys are counted once per code hash and the count says which code it was read for', async () => {
  const chain = fakeChain();
  const { swap, state } = setup(chain, { env: { storage: memoryStorage() } });
  await swap.refresh();
  await idle();
  assert.deepEqual(state().keys, { full: 0, codeHash: HASH.vulnerable });
  await swap.refresh();
  await idle();
  const lists = () => chain.calls.filter((c) => c.params.request_type === 'view_access_key_list');
  assert.equal(lists().length, 1, 'the same code is not asked about again');
  assert.equal(lists()[0].params.account_id, 'chameleon.example.testnet');
  chain.keys = [{ public_key: 'ed25519:k', access_key: { nonce: 1, permission: 'FullAccess' } }];
  await swap.flip();
  await idle();
  assert.equal(lists().length, 2, 'new code, new read');
  assert.deepEqual(state().keys, { full: 1, codeHash: HASH.patched });
});

test('a key list that cannot be read is no key fact, tried a few times for one code hash and then left alone', async () => {
  const chain = fakeChain();
  chain.keyListError = 'UNKNOWN_ACCOUNT';
  const { swap, state } = setup(chain, { env: { storage: memoryStorage() } });
  for (let i = 0; i < 6; i++) { await swap.refresh(); await idle(); }
  assert.equal(state().keys, null);
  assert.equal(state().mode, 'live', 'the verdicts do not wait for it');
  assert.equal(chain.calls.filter((c) => c.params.request_type === 'view_access_key_list').length, 3);
});

test('a partial key list is no key fact either', async () => {
  const chain = fakeChain();
  const answer = chain.fetch;
  chain.fetch = async (url, init) => {
    const response = await answer(url, init);
    if (JSON.parse(init.body).params?.request_type !== 'view_access_key_list') return response;
    return { ...response, json: async () => ({ jsonrpc: '2.0', id: 'x', result: { keys: [], last_key: 'ed25519:next' } }) };
  };
  const { swap, state } = setup(chain, { env: { storage: memoryStorage() } });
  await swap.refresh();
  await idle();
  assert.equal(state().keys, null);
});

test('the recording is not a live read: it pins nothing and counts no keys', async () => {
  const chain = fakeChain();
  chain.down = true;
  const { swap, state } = setup(chain, { env: { storage: memoryStorage() } });
  await swap.refresh();
  assert.deepEqual([state().mode, state().arrival, state().keys], ['recorded', null, null]);
});
