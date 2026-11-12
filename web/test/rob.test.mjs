// The "Rob it" controller (src/rob.js) against the same fake NEAR node as the Swap (test/swap-chain.mjs): the real
// PF001 exploit succeeds on the vulnerable build, the patched build's own `#[private]` refuses it on chain, and the
// shared key's nonce and network handling matches the Swap's flip. Signing is the real WebCrypto; only the network is fake.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRob, readRobConfig, ROB_AMOUNT_YOCTO } from '../src/rob.js';
import { CONFIG, fakeChain, ON_DEPOSIT_PRIVATE_FAILURE, UNSET_CONFIG } from './swap-chain.mjs';

function setup(chain, { config = CONFIG, env = {} } = {}) {
  const states = [];
  const rob = createRob({ config, onChange: (s) => states.push(s), env: { fetch: (...args) => chain.fetch(...args), now: () => chain.nowMs, sleep: async () => {}, ...env } });
  return { rob, states, state: () => rob.getState() };
}
const sends = (chain) => chain.calls.filter((c) => c.method === 'send_tx');

test('readRobConfig names every empty or malformed field and converts gas', () => {
  assert.deepEqual(readRobConfig(UNSET_CONFIG).missing, ['chameleonId', 'robberId', 'robberKey']);
  assert.deepEqual(readRobConfig({ ...CONFIG, robberId: 'Not An Id', robberKey: 'ed25519:abc', rpcUrls: ['http://x'], robGasTgas: 0 }).missing,
    ['robberId', 'robberKey', 'robGasTgas', 'rpcUrls']);
  const ok = readRobConfig(CONFIG);
  assert.equal(ok.ok, true);
  assert.equal(ok.gas, 30_000_000_000_000n);
});

test('an unset config starts disabled and sends nothing', async () => {
  const chain = fakeChain();
  const { rob, state } = setup(chain, { config: UNSET_CONFIG });
  assert.deepEqual([state().ok, state().canAct], [false, false]);
  await rob.rob();
  assert.equal(chain.calls.length, 0);
});

test('sync gates the button on the Swap being live; a click while gated sends nothing', async () => {
  const chain = fakeChain();
  const { rob, state } = setup(chain);
  assert.equal(state().canAct, false);
  await rob.rob();
  assert.equal(chain.calls.length, 0, 'the button is disabled until sync(true)');
  rob.sync(true);
  assert.equal(state().canAct, true);
  rob.sync(false);
  assert.equal(state().canAct, false);
});

test('an RPC node a block behind does not make a robbery read as no change: the page waits for the balance to move', async () => {
  for (const [laggingReads, label] of [[2, 'catches up'], [99, 'never catches up']]) {
    const chain = fakeChain();
    let reads = 0;
    const laggingFetch = async (url, init) => {
      const lag = JSON.parse(init.body).params?.method_name === 'balance_of' && (reads += 1) > 1 && reads <= 1 + laggingReads;
      const real = chain.balances['robber.example.testnet'];
      if (lag) chain.balances['robber.example.testnet'] = '0';
      try { return await chain.fetch(url, init); } finally { if (lag) chain.balances['robber.example.testnet'] = real; }
    };
    const { rob, state } = setup(chain, { env: { fetch: laggingFetch } });
    rob.sync(true);
    await rob.rob();
    assert.deepEqual([state().stage, state().before, state().after], ['done', '0', ROB_AMOUNT_YOCTO], label);
  }
});

test('on the vulnerable build the forged call succeeds: a real balance, before and after, and a transaction hash', async () => {
  const chain = fakeChain();
  const { rob, state } = setup(chain);
  rob.sync(true);
  await rob.rob();
  assert.equal(state().stage, 'done');
  assert.equal(state().before, '0');
  assert.equal(state().after, ROB_AMOUNT_YOCTO);
  assert.ok(state().hash);
  assert.equal(chain.balances['robber.example.testnet'], ROB_AMOUNT_YOCTO);
  assert.ok(chain.calls.some((c) => c.params?.method_name === 'balance_of'), 'the page reads balance_of itself, not just the recording');
  assert.ok(sends(chain)[0]);
});

test('robbing twice forges two credits, on top of each other', async () => {
  const chain = fakeChain();
  const { rob, state } = setup(chain);
  rob.sync(true);
  await rob.rob();
  await rob.rob();
  assert.equal(state().stage, 'done');
  assert.equal(state().before, ROB_AMOUNT_YOCTO);
  assert.equal(state().after, (2n * BigInt(ROB_AMOUNT_YOCTO)).toString());
});

test('on the patched build the same call fails on chain: the contract\'s own refusal, not a network problem', async () => {
  const chain = fakeChain();
  chain.build = 'patched';
  const { rob, state } = setup(chain);
  rob.sync(true);
  await rob.rob();
  assert.equal(state().stage, 'refused');
  assert.equal(state().message, 'Method on_deposit is private');
  assert.ok(state().hash, 'the failed transaction still has a real hash on chain');
  assert.equal(chain.balances['robber.example.testnet'], undefined, 'nothing was credited');
});

test('a nonce collision with another visitor reads the key again and signs again', async () => {
  const chain = fakeChain();
  chain.sendErrors = [{ name: 'HANDLER_ERROR', cause: { name: 'INVALID_TRANSACTION', info: { InvalidNonce: { tx_nonce: 1001, ak_nonce: 1005 } } } }];
  const { rob, state } = setup(chain);
  rob.sync(true);
  await rob.rob();
  assert.equal(sends(chain).length, 2);
  assert.equal(state().stage, 'done');
});

test('nonce collisions that never clear end as a failed rob with the RPC\'s name for it', async () => {
  const chain = fakeChain();
  const collision = { name: 'HANDLER_ERROR', cause: { name: 'INVALID_TRANSACTION', info: { InvalidNonce: {} } } };
  chain.sendErrors = [collision, collision, collision, collision];
  const { rob, state } = setup(chain);
  rob.sync(true);
  await rob.rob();
  assert.equal(sends(chain).length, 3);
  assert.equal(state().stage, 'failed');
  assert.match(state().message, /INVALID_TRANSACTION/);
});

test('the key refused for lack of allowance or balance is cannot-pay, read before anything was signed', async () => {
  const chain = fakeChain();
  chain.sendErrors = [{ name: 'HANDLER_ERROR', cause: { name: 'INVALID_TRANSACTION', info: { tx_execution_error: { InvalidTxError: { InvalidAccessKeyError: { NotEnoughAllowance: { allowance: '1', cost: '2' } } } } } } }];
  const { rob, state } = setup(chain);
  rob.sync(true);
  await rob.rob();
  assert.deepEqual([state().stage, state().hash], ['cannot-pay', null]);
});

test('a refusal the chain itself executed, not just the node, is also cannot-pay', async () => {
  const chain = fakeChain();
  chain.sendResult = { status: { Failure: { ActionError: { index: 0, kind: { LackBalanceForState: { account_id: 'robber.example.testnet', amount: '1' } } } } } };
  const { rob, state } = setup(chain);
  rob.sync(true);
  await rob.rob();
  assert.equal(state().stage, 'cannot-pay');
  assert.ok(state().hash, 'this one did reach the chain, so its hash is kept');
});

test('a failure before anything was sent says nothing was sent; a lost answer after sending is unconfirmed, with the hash', async () => {
  const chain = fakeChain();
  const { rob, state } = setup(chain);
  rob.sync(true);
  const fetch = chain.fetch;
  chain.fetch = async (url, init) => { if (JSON.parse(init.body).method === 'block' && JSON.parse(init.body).params.finality === 'final') throw new TypeError('offline'); return fetch(url, init); };
  await rob.rob();
  assert.equal(state().stage, 'failed');
  assert.equal(state().hash, null);
  assert.match(state().message, /^Nothing was sent\./);

  chain.fetch = async (url, init) => { if (JSON.parse(init.body).method === 'send_tx') throw new TypeError('connection reset'); return fetch(url, init); };
  await rob.rob();
  assert.equal(state().stage, 'unconfirmed');
  assert.ok(state().hash);
  assert.equal(sends(chain).length, 0, 'the fake node never saw it');
});

test('a lost send that did land is read back by hash and reported as done, not unconfirmed', async () => {
  const chain = fakeChain();
  const { rob, state } = setup(chain);
  rob.sync(true);
  const fetch = chain.fetch;
  chain.fetch = async (url, init) => { if (JSON.parse(init.body).method === 'send_tx') throw new TypeError('connection reset'); return fetch(url, init); };
  chain.txResult = { status: { SuccessValue: '' } };
  await rob.rob();
  assert.equal(state().stage, 'done');
  assert.ok(state().hash);
  assert.equal(sends(chain).length, 0, 'the fake node never actually received the send; the lookup by hash is what found it');
});

test('a browser that cannot sign ed25519 fails the click with a plain message and sends nothing', async () => {
  const chain = fakeChain();
  const subtle = { digest: (...args) => globalThis.crypto.subtle.digest(...args), importKey: async () => { throw Object.assign(new Error('x'), { name: 'NotSupportedError' }); } };
  const { rob, state } = setup(chain, { env: { subtle } });
  rob.sync(true);
  await rob.rob();
  assert.deepEqual([state().stage, state().message], ['failed', 'this browser cannot sign with ed25519 (WebCrypto)']);
  assert.equal(sends(chain).length, 0);
});

test('a double click while a rob is in flight sends only once', async () => {
  const chain = fakeChain();
  const { rob, state } = setup(chain);
  rob.sync(true);
  const first = rob.rob();
  const second = rob.rob();
  await Promise.all([first, second]);
  assert.equal(sends(chain).length, 1);
  assert.equal(state().stage, 'done');
});

test('balance_of answering with something unusable is a failure, not a silent zero', async () => {
  const chain = fakeChain();
  chain.balances['robber.example.testnet'] = 'not a number';
  const { rob, state } = setup(chain);
  rob.sync(true);
  await rob.rob();
  assert.equal(state().stage, 'failed');
  assert.match(state().message, /balance_of returned no usable amount/);
});

test('a result belongs to the code it ran against: when the live code changes, the panel goes back to idle', async () => {
  const chain = fakeChain();
  chain.build = 'patched';
  const { rob, state } = setup(chain);
  rob.sync(true, 'hash-a');
  await rob.rob();
  assert.equal(state().stage, 'refused');
  rob.sync(true, 'hash-a');
  assert.equal(state().stage, 'refused', 'the same code read again keeps its result');
  rob.sync(true, 'hash-b');
  assert.deepEqual([state().stage, state().before, state().after, state().hash, state().message, state().canAct, state().build], ['idle', null, null, null, '', true, 'hash-b']);
  rob.sync(true, null);
  assert.equal(state().build, 'hash-b', 'a read with no hash says nothing about the code');
  chain.build = 'vulnerable';
  await rob.rob();
  assert.equal(state().stage, 'done', 'and the button is ready again');
});

test('a rob in flight when the code changes is dropped, not painted under the other code\'s narrative', async () => {
  for (const outcome of ['lands', 'fails']) {
    const chain = fakeChain();
    const { rob, states, state } = setup(chain);
    rob.sync(true, 'hash-a');
    const fetch = chain.fetch;
    chain.fetch = async (url, init) => {
      if (JSON.parse(init.body).method === 'send_tx') { rob.sync(true, 'hash-b'); if (outcome === 'fails') throw new TypeError('offline'); }
      return fetch(url, init);
    };
    await rob.rob();
    assert.deepEqual([state().stage, state().hash, state().before, state().after, state().build], ['idle', null, null, null, 'hash-b'], outcome);
    assert.ok(states.every((s) => !['done', 'refused', 'failed', 'unconfirmed'].includes(s.stage)), `${outcome}: no result was ever shown`);
    chain.fetch = fetch;
    await rob.rob();
    assert.equal(state().stage, 'done', `${outcome}: the next click is a normal rob`);
  }
});

test('ON_DEPOSIT_PRIVATE_FAILURE is the exact panic demo/swap/chameleon/patched/src/lib.rs produces', () => {
  const text = JSON.stringify(ON_DEPOSIT_PRIVATE_FAILURE);
  assert.match(text, /Smart contract panicked: Method on_deposit is private/);
});
