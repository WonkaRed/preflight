// "Check a contract you know" (src/account-check.js): the account id check, the examples, and every state the read can end in,
// against a fake node that answers the JSON-RPC the page sends. The decision rule is pinned to the real guard in account-check-guard.test.mjs.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { EXAMPLES, NETWORKS, checkAccount, guardDecision, parseRegistryVerdict, validateAccountId } from '../src/account-check.js';
import { base58Encode } from '../src/near.js';
import { SWAP_CONFIG } from '../src/swap-config.js';

const hashOf = (text) => base58Encode(createHash('sha256').update(text).digest());
const NO_CODE = '11111111111111111111111111111111';
const FULL = { access_key: { nonce: 1, permission: 'FullAccess' }, public_key: 'ed25519:x' };
const CALL = { access_key: { nonce: 1, permission: { FunctionCall: { allowance: '1', receiver_id: 'a.near', method_names: [] } } }, public_key: 'ed25519:y' };

const NETS = {
  mainnet: { label: 'Mainnet', rpcUrls: ['https://main-a.example', 'https://main-b.example'], explorerUrl: 'https://nearblocks.example' },
  testnet: { label: 'Testnet', rpcUrls: ['https://test-a.example'], explorerUrl: 'https://testnet.nearblocks.example' },
};
const REG = { rpcUrls: ['https://reg-a.example', 'https://reg-b.example'], accountId: 'registry.example.testnet' };
const verdictFor = (hash, status, ruleIds = []) => ({ code_hash: hash, status, rule_ids: ruleIds, report_url: 'https://example.org/r.json', report_sha256: '0'.repeat(64), auditor: 'auditor.example.testnet', published_at_ms: '1' });

/** A fake node. `down` lists URLs that refuse to answer; `accounts`, `keys` (view_access_key_list results) and `verdicts` are by id or hash. */
function fakeNode({ accounts = {}, keys = {}, verdicts = {}, down = [], registryDown = false } = {}) {
  const calls = [];
  const reply = (body) => ({ ok: true, status: 200, json: async () => ({ jsonrpc: '2.0', id: 'x', ...body }) });
  const chainError = (name) => reply({ error: { name: 'HANDLER_ERROR', cause: { name, info: {} } } });
  const fetch = async (url, init) => {
    const { params } = JSON.parse(init.body);
    calls.push({ url, type: params.request_type, account: params.account_id });
    if (down.includes(url) || (registryDown && url.startsWith('https://reg-'))) throw new TypeError('fetch failed');
    if (params.request_type === 'view_account') return params.account_id in accounts ? reply({ result: accounts[params.account_id] }) : chainError('UNKNOWN_ACCOUNT');
    if (params.request_type === 'view_access_key_list') return params.account_id in keys ? reply({ result: keys[params.account_id] }) : chainError('UNKNOWN_ACCESS_KEY');
    if (params.request_type === 'call_function' && params.account_id === REG.accountId) {
      const { code_hash: hash } = JSON.parse(Buffer.from(params.args_base64, 'base64').toString());
      return reply({ result: { result: [...Buffer.from(JSON.stringify(verdicts[hash] ?? null))] } });
    }
    throw new Error(`fake node: unexpected ${JSON.stringify(params)}`);
  };
  return { env: { fetch, sleep: async () => {} }, calls };
}
const run = (id, network, node) => checkAccount(id, network, node.env, { networks: NETS, registry: REG });
const account = (code_hash, extra = {}) => ({ amount: '1', code_hash, ...extra });

test('an account id is checked against the NEAR rules before anything is sent, and a lowercase hint is given for capitals', () => {
  const guardRule = ['wrap.near', 'aurora', 'a1', 'v2.ref-finance.near', 'alice_bob-1.testnet', 'ab', 'a'.repeat(64), '0'.repeat(64), `0x${'a'.repeat(40)}`];
  for (const id of guardRule) assert.deepEqual(validateAccountId(id), { ok: true, accountId: id }, id);
  assert.deepEqual(validateAccountId('  wrap.near \n'), { ok: true, accountId: 'wrap.near' }, 'spaces around the name are dropped');
  const bad = [
    '', '   ', 'a', 'a'.repeat(65), 'Wrap.near', 'a..near', '.near', 'near.', '-a.near', 'a-.near', 'a b.near', 'wrap\n.near', 'wr@p.near',
    'wäp.near', 'wrap.near<script>', '<img src=x onerror=alert(1)>.near', 'https://nearblocks.io/address/wrap.near', 'a/b.near', '__a.near', null, undefined, 42, {},
  ];
  for (const id of bad) assert.equal(validateAccountId(id).ok, false, String(id));
  assert.match(validateAccountId('').reason, /Type a NEAR account name/);
  assert.match(validateAccountId('a').reason, /at least 2/);
  assert.match(validateAccountId('a'.repeat(65)).reason, /at most 64/);
  assert.match(validateAccountId('Wrap.near').reason, /lowercase only/);
  assert.match(validateAccountId('<img src=x onerror=alert(1)>.near').reason, /only lowercase letters, digits/);
});

test('the examples are valid accounts, 3 or 4 of them, from the public survey plus the demo shop and the chameleon', () => {
  assert.ok(EXAMPLES.length >= 3 && EXAMPLES.length <= 4);
  const survey = readFileSync(new URL('../../docs/mainnet-survey.md', import.meta.url), 'utf8');
  for (const example of EXAMPLES) {
    assert.equal(validateAccountId(example.accountId).ok, true, example.accountId);
    if (example.network === 'mainnet') assert.ok(survey.includes(`\`${example.accountId}\``), `${example.accountId} is not in docs/mainnet-survey.md`);
  }
  assert.deepEqual(EXAMPLES.filter((e) => e.network === 'testnet').map((e) => e.accountId), ['shop-vulnerable.preflight-guard.testnet', SWAP_CONFIG.chameleonId]);
  assert.ok(EXAMPLES.some((e) => e.network === 'mainnet'));
});

test('the networks: mainnet answers from two endpoints, testnet is the Swap\'s, and every endpoint is https', () => {
  assert.equal(NETWORKS.mainnet.rpcUrls.length, 2);
  assert.deepEqual(NETWORKS.testnet.rpcUrls, SWAP_CONFIG.rpcUrls);
  for (const { rpcUrls, explorerUrl } of Object.values(NETWORKS)) {
    for (const url of [...rpcUrls, explorerUrl]) assert.match(url, /^https:\/\/[\w.-]+$/);
  }
});

test('the guard rule: no verdict and a Warn verdict are warn, Unsafe is block, Safe is allow, and a code-less account is allowed by the check but refused by the call', () => {
  const verdict = (decision, registered = true) => ({ decision, registered, ruleIds: [] });
  assert.deepEqual(guardDecision('h', verdict('WARN', false)), { check: 'warn', decision: 'warn' });
  assert.deepEqual(guardDecision('h', verdict('WARN')), { check: 'warn', decision: 'warn' });
  assert.deepEqual(guardDecision('h', verdict('BLOCK')), { check: 'block', decision: 'block' });
  assert.deepEqual(guardDecision('h', verdict('ALLOW')), { check: 'allow', decision: 'allow' });
  assert.deepEqual(guardDecision(null, null), { check: 'allow', decision: 'block' });
});

test('a contract with a Safe verdict: allow, with its code hash, its full-access key count and the registry read on testnet', async () => {
  const hash = hashOf('safe');
  const node = fakeNode({ accounts: { 'safe.near': account(hash) }, keys: { 'safe.near': { keys: [CALL, CALL] } }, verdicts: { [hash]: verdictFor(hash, 'Safe') } });
  const result = await run('safe.near', 'mainnet', node);
  assert.equal(result.state, 'checked');
  assert.equal(result.codeHash, hash);
  assert.equal(result.keys, 0);
  assert.deepEqual(result.guard, { check: 'allow', decision: 'allow' });
  assert.equal(result.verdict.registered, true);
  assert.equal(result.host, 'main-a.example');
  assert.deepEqual(node.calls.map((c) => [new URL(c.url).hostname, c.type]).sort(), [['main-a.example', 'view_access_key_list'], ['main-a.example', 'view_account'], ['reg-a.example', 'call_function']]);
});

test('no verdict is a warn, an Unsafe verdict a block with its rules, and full-access keys are counted', async () => {
  const hash = hashOf('unknown');
  const bad = hashOf('bad');
  const node = fakeNode({
    accounts: { 'unknown.near': account(hash), 'bad.testnet': account(bad) },
    keys: { 'unknown.near': { keys: [FULL, FULL, CALL] }, 'bad.testnet': { keys: [] } },
    verdicts: { [bad]: verdictFor(bad, 'Unsafe', ['PF001']) },
  });
  const none = await run('unknown.near', 'mainnet', node);
  assert.deepEqual([none.state, none.guard.decision, none.verdict.registered, none.keys], ['checked', 'warn', false, 2]);
  const unsafe = await run('bad.testnet', 'testnet', node);
  assert.deepEqual([unsafe.guard.decision, unsafe.verdict.ruleIds, unsafe.keys], ['block', ['PF001'], 0]);
});

test('an account that does not exist, and one with no contract (all-ones hash), are named as such and read no key list or registry', async () => {
  const node = fakeNode({ accounts: { 'alice.near': account(NO_CODE) } });
  const missing = await run('nobody.near', 'mainnet', node);
  assert.equal(missing.state, 'missing');
  const nocode = await run('alice.near', 'mainnet', node);
  assert.equal(nocode.state, 'nocode');
  assert.deepEqual(node.calls.map((c) => c.type), ['view_account', 'view_account'], 'nothing else was asked');
});

test('an account on a global contract: by hash it is judged on that hash, by publisher it is not decided here', async () => {
  const hash = hashOf('global');
  const node = fakeNode({
    accounts: { 'byhash.near': account(NO_CODE, { global_contract_hash: hash }), 'bypub.near': account(NO_CODE, { global_contract_account_id: 'publisher.near' }) },
    keys: { 'byhash.near': { keys: [] }, 'bypub.near': { keys: [FULL] } },
    verdicts: { [hash]: verdictFor(hash, 'Safe') },
  });
  const byHash = await run('byhash.near', 'mainnet', node);
  assert.deepEqual([byHash.state, byHash.codeHash, byHash.guard.decision], ['checked', hash, 'allow']);
  const byPublisher = await run('bypub.near', 'mainnet', node);
  assert.deepEqual([byPublisher.state, byPublisher.publisher, byPublisher.keys], ['global', 'publisher.near', 1]);
  assert.equal('guard' in byPublisher, false, 'no decision without a code hash');
});

test('a key list that cannot be counted leaves the key count unknown but the verdict stands', async () => {
  const hash = hashOf('k');
  const verdicts = { [hash]: verdictFor(hash, 'Safe') };
  for (const keys of [{}, { 'k.near': { keys: [FULL], last_key: 'ed25519:z' } }, { 'k.near': { keys: [{ access_key: { permission: 'Mystery' } }] } }, { 'k.near': { nokeys: true } }]) {
    const result = await run('k.near', 'mainnet', fakeNode({ accounts: { 'k.near': account(hash) }, keys, verdicts }));
    assert.deepEqual([result.state, result.keys, result.guard.decision], ['checked', null, 'allow'], JSON.stringify(keys));
  }
});

test('reads fail over to the second endpoint, and every endpoint down is a failed read that the guard would block, never a verdict', async () => {
  const hash = hashOf('f');
  const chain = { accounts: { 'f.near': account(hash) }, keys: { 'f.near': { keys: [] } }, verdicts: { [hash]: verdictFor(hash, 'Safe') } };
  const over = await run('f.near', 'mainnet', fakeNode({ ...chain, down: ['https://main-a.example', 'https://reg-a.example'] }));
  assert.deepEqual([over.state, over.host], ['checked', 'main-b.example']);

  const noChain = await run('f.near', 'mainnet', fakeNode({ ...chain, down: NETS.mainnet.rpcUrls }));
  assert.deepEqual([noChain.state, noChain.what, noChain.decision], ['failed', 'account', 'block']);
  const noRegistry = await run('f.near', 'mainnet', fakeNode({ ...chain, registryDown: true }));
  assert.deepEqual([noRegistry.state, noRegistry.what, noRegistry.decision, noRegistry.codeHash], ['failed', 'registry', 'block', hash]);
});

test('an answer this page cannot read is a failed read, not a verdict', async () => {
  const hash = hashOf('s');
  const cases = {
    'no code_hash': account(undefined),
    'not a hash': account('not-a-hash'),
    'a number as global hash': account(NO_CODE, { global_contract_hash: 7 }),
    'a global hash that is no hash': account(NO_CODE, { global_contract_hash: 'zzz' }),
    'local code and a global contract': account(hash, { global_contract_hash: hashOf('g') }),
  };
  for (const [name, body] of Object.entries(cases)) {
    const result = await run('s.near', 'mainnet', fakeNode({ accounts: { 's.near': body } }));
    assert.deepEqual([result.state, result.decision], ['failed', 'block'], name);
  }
  const malformed = fakeNode({ accounts: { 's.near': account(hash) }, verdicts: { [hash]: { code_hash: hashOf('other'), status: 'Safe', rule_ids: [] } } });
  assert.equal((await run('s.near', 'mainnet', malformed)).state, 'failed', 'a verdict for another hash');
});

test('a stored verdict is read whole, and a verdict that is not well formed is a failed registry read, never a repaired one', async () => {
  const hash = hashOf('v');
  assert.deepEqual(parseRegistryVerdict(verdictFor(hash, 'Unsafe', ['PF001']), hash), { decision: 'BLOCK', ruleIds: ['PF001'], registered: true, auditor: 'auditor.example.testnet', reportUrl: 'https://example.org/r.json' });
  assert.deepEqual(parseRegistryVerdict(null, hash), { decision: 'WARN', ruleIds: [], registered: false, auditor: null, reportUrl: null });
  const edits = { report_url: 'https://example.org/a b', report_sha256: 'f'.repeat(63), auditor: 'Bad Auditor', published_at_ms: '1.5' };
  for (const [field, value] of Object.entries(edits)) {
    const node = fakeNode({ accounts: { 'm.near': account(hash) }, verdicts: { [hash]: { ...verdictFor(hash, 'Safe'), [field]: value } } });
    const result = await run('m.near', 'mainnet', node);
    assert.deepEqual([result.state, result.what, result.decision], ['failed', 'registry', 'block'], field);
    assert.ok(!result.detail.includes(value), 'the message names the field, not its value');
    assert.match(result.detail, new RegExp(`bad ${field}`));
  }
  for (const raw of [[], 'Safe', 7, true, { ...verdictFor(hash, '__proto__') }, { ...verdictFor(hash, 'Safe'), rule_ids: undefined }]) {
    assert.throws(() => parseRegistryVerdict(raw, hash), Error, JSON.stringify(raw));
  }
});
