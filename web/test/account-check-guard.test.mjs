// Pins the page's "what would the guard say" (src/account-check.js) to the real guard: the same scenarios run through
// guard/src/check.ts (`inspectContract`, which is `checkContract` before its text is made printable) and through
// `GuardedAgent.guardedCall` on the guard's own fake chain, and through the page's read against that same fake chain. If the
// guard's rule changes, this test fails until the page follows. It needs the guard's dependencies: `make -C guard build`
// installs them (the Makefile does it before this test runs).
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import { GuardedAgent, RefusedError, isValidAccountId } from '../../guard/src/index.ts';
import { inspectContract } from '../../guard/src/check.ts';
import { FakeNear, fakeWasm } from '../../guard/testkit/fake-rpc.ts';
import { checkAccount, validateAccountId } from '../src/account-check.js';

// The guard's own copy of near-api-js (pinned in guard/package-lock.json), so the signer is the one the guard is tested with.
const { KeyPair, KeyPairSigner, teraToGas } = createRequire(new URL('../../guard/package.json', import.meta.url))('near-api-js');

const REGISTRY = 'registry.test.near';
const AGENT = 'agent.test.near';
const TARGET = 'escrow.test.near';

/** A verdict as the registry stores it, then changed by `edit` (a field removed is `undefined`): what a registry that does not enforce its own rules, or a node that lies, would hand out. */
const stored = (status, ruleIds, edit) => (fake) => {
  fake.accounts.set(TARGET, { wasm: fakeWasm('stored') });
  const hash = fake.publish(TARGET, status, ruleIds);
  const verdict = { ...fake.verdicts.get(hash) };
  edit(verdict, hash);
  fake.verdicts.set(hash, JSON.parse(JSON.stringify(verdict)));
};
const withField = (name, value) => (verdict) => { verdict[name] = value; };

/** What each situation does to the chain. Each scenario starts from an empty fake chain. */
const SCENARIOS = {
  'a Safe verdict': (fake) => { fake.accounts.set(TARGET, { wasm: fakeWasm('safe') }); fake.publish(TARGET, 'Safe'); },
  'a Warn verdict': (fake) => { fake.accounts.set(TARGET, { wasm: fakeWasm('warn') }); fake.publish(TARGET, 'Warn', ['PF010']); },
  'an Unsafe verdict': (fake) => { fake.accounts.set(TARGET, { wasm: fakeWasm('unsafe') }); fake.publish(TARGET, 'Unsafe', ['PF001']); },
  'no verdict for the code': (fake) => { fake.accounts.set(TARGET, { wasm: fakeWasm('unaudited') }); },
  'a verdict for other code only (the code was swapped)': (fake) => {
    fake.accounts.set(TARGET, { wasm: fakeWasm('audited') });
    fake.publish(TARGET, 'Safe');
    fake.accounts.set(TARGET, { wasm: fakeWasm('swapped') });
  },
  'a global contract named by hash, Safe': (fake) => {
    const wasm = fakeWasm('global');
    fake.accounts.set('publisher.test.near', { wasm });
    const hash = fake.publish('publisher.test.near', 'Safe');
    fake.accounts.set(TARGET, { wasm, globalCodeHash: hash });
  },
  // Verdicts that are not well formed: the guard fails closed (block) on each, so the page must not show ALLOW or WARN for them.
  'a Safe verdict whose report url has a space': stored('Safe', [], withField('report_url', 'https://example.org/my report.json')),
  'a Safe verdict whose report url has non-ASCII characters': stored('Safe', [], withField('report_url', 'https://example.org/r\u00e9sum\u00e9.json')),
  'a Safe verdict whose report url has a control character': stored('Safe', [], withField('report_url', 'https://example.org/r\n.json')),
  'a Safe verdict whose report url is not http or https': stored('Safe', [], withField('report_url', 'ftp://example.org/r.json')),
  'a Safe verdict whose report url is too long': stored('Safe', [], withField('report_url', `https://example.org/${'a'.repeat(250)}`)),
  'a Safe verdict whose report url is not text': stored('Safe', [], withField('report_url', 7)),
  'a Safe verdict with no report url': stored('Safe', [], withField('report_url', undefined)),
  'a Safe verdict with an http report url (the guard accepts it)': stored('Safe', [], withField('report_url', 'http://example.org/r.json')),
  'a Safe verdict with no report hash': stored('Safe', [], withField('report_sha256', undefined)),
  'a Safe verdict with an upper-case report hash': stored('Safe', [], withField('report_sha256', 'A'.repeat(64))),
  'a Safe verdict with a short report hash': stored('Safe', [], withField('report_sha256', 'a'.repeat(63))),
  'a Safe verdict with rule ids': stored('Safe', ['PF001'], () => {}),
  'an Unsafe verdict with no rule ids': stored('Unsafe', [], () => {}),
  'a Warn verdict with a repeated rule id': stored('Warn', ['PF010', 'PF010'], () => {}),
  'a Warn verdict with a rule id that is not PF and three digits': stored('Warn', ['PF1'], () => {}),
  'an Unsafe verdict with too many rule ids': stored('Unsafe', Array.from({ length: 33 }, (_, i) => `PF${String(100 + i)}`), () => {}),
  'a Safe verdict whose rule ids are not a list': stored('Safe', [], withField('rule_ids', 'PF001')),
  'a Safe verdict from an auditor that is no account id': stored('Safe', [], withField('auditor', 'Not An Account')),
  'a Safe verdict with no auditor': stored('Safe', [], withField('auditor', undefined)),
  'a Safe verdict with a publish time that is not a number': stored('Safe', [], withField('published_at_ms', 'yesterday')),
  'a Safe verdict with a publish time above 64 bits': stored('Safe', [], withField('published_at_ms', '18446744073709551616')),
  'a Safe verdict with a publish time that is a number, not text': stored('Safe', [], withField('published_at_ms', 1762790400000)),
  'a verdict with a status the registry does not have': stored('Safe', [], withField('status', 'Maybe')),
  'a verdict for another code hash': stored('Safe', [], withField('code_hash', '9EUtV11wgCZ4N16xa24ETnn8E78GjeSit1r7gMyQZ6Zi')),
  'an account with no contract': (fake) => { fake.accounts.set(TARGET, {}); },
  'an account that does not exist': () => {},
  'the registry unreachable': (fake) => { fake.accounts.set(TARGET, { wasm: fakeWasm('safe') }); fake.publish(TARGET, 'Safe'); fake.faults.set('call_function', { kind: 'http', status: 500 }); },
  'the account unreadable': (fake) => { fake.accounts.set(TARGET, { wasm: fakeWasm('safe') }); fake.faults.set('view_account', { kind: 'http', status: 500 }); },
  'a registry answer that is not a verdict': (fake) => { fake.accounts.set(TARGET, { wasm: fakeWasm('safe') }); fake.faults.set('call_function', { kind: 'body', text: 'not json' }); },
};

let dir;
before(async () => { dir = await mkdtemp(join(tmpdir(), 'account-check-guard.')); });
after(() => rm(dir, { recursive: true, force: true }));

/** Runs `situate` on a fresh fake chain and hands `use` the chain and its URL; the chain is stopped afterwards. */
async function onFakeChain(situate, use) {
  const fake = new FakeNear(REGISTRY);
  const url = await fake.start();
  try {
    situate(fake);
    return await use(fake, url);
  } finally {
    await fake.stop();
  }
}

/** What an agent that tries to pay TARGET ends up with: `allow` (signed and sent), or the decision it was refused with (`warn` when nobody approves). */
async function agentOutcome(fake, url, n) {
  const signer = new KeyPairSigner(KeyPair.fromRandom('ed25519'));
  fake.addKey(AGENT, (await signer.getPublicKey()).toString(), { FunctionCall: { allowance: '250000000000000000000000', receiver_id: TARGET, method_names: ['release'] } });
  const agent = new GuardedAgent({
    accountId: AGENT, signer, guard: { rpcUrl: url, registryId: REGISTRY, timeoutMs: 3000, rateLimitBackoffMs: [] },
    policy: { allowedContracts: [TARGET], maxDepositPerCall: 0n, maxTotalDeposit: 0n }, logPath: join(dir, `decisions-${n}.jsonl`),
  });
  try {
    await agent.guardedCall({ contractId: TARGET, method: 'release', args: {}, deposit: 0n, gas: teraToGas('30') });
    return 'allow';
  } catch (error) {
    if (!(error instanceof RefusedError)) throw error;
    return error.entry.decision;
  }
}

const pageRead = (url, fake) => checkAccount(TARGET, 'mainnet', { fetch: (...args) => globalThis.fetch(...args), sleep: async () => {} }, {
  networks: { mainnet: { label: 'Mainnet', rpcUrls: [url], explorerUrl: 'https://explorer.example' } },
  registry: { rpcUrls: [url], accountId: fake.registryId },
});

/** The page's answer in the guard's terms: what `checkContract` says, what the paying call does, and the code hash it judged. */
function pageSays(result) {
  if (result.state === 'checked') return { check: result.guard.check, decision: result.guard.decision, codeHash: result.codeHash };
  if (result.state === 'failed') return { check: result.decision, decision: result.decision, codeHash: result.codeHash ?? null };
  assert.ok(result.state === 'missing' || result.state === 'nocode', `the page decided nothing for ${result.state}`);
  return { check: 'allow', decision: 'block', codeHash: null };
}

describe('the page says what the guard says', () => {
  let n = 0;
  for (const [name, situate] of Object.entries(SCENARIOS)) {
    test(name, async () => {
      await onFakeChain(situate, async (fake, url) => {
        n += 1;
        const guard = await inspectContract(TARGET, { rpcUrl: url, registryId: REGISTRY, timeoutMs: 3000, rateLimitBackoffMs: [] });
        const page = pageSays(await pageRead(url, fake));
        assert.equal(page.check, guard.decision, 'what checkContract says');
        assert.equal(page.codeHash, guard.codeHash, 'the code it judged');
        assert.equal(page.decision, await agentOutcome(fake, url, n), 'what an agent that tries to pay does');
      });
    });
  }

  test('the cases cover every decision the guard can give, so none can drift unseen', async () => {
    const seen = new Set();
    for (const situate of Object.values(SCENARIOS)) {
      await onFakeChain(situate, async (fake, url) => {
        seen.add((await inspectContract(TARGET, { rpcUrl: url, registryId: REGISTRY, timeoutMs: 3000, rateLimitBackoffMs: [] })).decision);
      });
    }
    assert.deepEqual([...seen].sort(), ['allow', 'block', 'warn']);
  });

  test('a global contract named by its publisher is not decided by the page; the guard reads the code and decides', async () => {
    await onFakeChain((fake) => { fake.accounts.set(TARGET, { wasm: fakeWasm('pub'), globalPublisher: 'publisher.test.near' }); fake.publish(TARGET, 'Safe'); }, async (fake, url) => {
      const page = await pageRead(url, fake);
      assert.deepEqual([page.state, page.publisher, 'guard' in page], ['global', 'publisher.test.near', false]);
      assert.equal((await inspectContract(TARGET, { rpcUrl: url, registryId: REGISTRY, timeoutMs: 3000, rateLimitBackoffMs: [] })).decision, 'allow');
    });
  });
});

test('the page accepts exactly the account ids the guard accepts', () => {
  const ids = [
    'wrap.near', 'aurora', 'a1', 'ab', 'a', '', '-', '_', 'a-b', 'a_b', 'a--b', 'a__b', 'a-_b', 'a.b', 'a..b', '.a', 'a.', '-a', 'a-', 'A.near', 'a.NEAR', 'a b', 'a\tb', 'a\u0000b', 'a‮b',
    'wäp', 'wrap.near.', 'x'.repeat(63), 'x'.repeat(64), 'x'.repeat(65), '0x'.padEnd(42, 'a'), '1'.repeat(64), 'a.b.c.d.e.f', 'sub.alice.near', '<img src=x onerror=alert(1)>.near', 'a/b', 'a@b', 'a:b',
  ];
  for (const id of ids) assert.equal(validateAccountId(id).ok, isValidAccountId(id.trim()), JSON.stringify(id));
});
