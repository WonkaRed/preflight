// The auditor-free check in the browser (src/code-pin.js): the rules mirror guard/src/mutability.ts, so these cases are the guard's own.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { changedSince, countFullAccessKeys, createArrivalPin } from '../src/code-pin.js';
import { HASH } from './swap-chain.mjs';

const fullKey = (n) => ({ public_key: `ed25519:k${n}`, access_key: { nonce: n, permission: 'FullAccess' } });
const callKey = (n) => ({ public_key: `ed25519:c${n}`, access_key: { nonce: n, permission: { FunctionCall: { allowance: '1', receiver_id: 'a.testnet', method_names: [] } } } });
const memoryStorage = () => {
  const map = new Map();
  return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => { map.set(k, String(v)); }, map };
};

test('a fingerprint that differs from the pinned one is a change; nothing pinned, or the same one, is not', () => {
  assert.deepEqual(changedSince(HASH.vulnerable, HASH.patched), { then: HASH.vulnerable, now: HASH.patched });
  assert.equal(changedSince(HASH.vulnerable, HASH.vulnerable), null);
  assert.equal(changedSince(null, HASH.patched), null);
});

test('full-access keys are counted; function-call keys are not', () => {
  assert.equal(countFullAccessKeys({ keys: [] }), 0);
  assert.equal(countFullAccessKeys({ keys: [callKey(1), callKey(2)] }), 0);
  assert.equal(countFullAccessKeys({ keys: [fullKey(1), callKey(2), fullKey(3)], last_key: null }), 2);
});

test('a list that cannot be counted is null, never zero: it might hide a key that can deploy', () => {
  assert.equal(countFullAccessKeys(null), null);
  assert.equal(countFullAccessKeys({}), null);
  assert.equal(countFullAccessKeys({ keys: 'FullAccess' }), null);
  assert.equal(countFullAccessKeys({ keys: [] , last_key: 'ed25519:next' }), null, 'a partial page');
  assert.equal(countFullAccessKeys({ keys: [fullKey(1), { public_key: 'x', access_key: { nonce: 1, permission: 'Mystery' } }] }), null, 'a kind of key this page does not know');
  assert.equal(countFullAccessKeys({ keys: [null] }), null);
  assert.equal(countFullAccessKeys({ keys: [{ access_key: { permission: { FunctionCall: null } } }] }), null);
});

test('the first fingerprint seen is the pin, in memory and in session storage, and later ones never replace it', () => {
  const storage = memoryStorage();
  const pin = createArrivalPin(storage, 'chameleon.example.testnet');
  assert.equal(pin.see(HASH.vulnerable), HASH.vulnerable);
  assert.equal(pin.see(HASH.patched), HASH.vulnerable);
  assert.deepEqual([...storage.map.values()], [HASH.vulnerable]);
  assert.equal(createArrivalPin(storage, 'chameleon.example.testnet').see(HASH.patched), HASH.vulnerable, 'a reload in the same tab keeps the pin');
  assert.equal(createArrivalPin(storage, 'other.example.testnet').see(HASH.patched), HASH.patched, 'one pin per address');
});

test('without usable storage the pin lives in memory: a blocked, throwing or poisoned store changes nothing', () => {
  const blocked = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceededError'); } };
  const a = createArrivalPin(blocked, 'chameleon.example.testnet');
  assert.equal(a.see(HASH.vulnerable), HASH.vulnerable);
  assert.equal(a.see(HASH.patched), HASH.vulnerable);
  const b = createArrivalPin(null, 'chameleon.example.testnet');
  assert.equal(b.see(HASH.patched), HASH.patched);
  const poisoned = memoryStorage();
  poisoned.setItem('preflight-arrival:chameleon.example.testnet', '<img src=x>');
  assert.equal(createArrivalPin(poisoned, 'chameleon.example.testnet').see(HASH.patched), HASH.patched, 'a stored value that is not a hash is ignored');
});
