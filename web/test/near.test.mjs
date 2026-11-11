// src/near.js: base58, the Borsh transaction and the ed25519 signature, byte for byte against a transaction built and
// signed by near-api-js 7.4.0 (test/data/swap-vector.json).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { base58Decode, base58Encode, encodeFunctionCall, isHash, parseSecretKey, signTransaction } from '../src/near.js';

const vector = JSON.parse(readFileSync(new URL('data/swap-vector.json', import.meta.url), 'utf8'));
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const encode = (over = {}) => {
  const { tx } = vector;
  return encodeFunctionCall({
    signerId: tx.signerId, publicKey: base58Decode(vector.publicKey.slice('ed25519:'.length)), nonce: BigInt(tx.nonce), receiverId: tx.receiverId,
    blockHash: base58Decode(tx.blockHash), method: tx.method, args: new TextEncoder().encode(tx.argsJson), gas: BigInt(tx.gas), deposit: BigInt(tx.deposit), ...over,
  });
};

test('base58 round-trips, keeps leading zero bytes, and rejects characters outside the alphabet', () => {
  for (const bytes of [[], [0], [0, 0, 1], [255], Array.from({ length: 32 }, (_, i) => i * 8)]) {
    assert.deepEqual([...base58Decode(base58Encode(Uint8Array.from(bytes)))], bytes);
  }
  assert.equal(base58Encode(new Uint8Array(32)), '1'.repeat(32), 'the all-zero hash is 32 ones, the "no code" hash');
  for (const bad of ['0', 'O', 'I', 'l', 'a b', '+']) assert.throws(() => base58Decode(bad), RangeError, bad);
});

test('isHash accepts exactly a base58 string of 32 bytes', () => {
  assert.equal(isHash(vector.txHash), true);
  assert.equal(isHash('1'.repeat(32)), true);
  for (const bad of ['', 'abc', base58Encode(new Uint8Array(31)), base58Encode(new Uint8Array(33).fill(1)), `${vector.txHash}0`, null, 42, 'x'.repeat(100)]) assert.equal(isHash(bad), false, String(bad));
});

test('the transaction bytes are what near-api-js encodes', () => {
  assert.equal(hex(encode()), vector.txHex);
});

test('the signature, signed transaction and transaction hash are what near-api-js produces', async () => {
  const { signedBase64, txHash } = await signTransaction(encode(), vector.secretKey);
  assert.equal(txHash, vector.txHash);
  assert.equal(signedBase64, vector.signedBase64);
});

test('integers outside their width and keys or hashes of the wrong length are errors, never a silent wrap', () => {
  assert.throws(() => encode({ nonce: 2n ** 64n }), RangeError);
  assert.throws(() => encode({ gas: -1n }), RangeError);
  assert.throws(() => encode({ deposit: 2n ** 128n }), RangeError);
  assert.throws(() => encode({ blockHash: new Uint8Array(31) }), RangeError);
  assert.throws(() => encode({ publicKey: new Uint8Array(33) }), RangeError);
});

test('a secret key that is not 64 bytes of ed25519 is refused', () => {
  for (const bad of ['', 'ed25519:', 'secp256k1:abc', `ed25519:${base58Encode(new Uint8Array(32).fill(1))}`, vector.secretKey.slice('ed25519:'.length), 'ed25519:0OIl']) {
    assert.throws(() => parseSecretKey(bad), RangeError, bad);
  }
});

test('a secret key whose halves do not match fails at signing, not at the chain', async () => {
  const seed = base58Decode(vector.secretKey.slice('ed25519:'.length)).slice(0, 32);
  const other = base58Decode(vector.publicKey.slice('ed25519:'.length)).map((b) => b ^ 1);
  const mismatched = `ed25519:${base58Encode(Uint8Array.from([...seed, ...other]))}`;
  await assert.rejects(() => signTransaction(encode(), mismatched));
});

test('no WebCrypto, or no ed25519 in it, is a plain error', async () => {
  await assert.rejects(() => signTransaction(encode(), vector.secretKey, null), /WebCrypto is not available/);
  const subtle = { digest: async () => new Uint8Array(32), importKey: async () => { throw Object.assign(new Error('x'), { name: 'NotSupportedError' }); } };
  await assert.rejects(() => signTransaction(encode(), vector.secretKey, subtle), /cannot sign with ed25519/);
});
