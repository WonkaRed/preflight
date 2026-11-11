// The little of NEAR the Swap needs, with no library: base58, Borsh for one function-call transaction, and an ed25519
// signature from WebCrypto. Nothing here touches the network or the page, so it runs the same in a browser and in node's
// test runner. `test/near.test.mjs` checks every byte against a transaction built and signed by near-api-js 7.4.0.

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const encoder = new TextEncoder();

export function base58Encode(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const byte of bytes) n = n * 256n + BigInt(byte);
  let out = '';
  for (; n > 0n; n /= 58n) out = ALPHABET[Number(n % 58n)] + out;
  return '1'.repeat(zeros) + out;
}

export function base58Decode(text) {
  let zeros = 0;
  while (zeros < text.length && text[zeros] === '1') zeros++;
  let n = 0n;
  for (const char of text) {
    const digit = ALPHABET.indexOf(char);
    if (digit < 0) throw new RangeError('not base58');
    n = n * 58n + BigInt(digit);
  }
  const bytes = [];
  for (; n > 0n; n >>= 8n) bytes.unshift(Number(n & 0xffn));
  return Uint8Array.from([...new Array(zeros).fill(0), ...bytes]);
}

/** Whether `text` is a base58 string of exactly 32 bytes: the shape of every NEAR hash (code hash, block hash, tx hash). */
export function isHash(text) {
  if (typeof text !== 'string' || text.length > 44) return false;
  try { return base58Decode(text).length === 32; } catch { return false; }
}

const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
};

// Borsh, little endian. Integers outside their width are an error, never a silent wrap.
const uint = (value, bytes) => {
  const big = BigInt(value);
  if (big < 0n || big >= 1n << BigInt(8 * bytes)) throw new RangeError(`${value} does not fit in u${8 * bytes}`);
  return Uint8Array.from({ length: bytes }, (_, i) => Number((big >> BigInt(8 * i)) & 0xffn));
};
const vec = (bytes) => concat([uint(bytes.length, 4), bytes]);
const string = (text) => vec(encoder.encode(text));
const fixed = (bytes, length, what) => {
  if (bytes.length !== length) throw new RangeError(`${what} must be ${length} bytes`);
  return bytes;
};

const ED25519 = 0;
const FUNCTION_CALL = 2;

/** The Borsh bytes of a transaction with one FunctionCall action. `args` is the raw argument bytes. Keys and hashes are bytes. */
export function encodeFunctionCall({ signerId, publicKey, nonce, receiverId, blockHash, method, args, gas, deposit = 0n }) {
  return concat([
    string(signerId), uint(ED25519, 1), fixed(publicKey, 32, 'public key'), uint(nonce, 8), string(receiverId), fixed(blockHash, 32, 'block hash'),
    uint(1, 4), uint(FUNCTION_CALL, 1), string(method), vec(args), uint(gas, 8), uint(deposit, 16),
  ]);
}

/** `ed25519:<base58 of seed then public key>`, the form NEAR prints a secret key in. */
export function parseSecretKey(text) {
  const match = /^ed25519:([1-9A-HJ-NP-Za-km-z]+)$/.exec(text);
  const bytes = match && base58Decode(match[1]);
  if (!bytes || bytes.length !== 64) throw new RangeError('not an ed25519 secret key');
  return { seed: bytes.slice(0, 32), publicKey: bytes.slice(32) };
}

// PKCS#8 wrapper of a raw ed25519 seed (RFC 8410): WebCrypto imports private keys only in this form.
const PKCS8_ED25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

/**
 * Signs the transaction the way NEAR does (ed25519 over the SHA-256 of its bytes). Returns the signed transaction as
 * base64, ready for `send_tx`, and the transaction hash, which is also its explorer id. The signature is checked against
 * the key's own public half before it is returned, so a secret key whose halves do not match fails here, loudly, and not
 * as a rejected transaction. Throws when this browser has no ed25519 in WebCrypto.
 */
export async function signTransaction(txBytes, secretKey, subtle = globalThis.crypto?.subtle) {
  if (!subtle) throw new Error('WebCrypto is not available here (it needs https or localhost)');
  const { seed, publicKey } = parseSecretKey(secretKey);
  const hash = new Uint8Array(await subtle.digest('SHA-256', txBytes));
  let signature;
  try {
    const key = await subtle.importKey('pkcs8', concat([PKCS8_ED25519, seed]), 'Ed25519', false, ['sign']);
    signature = new Uint8Array(await subtle.sign('Ed25519', key, hash));
    const pub = await subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
    if (!(await subtle.verify('Ed25519', pub, signature, hash))) throw new RangeError('the secret key does not match its public key');
  } catch (error) {
    if (error?.name === 'NotSupportedError') throw new Error('this browser cannot sign with ed25519 (WebCrypto)');
    throw error;
  }
  return { signedBase64: btoa(String.fromCharCode(...concat([txBytes, uint(ED25519, 1), signature]))), txHash: base58Encode(hash) };
}
