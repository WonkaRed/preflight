// A fake NEAR RPC node for the Swap tests: one chameleon account that swaps between two builds, a switch contract with
// `status()`, a registry, an access key with a nonce. It answers the same JSON-RPC the page sends, as `fetch` would.
import { createHash } from 'node:crypto';
import { base58Encode } from '../src/near.js';
import { SWAP_CONFIG } from '../src/swap-config.js';

// The page's own config with the live fields blanked: what a checkout without a deployment ships.
export const UNSET_CONFIG = { ...SWAP_CONFIG, chameleonId: '', switchId: '', registryId: '', flipKey: '', robberId: '', robberKey: '' };
import { readFileSync } from 'node:fs';

export const vector = JSON.parse(readFileSync(new URL('data/swap-vector.json', import.meta.url), 'utf8'));
export const recordedJson = JSON.parse(readFileSync(new URL('data/swap-recorded.json', import.meta.url), 'utf8'));

export const CONFIG = {
  ...SWAP_CONFIG, chameleonId: 'chameleon.example.testnet', switchId: 'switch.example.testnet', registryId: 'registry.example.testnet', flipKey: vector.secretKey, flipSignerId: '',
  robberId: 'robber.example.testnet', robberKey: vector.secretKey, robGasTgas: 30,
};

const WASM = { vulnerable: new TextEncoder().encode('demo vulnerable build'), patched: new TextEncoder().encode('demo patched build') };
export const HASH = Object.fromEntries(Object.entries(WASM).map(([name, wasm]) => [name, base58Encode(createHash('sha256').update(wasm).digest())]));
/** `switch.status()` as the contract returns it (demo/swap/switch/src/lib.rs, `Status`). */
export const status = (flips, nextFlipMs, hashes = HASH, live = 'vulnerable', lastFlipMs = 0) => ({
  chameleon: 'chameleon.example.testnet', live, flips, last_flip_ms: lastFlipMs, min_interval_ms: 10_000, next_flip_ms: nextFlipMs,
  vulnerable: { code_hash: hashes.vulnerable, code_hash_hex: '00', size_bytes: 21 }, patched: { code_hash: hashes.patched, code_hash_hex: '00', size_bytes: 18 },
});
const HEIGHT = 1_000_000;
const utf8 = (value) => [...Buffer.from(JSON.stringify(value))];

/** The `tx` answer for a successful `flip` the switch signed itself (the flip key lives on the switch). */
export const flipTxResult = { transaction: { signer_id: 'switch.example.testnet', receiver_id: 'switch.example.testnet', actions: [{ FunctionCall: { method_name: 'flip', args: 'e30=', gas: 1, deposit: '0' } }] }, status: { SuccessValue: '' } };

/** The chain's own panic when the patched build refuses a direct call to `on_deposit` (demo/swap/chameleon/patched/src/lib.rs). */
export const ON_DEPOSIT_PRIVATE_FAILURE = { ActionError: { index: 0, kind: { FunctionCallError: { ExecutionError: 'Smart contract panicked: Method on_deposit is private' } } } };

const readString = (bytes, at) => {
  const len = bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24);
  return { value: Buffer.from(bytes.subarray(at + 4, at + 4 + len)).toString('utf8'), at: at + 4 + len };
};

/**
 * Reads the one field this fake chain needs out of a signed transaction `near.js#encodeFunctionCall` produced: which
 * method it calls, on which receiver, with which JSON args. A purpose-built mirror of that one encoder, not a general
 * Borsh reader; it is wrong to use for anything else.
 */
export function decodeSignedTx(signedBase64) {
  const bytes = Buffer.from(signedBase64, 'base64');
  let at = 0;
  ({ at } = readString(bytes, at)); // signerId
  at += 1 + 32 + 8; // key type, public key, nonce
  const receiver = readString(bytes, at);
  at = receiver.at + 32; // blockHash
  at += 4 + 1; // actions vec len (always 1 here), action tag (FunctionCall)
  const method = readString(bytes, at);
  const argsLen = bytes[method.at] | (bytes[method.at + 1] << 8) | (bytes[method.at + 2] << 16) | (bytes[method.at + 3] << 24);
  const argsBytes = bytes.subarray(method.at + 4, method.at + 4 + argsLen);
  return { receiverId: receiver.value, methodName: method.value, args: JSON.parse(Buffer.from(argsBytes).toString('utf8')) };
}

/** `chain.script.<name>` holds per-test misbehavior; `chain.calls` records every request as `{ method, params }`. */
export function fakeChain() {
  const chain = {
    build: 'vulnerable', flips: 3, lastFlipMs: 0, nextFlipMs: 0, minIntervalMs: 10_000, nowMs: 1_800_000_000_000, nonce: 1000,
    verdicts: {
      [HASH.vulnerable]: { code_hash: HASH.vulnerable, status: 'Unsafe', rule_ids: ['PF001'], report_url: 'https://example.com/vulnerable.json', auditor: 'auditor.example.testnet' },
      [HASH.patched]: { code_hash: HASH.patched, status: 'Safe', rule_ids: [], report_url: 'https://example.com/patched.json', auditor: 'auditor.example.testnet' },
    },
    lag: 0, lagAfterSend: 0, target: null, // account reads that still show the old build after a swap (the deploy receipt lands later)
    sendErrors: [],  // JSON-RPC errors send_tx answers with, one per call, before it succeeds
    sendResult: null, // overrides a successful send_tx result
    txResult: null, // what `tx` (look a transaction up by hash) answers; null is UNKNOWN_TRANSACTION
    upgradeFails: false, // the flip succeeds but the chameleon's upgrade does not: no new code, no count, no countdown
    // The last swap, for the page to find on chain: blocks come every `blockMs`, the swap ran at `lastFlipMs` (a block's time), and its
    // transaction is `swapTx`. `skipped` heights are ones the chain never produced; `statusLive` is what the switch says is live.
    blockMs: 1000, skipped: new Set(), swapTx: null, statusLive: undefined,
    keys: [], keyListError: null, // the chameleon's access keys, as view_access_key_list lists them: none, as on testnet
    down: false, accessKeyError: null, statusOverride: undefined, codeOverride: undefined,
    calls: [],
    taken: new Set(),
    balances: {}, // account id -> yoctoNEAR string the chameleon's `balance_of` reports; `on_deposit` is the only writer
  };
  const rpcError = (cause, info) => ({ error: { name: 'HANDLER_ERROR', cause: { name: cause, info } } });
  const view = (value) => ({ result: { result: utf8(value), logs: [], block_height: 1, block_hash: vector.tx.blockHash } });

  chain.fetch = async (url, init) => {
    const { method, params } = JSON.parse(init.body);
    chain.calls.push({ url, method, params });
    if (chain.down) throw new TypeError('fetch failed');
    const answer = (() => {
      if (method === 'block' && params.block_id !== undefined) {
        const height = params.block_id;
        if (chain.skipped.has(height)) return rpcError('UNKNOWN_BLOCK', {});
        return { result: { header: { height, hash: vector.tx.blockHash, timestamp_nanosec: String(BigInt(chain.nowMs - (HEIGHT - height) * chain.blockMs) * 1_000_000n) } } };
      }
      if (method === 'block') return { result: { header: { height: HEIGHT, hash: vector.tx.blockHash, timestamp_nanosec: String(BigInt(chain.nowMs) * 1_000_000n) } } };
      if (method === 'EXPERIMENTAL_changes') {
        const ran = HEIGHT - (chain.nowMs - chain.lastFlipMs) / chain.blockMs;
        const changes = chain.swapTx && params.block_id === ran + (chain.swapTx.blocksLate ?? 0)
          ? [{ cause: { type: 'receipt_processing', receipt_hash: HASH.patched }, type: 'access_key_update' }, { cause: { type: 'transaction_processing', tx_hash: chain.swapTx.hash }, type: 'access_key_update' }] : [];
        return { result: { block_hash: vector.tx.blockHash, changes } };
      }
      if (method === 'send_tx') {
        const error = chain.sendErrors.shift();
        if (error) return { error };
        const decoded = decodeSignedTx(params.signed_tx_base64);
        if (decoded.methodName === 'on_deposit') {
          const done = { result: chain.sendResult ?? { final_execution_status: 'EXECUTED_OPTIMISTIC', status: { SuccessValue: '' } } };
          if (chain.taken.has(params.signed_tx_base64)) return done;
          chain.taken.add(params.signed_tx_base64);
          chain.nonce += 1; // the chain consumes the key's nonce once a transaction is accepted, whether the call itself then succeeds or not
          if (chain.sendResult) return done; // a test overrides the whole outcome (e.g. a forced Failure)
          if (chain.build === 'patched') return { result: { final_execution_status: 'EXECUTED_OPTIMISTIC', status: { Failure: ON_DEPOSIT_PRIVATE_FAILURE } } };
          const { depositor, net } = decoded.args;
          chain.balances[depositor] = String(BigInt(chain.balances[depositor] ?? '0') + BigInt(net));
          return done;
        }
        const done = { result: chain.sendResult ?? { final_execution_status: 'EXECUTED_OPTIMISTIC', status: { SuccessValue: '' } } };
        if (chain.taken.has(params.signed_tx_base64)) return done; // the chain takes one signed transaction once, however often it is sent
        chain.taken.add(params.signed_tx_base64);
        if (chain.upgradeFails) return { result: chain.sendResult }; // the switch's callback leaves everything as it was
        chain.target = chain.build === 'vulnerable' ? 'patched' : 'vulnerable';
        chain.lag = chain.lagAfterSend;
        if (chain.lag === 0) chain.build = chain.target;
        chain.flips += 1;
        chain.nextFlipMs = chain.nowMs + chain.minIntervalMs;
        return done;
      }
      if (method === 'tx' && chain.swapTx && params.tx_hash === chain.swapTx.hash) return { result: chain.swapTx.result };
      if (method === 'tx') return chain.txResult ? { result: chain.txResult } : rpcError('UNKNOWN_TRANSACTION', { requested_transaction_hash: params.tx_hash });
      const { request_type: type, account_id: account } = params;
      if (type === 'view_account') {
        const shown = chain.build;
        if (chain.lag > 0 && --chain.lag === 0) chain.build = chain.target;
        return { result: { code_hash: HASH[shown], amount: '1' } };
      }
      if (type === 'view_code') {
        const wasm = chain.codeOverride ?? WASM[chain.build];
        return { result: { code_base64: Buffer.from(wasm).toString('base64'), hash: HASH[chain.build] } };
      }
      if (type === 'view_access_key_list') return chain.keyListError ? rpcError(chain.keyListError) : { result: { keys: chain.keys, block_height: 1, block_hash: vector.tx.blockHash } };
      if (type === 'view_access_key') return chain.accessKeyError ? rpcError(chain.accessKeyError) : { result: { nonce: chain.nonce, permission: 'FullAccess' } };
      if (type === 'call_function' && account === 'switch.example.testnet' && params.method_name === 'status') {
        if (chain.statusOverride !== undefined) return view(chain.statusOverride);
        return view(status(chain.flips, chain.nextFlipMs, HASH, chain.statusLive ?? chain.build, chain.lastFlipMs));
      }
      if (type === 'call_function' && account === 'chameleon.example.testnet' && params.method_name === 'balance_of') {
        const { account_id: who } = JSON.parse(Buffer.from(params.args_base64, 'base64').toString());
        return view(chain.balances[who] ?? '0');
      }
      if (type === 'call_function' && account === 'registry.example.testnet' && params.method_name === 'get_verdict') {
        const { code_hash: hash } = JSON.parse(Buffer.from(params.args_base64, 'base64').toString());
        return view(chain.verdicts[hash] ?? null);
      }
      throw new Error(`fake chain: unexpected ${method} ${JSON.stringify(params)}`);
    })();
    return { ok: true, status: 200, json: async () => ({ jsonrpc: '2.0', id: 'preflight-swap', ...answer }) };
  };
  return chain;
}
