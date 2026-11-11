// A fake NEAR RPC node for the Swap tests: one chameleon account that swaps between two builds, a switch contract with
// `status()`, a registry, an access key with a nonce. It answers the same JSON-RPC the page sends, as `fetch` would.
import { createHash } from 'node:crypto';
import { base58Encode } from '../src/near.js';
import { SWAP_CONFIG } from '../src/swap-config.js';

// The page's own config with the four live fields blanked: what a checkout without a deployment ships.
export const UNSET_CONFIG = { ...SWAP_CONFIG, chameleonId: '', switchId: '', registryId: '', flipKey: '' };
import { readFileSync } from 'node:fs';

export const vector = JSON.parse(readFileSync(new URL('data/swap-vector.json', import.meta.url), 'utf8'));
export const recordedJson = JSON.parse(readFileSync(new URL('data/swap-recorded.json', import.meta.url), 'utf8'));

export const CONFIG = {
  ...SWAP_CONFIG, chameleonId: 'chameleon.example.testnet', switchId: 'switch.example.testnet', registryId: 'registry.example.testnet', flipKey: vector.secretKey, flipSignerId: '',
};

const WASM = { vulnerable: new TextEncoder().encode('demo vulnerable build'), patched: new TextEncoder().encode('demo patched build') };
export const HASH = Object.fromEntries(Object.entries(WASM).map(([name, wasm]) => [name, base58Encode(createHash('sha256').update(wasm).digest())]));
/** `switch.status()` as the contract returns it (demo/swap/switch/src/lib.rs, `Status`). */
export const status = (flips, nextFlipMs, hashes = HASH) => ({
  chameleon: 'chameleon.example.testnet', live: 'vulnerable', flips, last_flip_ms: 0, min_interval_ms: 10_000, next_flip_ms: nextFlipMs,
  vulnerable: { code_hash: hashes.vulnerable, code_hash_hex: '00', size_bytes: 21 }, patched: { code_hash: hashes.patched, code_hash_hex: '00', size_bytes: 18 },
});
const utf8 = (value) => [...Buffer.from(JSON.stringify(value))];

/** `chain.script.<name>` holds per-test misbehavior; `chain.calls` records every request as `{ method, params }`. */
export function fakeChain() {
  const chain = {
    build: 'vulnerable', flips: 3, nextFlipMs: 0, minIntervalMs: 10_000, nowMs: 1_800_000_000_000, nonce: 1000,
    verdicts: {
      [HASH.vulnerable]: { code_hash: HASH.vulnerable, status: 'Unsafe', rule_ids: ['PF001'], report_url: 'https://example.com/vulnerable.json', auditor: 'auditor.example.testnet' },
      [HASH.patched]: { code_hash: HASH.patched, status: 'Safe', rule_ids: [], report_url: 'https://example.com/patched.json', auditor: 'auditor.example.testnet' },
    },
    lag: 0, lagAfterSend: 0, target: null, // account reads that still show the old build after a swap (the deploy receipt lands later)
    sendErrors: [],  // JSON-RPC errors send_tx answers with, one per call, before it succeeds
    sendResult: null, // overrides a successful send_tx result
    txResult: null, // what `tx` (look a transaction up by hash) answers; null is UNKNOWN_TRANSACTION
    upgradeFails: false, // the flip succeeds but the chameleon's upgrade does not: no new code, no count, no countdown
    down: false, accessKeyError: null, statusOverride: undefined, codeOverride: undefined,
    calls: [],
    taken: new Set(),
  };
  const rpcError = (cause, info) => ({ error: { name: 'HANDLER_ERROR', cause: { name: cause, info } } });
  const view = (value) => ({ result: { result: utf8(value), logs: [], block_height: 1, block_hash: vector.tx.blockHash } });

  chain.fetch = async (url, init) => {
    const { method, params } = JSON.parse(init.body);
    chain.calls.push({ url, method, params });
    if (chain.down) throw new TypeError('fetch failed');
    const answer = (() => {
      if (method === 'block') return { result: { header: { hash: vector.tx.blockHash, timestamp_nanosec: String(BigInt(chain.nowMs) * 1_000_000n) } } };
      if (method === 'send_tx') {
        const error = chain.sendErrors.shift();
        if (error) return { error };
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
      if (type === 'view_access_key') return chain.accessKeyError ? rpcError(chain.accessKeyError) : { result: { nonce: chain.nonce, permission: 'FullAccess' } };
      if (type === 'call_function' && account === 'switch.example.testnet' && params.method_name === 'status') {
        if (chain.statusOverride !== undefined) return view(chain.statusOverride);
        return view(status(chain.flips, chain.nextFlipMs));
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
