// The Swap's logic, with no DOM: it reads one NEAR account's deployed code over RPC, looks the code's hash up in the
// registry, and sends the `flip` transaction that swaps the code. The page (swap-view.js) only paints `state`.
//
// Chain data is untrusted. Every answer is checked for the shape this file expects before it is used, and anything else
// is an error, never a verdict. Network access goes through `env.fetch` only, so tests run it against a fake node.
import { base58Decode, base58Encode, encodeFunctionCall, isHash, parseSecretKey, signTransaction } from './near.js';

export const POLL_MS = 5000;
// A visitor who has not clicked for ACTIVE_MS is probably not watching: read less often, so open tabs spare the public RPC.
export const IDLE_POLL_MS = 15_000;
export const ACTIVE_MS = 120_000;
const RPC_TIMEOUT_MS = 8000;
// After every endpoint failed once, reads wait this long and go round once more before the page says the RPC is unreachable.
const ROUND_PAUSE_MS = 400;
// Failed reads that leave the last live data on screen (with a note) before the page falls back to the recording.
const RECONNECT_POLLS = 2;
const TX_LOOKUPS = 3;
const LANDING_POLLS = 10;
const LANDING_MS = 1500;
const NONCE_TRIES = 3;
// The contract's interval is measured on chain time and the page reads chain time a block or two late: wait a second more.
const COUNTDOWN_MARGIN_MS = 1000;
const NO_CODE_HASH = '11111111111111111111111111111111';
const ACCOUNT_ID = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
const RULE_ID = /^PF\d{3}$/;
const DECISION = { Unsafe: 'BLOCK', Warn: 'WARN', Safe: 'ALLOW' };
const BUILDS = ['vulnerable', 'patched'];

export const isAccountId = (id) => typeof id === 'string' && id.length >= 2 && id.length <= 64 && ACCOUNT_ID.test(id);
const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/** A failure of one RPC step. `kind`: 'network' (no usable answer), 'rpc' (the node answered with an error), 'shape' (an answer this page cannot read), 'raced' (the code changed between two reads). */
export class RpcError extends Error {
  constructor(message, kind, detail = '') {
    super(message);
    this.name = 'RpcError';
    this.kind = kind;
    this.detail = detail;
  }
}

// ---- Config and recording ------------------------------------------------------------------------------------------

/** The config as the controller uses it, or `{ ok: false, missing }` naming every field that is empty or malformed. */
export function readConfig(config) {
  const missing = [];
  for (const field of ['chameleonId', 'switchId', 'registryId']) if (!isAccountId(config[field])) missing.push(field);
  if (config.flipSignerId !== '' && !isAccountId(config.flipSignerId)) missing.push('flipSignerId');
  let secret = null;
  try { secret = parseSecretKey(config.flipKey); } catch { missing.push('flipKey'); }
  if (!Array.isArray(config.rpcUrls) || config.rpcUrls.length === 0 || config.rpcUrls.length > 6 || !config.rpcUrls.every((url) => typeof url === 'string' && /^https:\/\/[\w.-]+(:\d+)?(\/\S*)?$/.test(url))) missing.push('rpcUrls');
  if (!Number.isInteger(config.flipGasTgas) || config.flipGasTgas < 1 || config.flipGasTgas > 300) missing.push('flipGasTgas');
  if (missing.length) return { ok: false, missing };
  return { ok: true, ...config, flipSignerId: config.flipSignerId || config.switchId, secret, gas: BigInt(config.flipGasTgas) * 10n ** 12n };
}

const GUARD_DECISIONS = ['allow', 'block', 'warn'];

/**
 * `demo/swap/recorded.json` (written by its `record` script) as the page replays it, or null if it is not that file.
 * `steps` is the chameleon as recorded before the first swap, then after each swap with that swap's transaction.
 */
export function parseRecorded(json) {
  if (!isObject(json) || !/^\d{4}-\d{2}-\d{2}T/.test(json.recordedAt) || !isAccountId(json.chameleon)) return null;
  if (!Array.isArray(json.flips) || json.flips.length === 0 || json.flips.length > 100) return null;
  const step = (snapshot, txHash) => {
    const verdict = isObject(snapshot) ? snapshot.verdict : undefined;
    if (!isObject(snapshot) || !BUILDS.includes(snapshot.live) || !isHash(snapshot.codeHash) || !GUARD_DECISIONS.includes(snapshot.decision)) return null;
    if (txHash !== null && !isHash(txHash)) return null;
    if (verdict !== null && !(isObject(verdict) && verdict.status in DECISION && Array.isArray(verdict.rule_ids) && verdict.rule_ids.every((id) => RULE_ID.test(id)))) return null;
    return { build: snapshot.live, codeHash: snapshot.codeHash, decision: snapshot.decision.toUpperCase(), ruleIds: verdict?.rule_ids ?? [], registered: verdict !== null, txHash };
  };
  const steps = [step(json.flips[0]?.before, null), ...json.flips.map((flip) => step(flip?.after, flip?.txHash))];
  return steps.every(Boolean) ? { recordedAt: json.recordedAt.slice(0, 10), chameleonId: json.chameleon, steps } : null;
}

// ---- RPC ---------------------------------------------------------------------------------------------------------

// An endpoint that is throttled, down, blocked by CORS (a 429 carries no CORS header, so the browser reports a network
// failure) or answering in something other than NEAR's JSON-RPC errors is 'network': the next endpoint may do better. A
// NEAR error (HANDLER_ERROR and the like) is the chain's own answer, the same everywhere, and is 'rpc'.
const CHAIN_ERRORS = ['HANDLER_ERROR', 'REQUEST_VALIDATION_ERROR'];
// ...unless it says only that this node cannot answer now (it timed out, is still syncing, lacks that block or shard).
const NODE_TROUBLE = ['TIMEOUT_ERROR', 'NOT_SYNCED_YET', 'UNKNOWN_BLOCK', 'UNAVAILABLE_SHARD'];

async function post(env, url, method, params) {
  let body;
  try {
    const response = await env.fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'preflight-swap', method, params }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    body = await response.json();
  } catch (error) {
    throw new RpcError(`RPC ${method} request failed: ${error?.name === 'TimeoutError' ? 'no answer in time' : error?.message ?? 'unknown'}`, 'network');
  }
  if (!isObject(body)) throw new RpcError(`RPC ${method} answered with something that is not JSON-RPC`, 'network');
  if (body.error === undefined && !('result' in body)) throw new RpcError(`RPC ${method} answered with neither a result nor an error`, 'network');
  if (body.error !== undefined) {
    const name = body.error?.cause?.name;
    const chains = isObject(body.error) && CHAIN_ERRORS.includes(body.error.name) && typeof name === 'string' && !NODE_TROUBLE.includes(name);
    throw new RpcError(`RPC ${method} returned an error${typeof name === 'string' ? ` (${name.slice(0, 60)})` : ''}`, chains ? 'rpc' : 'network', JSON.stringify(body.error).slice(0, 2000));
  }
  return body.result;
}

/**
 * Every RPC request goes through here. It tries the endpoints in turn, starting with the one that answered last, and
 * fails only when all of them failed in one round; reads then wait a moment and go round once more. Sending the same
 * request to another endpoint is safe for a signed transaction (one hash, the chain takes it once), so `send_tx` passes
 * the same bytes to each and never goes round twice.
 */
function createRpc(env, urls) {
  let first = 0;
  async function round(method, params) {
    let failure;
    for (let i = 0; i < urls.length; i++) {
      const at = (first + i) % urls.length;
      try {
        const result = await post(env, urls[at], method, params);
        first = at;
        return result;
      } catch (error) {
        if (error.kind !== 'network') throw error;
        failure = error;
      }
    }
    throw failure;
  }
  return {
    /** The host of the endpoint that answered last. */
    host: () => new URL(urls[first]).hostname,
    async call(method, params, { retry = true } = {}) {
      try {
        return await round(method, params);
      } catch (error) {
        if (!retry || error.kind !== 'network') throw error;
        await env.sleep(ROUND_PAUSE_MS);
        return round(method, params);
      }
    },
  };
}

async function query(net, params) {
  const result = await net.call('query', { finality: 'optimistic', ...params });
  if (!isObject(result)) throw new RpcError(`RPC ${params.request_type} answered with no result object`, 'shape');
  // A failed view is HTTP 200 with `result.error` as text, which must never read as "no answer, no verdict".
  if (result.error !== undefined && result.error !== null) throw new RpcError(`RPC ${params.request_type} failed`, 'rpc', String(result.error).slice(0, 2000));
  return result;
}

async function callView(net, accountId, method, args = {}) {
  const result = await query(net, { request_type: 'call_function', account_id: accountId, method_name: method, args_base64: btoa(JSON.stringify(args)) });
  const bytes = result.result;
  if (!Array.isArray(bytes) || !bytes.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) throw new RpcError(`${accountId}.${method} returned no byte array`, 'shape');
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes)));
  } catch {
    throw new RpcError(`${accountId}.${method} returned invalid JSON`, 'shape');
  }
}

// ---- Reading the chain -------------------------------------------------------------------------------------------

const count = (value, what) => {
  const n = typeof value === 'string' && /^\d{1,15}$/.test(value) ? Number(value) : value;
  if (!Number.isSafeInteger(n) || n < 0) throw new RpcError(`status() ${what} is not a count`, 'shape');
  return n;
};

/** What `switch.status()` returns, reduced to what the page uses: the two builds' code hashes, the swap count, and when the next swap is allowed (chain time, ms). */
function parseStatus(raw) {
  const hashOf = (build) => (isObject(raw) && isObject(raw[build]) && isHash(raw[build].code_hash) ? raw[build].code_hash : null);
  if (hashOf('vulnerable') === null || hashOf('patched') === null) throw new RpcError('status() has no usable code hashes', 'shape');
  return { hashes: { vulnerable: hashOf('vulnerable'), patched: hashOf('patched') }, flips: count(raw.flips, 'flips'), nextFlipMs: count(raw.next_flip_ms, 'next_flip_ms') };
}

/** The registry's answer for one hash, as a decision. No verdict is a WARN, as in the guard: unaudited code, or code changed since its audit. */
function parseVerdict(raw, codeHash) {
  if (raw === null) return { decision: 'WARN', ruleIds: [], registered: false };
  if (!isObject(raw) || raw.code_hash !== codeHash || !(raw.status in DECISION)) throw new RpcError('registry get_verdict returned a malformed verdict', 'shape');
  const ids = raw.rule_ids;
  if (!Array.isArray(ids) || ids.length > 32 || !ids.every((id) => RULE_ID.test(id))) throw new RpcError('registry get_verdict returned malformed rule ids', 'shape');
  return { decision: DECISION[raw.status], ruleIds: ids, registered: true };
}

/** The hash of the code actually deployed: the account's claimed hash, confirmed by hashing the code bytes themselves (once per new hash). */
async function verifiedHash(env, cfg, net, claimed, seen) {
  if (seen.hash === claimed) return claimed;
  const code = await query(net, { request_type: 'view_code', account_id: cfg.chameleonId });
  if (typeof code.code_base64 !== 'string' || !/^[A-Za-z\d+/]*={0,2}$/.test(code.code_base64) || code.code_base64.length % 4 !== 0) throw new RpcError('view_code returned no valid base64', 'shape');
  const wasm = Uint8Array.from(atob(code.code_base64), (c) => c.charCodeAt(0));
  const actual = base58Encode(new Uint8Array(await env.subtle.digest('SHA-256', wasm)));
  if (actual !== code.hash) throw new RpcError('view_code bytes do not hash to the hash the RPC reports', 'shape');
  if (actual !== claimed) throw new RpcError('the account was redeployed between two reads', 'raced');
  seen.hash = actual;
  return actual;
}

async function readOnce(env, cfg, net, seen) {
  const [account, statusRaw, block] = await Promise.all([
    query(net, { request_type: 'view_account', account_id: cfg.chameleonId }),
    callView(net, cfg.switchId, 'status'),
    net.call('block', { finality: 'optimistic' }),
  ]);
  if (!isHash(account.code_hash)) throw new RpcError('view_account returned no usable code_hash', 'shape');
  if (account.code_hash === NO_CODE_HASH) throw new RpcError('the account holds no contract code', 'shape');
  const status = parseStatus(statusRaw);
  const nanos = block?.header?.timestamp_nanosec;
  if (typeof nanos !== 'string' || !/^\d{10,25}$/.test(nanos)) throw new RpcError('block header has no timestamp', 'shape');

  const codeHash = await verifiedHash(env, cfg, net, account.code_hash, seen);
  const verdict = parseVerdict(await callView(net, cfg.registryId, 'get_verdict', { code_hash: codeHash }), codeHash);
  const remaining = status.nextFlipMs - Number(BigInt(nanos) / 1_000_000n);
  return {
    codeHash,
    build: BUILDS.find((name) => status.hashes[name] === codeHash) ?? null,
    verdict,
    flips: status.flips,
    waitUntil: remaining > 0 ? env.now() + remaining + COUNTDOWN_MARGIN_MS : null,
  };
}

// ---- Sending the swap --------------------------------------------------------------------------------------------

// Every way the demo key can stop being able to pay (nearcore's InvalidTxError, InvalidAccessKeyError and ActionError names,
// and the RPC's UNKNOWN_ACCESS_KEY for a deleted key): the allowance is spent, the account cannot cover gas or its storage, or the key is gone.
const CANNOT_PAY = /NotEnoughAllowance|NotEnoughBalance|LackBalanceForState|SignerDoesNotExist|AccessKeyNotFound|UNKNOWN_ACCESS_KEY/;
// What the switch logs, in the callback's receipt, when the chameleon's upgrade failed: the flip itself succeeded, the code did not change.
const UPGRADE_FAILED = 'the chameleon\'s upgrade failed';
const NONCE = /InvalidNonce/;

const upgradeFailed = (result) => (result?.receipts_outcome ?? []).some((receipt) => (receipt?.outcome?.logs ?? [])
  .some((line) => typeof line === 'string' && line.includes(UPGRADE_FAILED)));

/** The contract's own panic text from a failed outcome, else a plain sentence. Chain text, so it only ever reaches the page as text. */
function failureMessage(failure) {
  const panic = /Smart contract panicked: ([^"\\]{1,160})/.exec(JSON.stringify(failure));
  return panic ? `The contract refused the swap: ${panic[1]}` : 'The transaction failed on chain.';
}

// ---- The controller ----------------------------------------------------------------------------------------------

const defaults = () => ({
  fetch: (...args) => globalThis.fetch(...args),
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  subtle: globalThis.crypto?.subtle,
  hidden: () => globalThis.document?.hidden ?? false,
  schedule: (fn, ms) => { const id = setTimeout(fn, ms); return () => clearTimeout(id); },
});

/**
 * Starts nothing by itself: `start()` begins reading. `onChange(state)` fires after every change.
 *
 * state.mode   'loading' | 'live' | 'recorded' | 'empty'. Anything but 'live' is never presented as live: 'recorded'
 *              replays the bundled recording, 'empty' means there is neither a live contract nor a recording.
 * state.reason why the mode is not live: 'unconfigured' | 'rpc-down' | 'cannot-pay' (the demo key can no longer pay for swaps).
 * state.tx     the swap this visitor sent: { stage: 'pending' | 'landing' | 'done' | 'unseen' | 'failed' | 'unconfirmed', hash, message }.
 * state.waitUntil  local epoch ms before which the contract will refuse another swap, or null.
 * state.replay  the recording's current step (0 is before its first swap).
 * state.reconnecting  live data is still shown but the last read failed on every endpoint (a note, not yet a fallback).
 * state.endpoint  the host the last read went through, while live.
 */
export function createSwap({ config, recorded = null, onChange = () => {}, env: overrides = {} }) {
  const env = { ...defaults(), ...overrides };
  const cfg = readConfig(config);
  const seen = { hash: null };
  const net = cfg.ok ? createRpc(env, cfg.rpcUrls) : null;
  let state = {
    mode: 'loading', reason: null, detail: '', recorded, replay: 0,
    address: config.chameleonId || recorded?.chameleonId || null,
    codeHash: null, build: null, verdict: null, flips: null, waitUntil: null, tx: null, reconnecting: false, endpoint: null,
  };
  let cancelTimer = () => {};
  let activeUntil = 0;
  let stopped = false;
  let busy = false;
  let reading = null;
  let spent = false;
  let failedReads = 0;

  const set = (patch) => { state = { ...state, ...patch }; onChange(state); };
  const fallback = (reason, detail = '') => set({
    mode: recorded ? 'recorded' : 'empty', reason, detail, tx: null, waitUntil: null, reconnecting: false, endpoint: null,
    replay: state.mode === 'recorded' ? state.replay : 0,
  });

  async function readChain() {
    for (let attempt = 0; ; attempt++) {
      try { return await readOnce(env, cfg, net, seen); } catch (error) { if (error.kind !== 'raced' || attempt > 0) throw error; }
    }
  }

  function refresh() {
    reading ??= (async () => {
      if (spent || !cfg.ok) return;
      try {
        const chain = await readChain();
        failedReads = 0;
        set({ mode: 'live', reason: null, detail: '', reconnecting: false, endpoint: net.host(), ...chain });
      } catch (error) {
        // A blip must not replace data that was live a moment ago: keep it, with a note, for a couple of reads. Reading goes on
        // either way, so a recording gives way to live data again as soon as one read works.
        if (state.mode === 'live' && ++failedReads <= RECONNECT_POLLS) set({ reconnecting: true });
        else fallback('rpc-down', error instanceof RpcError ? error.message : 'unexpected failure reading the chain');
      }
    })().finally(() => { reading = null; });
    return reading;
  }

  // Nothing live is left to show: the recording takes over for good, and the page stops reading.
  function giveUp() {
    spent = true;
    return fallback('cannot-pay');
  }

  /** The final outcome of our own transaction as the chain has it, or null: still unknown, or nobody could say. */
  async function outcomeOf(hash, tries) {
    for (let attempt = 0; attempt < tries; attempt++) {
      if (attempt > 0) await env.sleep(LANDING_MS);
      try {
        const result = await net.call('tx', { tx_hash: hash, sender_account_id: cfg.flipSignerId, wait_until: 'NONE' });
        if (isObject(result?.status) && ('SuccessValue' in result.status || 'Failure' in result.status)) return result;
      } catch { /* not found yet, or no endpoint answered: the next try, or unconfirmed */ }
    }
    return null;
  }

  async function sendFlip() {
    await reading;
    const before = state.codeHash;
    let hash = null;
    let sent = false;
    set({ tx: { stage: 'pending', hash, message: '' } });
    try {
      let result;
      for (let attempt = 0; ; attempt++) {
        const [key, block] = await Promise.all([
          query(net, { request_type: 'view_access_key', account_id: cfg.flipSignerId, public_key: `ed25519:${base58Encode(cfg.secret.publicKey)}` }),
          net.call('block', { finality: 'final' }),
        ]);
        if (!Number.isSafeInteger(key.nonce) || !isHash(block?.header?.hash)) throw new RpcError('the access key or block answer is unusable', 'shape');
        const bytes = encodeFunctionCall({
          signerId: cfg.flipSignerId, publicKey: cfg.secret.publicKey, nonce: key.nonce + 1, receiverId: cfg.switchId,
          blockHash: base58Decode(block.header.hash), method: 'flip', args: new TextEncoder().encode('{}'), gas: cfg.gas,
        });
        const signed = await signTransaction(bytes, cfg.flipKey, env.subtle);
        hash = signed.txHash;
        set({ tx: { stage: 'pending', hash, message: '' } });
        sent = true;
        try {
          result = await net.call('send_tx', { signed_tx_base64: signed.signedBase64, wait_until: 'EXECUTED_OPTIMISTIC' }, { retry: false });
          break;
        } catch (error) {
          // No answer from any endpoint: the transaction may still have landed, so ask for it by hash before saying anything failed.
          if (error.kind === 'network') {
            result = await outcomeOf(hash, TX_LOOKUPS);
            if (result) break;
          }
          // Another visitor used the shared key a moment ago: read its nonce again and sign again. A copy of this very
          // transaction that an endpoint took before failing also makes the nonce stale, so look for it first.
          if (error.kind === 'rpc' && NONCE.test(error.detail) && attempt + 1 < NONCE_TRIES) {
            result = await outcomeOf(hash, 1);
            if (result) break;
            sent = false;
            continue;
          }
          throw error;
        }
      }
      const status = result?.status;
      if (isObject(status) && 'Failure' in status) {
        if (CANNOT_PAY.test(JSON.stringify(status.Failure))) return giveUp();
        set({ tx: { stage: 'failed', hash, message: failureMessage(status.Failure) } });
        return refresh();
      }
      if (!isObject(status) || !('SuccessValue' in status)) throw new RpcError('send_tx returned no final status', 'network');
      if (upgradeFailed(result)) {
        set({ tx: { stage: 'failed', hash, message: 'The swap was accepted, but the chameleon\'s upgrade failed, so it still runs the previous build.' } });
        return refresh();
      }
      set({ tx: { stage: 'landing', hash, message: '' } });
      // The deploy is a later receipt than the call: read until the chain shows the new code, for a bounded time.
      for (let poll = 0; poll < LANDING_POLLS; poll++) {
        await refresh();
        if (state.mode !== 'live' || state.codeHash !== before) break;
        await env.sleep(LANDING_MS);
      }
      if (state.mode === 'live') set({ tx: { stage: state.codeHash !== before ? 'done' : 'unseen', hash, message: '' } });
    } catch (error) {
      if (error instanceof RpcError && error.kind === 'rpc' && CANNOT_PAY.test(error.detail)) return giveUp();
      const unconfirmed = sent && error instanceof RpcError && error.kind === 'network';
      set({ tx: { stage: unconfirmed ? 'unconfirmed' : 'failed', hash: sent ? hash : null, message: error instanceof RpcError ? (sent ? '' : 'Nothing was sent. ') + error.message : error.message } });
    }
  }

  async function poll() {
    if (stopped) return;
    if (!busy && !env.hidden()) await refresh();
    if (!stopped && !spent) cancelTimer = env.schedule(poll, env.now() < activeUntil ? POLL_MS : IDLE_POLL_MS);
  }

  return {
    getState: () => state,
    start() {
      stopped = false;
      activeUntil = env.now() + ACTIVE_MS;
      if (!cfg.ok) return fallback('unconfigured', `Not set in swap-config.js: ${cfg.missing.join(', ')}`);
      return poll();
    },
    stop() { stopped = true; cancelTimer(); },
    /** The visitor is back (tab shown again): read at once and poll at the fast rate for a while. */
    wake() {
      activeUntil = env.now() + ACTIVE_MS;
      return refresh();
    },
    /** Live: sign and send `flip`. Recorded: step the replay. Anything else does nothing. */
    async flip() {
      if (state.mode === 'recorded') return set({ replay: (state.replay + 1) % recorded.steps.length });
      if (state.mode !== 'live' || busy || (state.waitUntil !== null && env.now() < state.waitUntil)) return;
      busy = true;
      activeUntil = env.now() + ACTIVE_MS;
      try { await sendFlip(); } finally { busy = false; }
    },
    refresh,
  };
}
