// "Check a contract you know": what Preflight's guard would say about paying any NEAR account, read from the chain now.
// No DOM here (account-check-view.js paints). Reads only: view_account, view_access_key_list and the registry's get_verdict,
// through the Swap's transport (swap.js `createRpc`), so the endpoints fail over the same way. Chain data is untrusted: every
// answer is checked for the shape expected, and anything else is a failure, never a verdict.
//
// The decision is the guard's own rule (guard/src/check.ts `inspectContract`, then `guardedCall` in guard/src/guarded.ts),
// pinned to the real guard by test/account-check-guard.test.mjs.
import { countFullAccessKeys } from './code-pin.js';
import { isHash } from './near.js';
import { SWAP_CONFIG } from './swap-config.js';
import { DECISION, callView, createRpc, isAccountId, query } from './swap.js';

const NO_CODE_HASH = '11111111111111111111111111111111';
const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

// Every origin here must also be in the page's connect-src (index.html) and send Access-Control-Allow-Origin on its answers.
export const NETWORKS = {
  mainnet: { label: 'Mainnet', rpcUrls: ['https://free.rpc.fastnear.com', 'https://near-mainnet.drpc.org'], explorerUrl: 'https://nearblocks.io' },
  testnet: { label: 'Testnet', rpcUrls: SWAP_CONFIG.rpcUrls, explorerUrl: 'https://testnet.nearblocks.io' },
};

// The registry lives on testnet. A code hash is the same on every network, so the verdict lookup is the same for either.
export const REGISTRY = { rpcUrls: SWAP_CONFIG.rpcUrls, accountId: SWAP_CONFIG.registryId };

/** One-click examples, one per guard answer: two mainnet rows of docs/mainnet-survey.md (no verdict yet: warn), the demo shop with a
 * published PF001 verdict (block) and the chameleon (allow, block after a swap). A test keeps the mainnet ones in the survey. */
export const EXAMPLES = [
  { accountId: 'wrap.near', network: 'mainnet', caption: 'Wrapped NEAR' },
  { accountId: 'v2.ref-finance.near', network: 'mainnet', caption: 'Ref Finance exchange' },
  { accountId: 'shop-vulnerable.preflight-guard.testnet', network: 'testnet', caption: 'A shop Preflight flagged' },
  { accountId: SWAP_CONFIG.chameleonId, network: 'testnet', caption: 'The demo chameleon' },
];

/** `{ ok: true, accountId }` for a NEAR account id, else `{ ok: false, reason }` in words for the person who typed it. Leading and trailing spaces are dropped. */
export function validateAccountId(text) {
  const accountId = typeof text === 'string' ? text.trim() : '';
  if (accountId === '') return { ok: false, reason: 'Type a NEAR account name first.' };
  if (accountId.length < 2) return { ok: false, reason: 'A NEAR account name has at least 2 characters.' };
  if (accountId.length > 64) return { ok: false, reason: 'A NEAR account name has at most 64 characters.' };
  if (/[A-Z]/.test(accountId) && isAccountId(accountId.toLowerCase())) return { ok: false, reason: 'NEAR account names are lowercase only.' };
  if (!isAccountId(accountId)) return { ok: false, reason: 'A NEAR account name uses only lowercase letters, digits and the separators - _ . with a letter or digit on each side of every separator.' };
  return { ok: true, accountId };
}

const RULE_ID = /^PF\d{3}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const U64_MAX = 2n ** 64n - 1n;
const MAX_RULE_IDS = 32;
const MAX_REPORT_URL_LENGTH = 256;
const REPORT_URL = /^https?:\/\/[\x21-\x7e]*$/;

/**
 * The registry's `get_verdict` answer for `codeHash` as the guard accepts it (guard/src/check.ts `parseVerdict`): every field of a stored verdict must
 * have the shape the registry enforces, and anything else throws, so the check fails and the decision is block. Never a dropped field: the guard would
 * refuse a verdict this page quietly repaired. `null` is no verdict (a WARN). Returns `{ decision, ruleIds, registered, auditor, reportUrl }`.
 */
export function parseRegistryVerdict(raw, codeHash) {
  if (raw === null) return { decision: 'WARN', ruleIds: [], registered: false, auditor: null, reportUrl: null };
  if (!isObject(raw)) throw new Error('registry get_verdict returned neither null nor an object');
  const bad = (field) => new Error(`registry get_verdict returned a malformed verdict: bad ${field}`);
  const text = (field) => {
    if (typeof raw[field] !== 'string') throw bad(field);
    return raw[field];
  };
  if (text('code_hash') !== codeHash) throw new Error('registry answered for a different code hash than the one requested');
  const status = text('status');
  if (!Object.hasOwn(DECISION, status)) throw bad('status');
  const ruleIds = raw.rule_ids;
  if (!Array.isArray(ruleIds) || ruleIds.length > MAX_RULE_IDS) throw bad('rule_ids');
  if (!ruleIds.every((id) => typeof id === 'string' && RULE_ID.test(id)) || new Set(ruleIds).size !== ruleIds.length) throw bad('rule_ids');
  if ((status === 'Safe') !== (ruleIds.length === 0)) throw bad('rule_ids');
  const reportUrl = text('report_url');
  if (reportUrl.length > MAX_REPORT_URL_LENGTH || !REPORT_URL.test(reportUrl)) throw bad('report_url');
  if (!SHA256_HEX.test(text('report_sha256'))) throw bad('report_sha256');
  const auditor = text('auditor');
  if (!isAccountId(auditor)) throw bad('auditor');
  const publishedAtMs = text('published_at_ms');
  if (!/^\d{1,20}$/.test(publishedAtMs) || BigInt(publishedAtMs) > U64_MAX) throw bad('published_at_ms');
  return { decision: DECISION[status], ruleIds, registered: true, auditor, reportUrl };
}

/**
 * What the guard does for an agent that pays `codeHash` (null: no account, or no code) given the registry's `verdict` (`parseRegistryVerdict`: no verdict is a WARN).
 * `check` is `checkContract`'s answer, `decision` what `guardedCall` does with it: a code-less account is `allow` (nothing to audit) there, yet a
 * function call to it is refused (guard/src/guarded.ts, "codeHash === null").
 */
export function guardDecision(codeHash, verdict) {
  if (codeHash === null) return { check: 'allow', decision: 'block' };
  const decision = verdict.decision.toLowerCase();
  return { check: decision, decision };
}

const failed = (accountId, network, what, error, extra = {}) => ({
  state: 'failed', accountId, network, what, detail: error?.message ?? 'unknown error', ...extra,
  // The guard fails closed: while it cannot check, it refuses.
  decision: 'block',
});

const optionalText = (account, key) => {
  const value = account[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') throw new Error(`view_account field ${key} is neither a string nor null`);
  return value;
};

/** `view_account`'s answer as the guard reads it (guard/src/check.ts `viewAccount`): the hash the account names, if any, and the publisher of a global contract it follows. */
function readClaims(account) {
  const local = account.code_hash;
  if (!isHash(local)) throw new Error('view_account returned no usable code_hash');
  const globalHash = optionalText(account, 'global_contract_hash');
  const publisher = optionalText(account, 'global_contract_account_id');
  if (globalHash !== null && !isHash(globalHash)) throw new Error('view_account returned a global_contract_hash that is not a hash');
  if (publisher !== null && !isAccountId(publisher)) throw new Error('view_account returned a global_contract_account_id that is not an account id');
  // A global contract leaves `code_hash` all zeros; a real local hash beside a global field contradicts itself.
  if (local !== NO_CODE_HASH && (globalHash !== null || publisher !== null)) throw new Error('view_account reports both a local code hash and a global contract');
  return { codeHash: globalHash ?? (local === NO_CODE_HASH ? null : local), publisher };
}

const unknownAccount = (error) => error?.kind === 'rpc' && /UNKNOWN_ACCOUNT/.test(error.detail);

/**
 * Reads `accountId` (already validated) on `network` ('mainnet' | 'testnet') and returns what the page shows. Never throws.
 *
 * state 'missing'  the account does not exist.
 * state 'nocode'   it exists and holds no contract (code hash all zeros).
 * state 'global'   it follows a global contract by its publisher; the code it runs is not named by the account, so nothing is decided here.
 * state 'checked'  `codeHash`, `keys` (full-access key count, null when it could not be counted), `publisher` (of a global contract, else null),
 *                  `verdict` (`parseRegistryVerdict`, `registered: false` for no verdict) and `guard` ({ check, decision }, see `guardDecision`).
 * state 'failed'   the chain or the registry could not be read; `what` says which; `decision` is the guard's: block.
 * Every state carries `accountId`, `network` and `host` (the endpoint that answered last, or null).
 */
export async function checkAccount(accountId, network, env, { networks = NETWORKS, registry = REGISTRY } = {}) {
  const chain = createRpc(env, networks[network].rpcUrls);
  const host = () => { try { return chain.host(); } catch { return null; } };
  const done = (result) => ({ accountId, network, host: host(), ...result });
  let account;
  try {
    account = await query(chain, { request_type: 'view_account', account_id: accountId });
  } catch (error) {
    if (unknownAccount(error)) return done({ state: 'missing' });
    return done(failed(accountId, network, 'account', error));
  }
  let claims;
  try {
    claims = readClaims(account);
  } catch (error) {
    return done(failed(accountId, network, 'account', error));
  }
  if (claims.codeHash === null && claims.publisher === null) return done({ state: 'nocode' });
  const keys = query(chain, { request_type: 'view_access_key_list', account_id: accountId }).then(countFullAccessKeys, () => null);
  if (claims.codeHash === null) return done({ state: 'global', publisher: claims.publisher, keys: await keys });
  let verdict;
  try {
    const registryChain = createRpc(env, registry.rpcUrls);
    verdict = parseRegistryVerdict(await callView(registryChain, registry.accountId, 'get_verdict', { code_hash: claims.codeHash }), claims.codeHash);
  } catch (error) {
    return done(failed(accountId, network, 'registry', error, { codeHash: claims.codeHash }));
  }
  return done({ state: 'checked', codeHash: claims.codeHash, keys: await keys, publisher: claims.publisher, verdict, guard: guardDecision(claims.codeHash, verdict) });
}
