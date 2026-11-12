// The auditor-free check, in the browser: the page remembers the code fingerprint it first saw at the address, and a later
// fingerprint that differs means the code changed since the visitor arrived. It needs no registry and no auditor, only two
// reads of the chain. This mirrors the small rules of guard/src/mutability.ts (`pinChangeReason`, `countFullAccessKeys`);
// the guard's code is Node-only and is not imported here.
import { isHash } from './near.js';

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/** `{ then, now }` when `codeHash` differs from the pinned one; null when nothing is pinned yet or the code is the same. */
export const changedSince = (pinned, codeHash) => (pinned === null || pinned === codeHash ? null : { then: pinned, now: codeHash });

/**
 * The number of full-access keys in a `view_access_key_list` answer, or null when the answer cannot be counted: not a key
 * list, a partial page (`last_key` set), or a key of a kind this page does not know. Null never reads as zero: an unknown
 * key might be able to deploy code.
 */
export function countFullAccessKeys(result) {
  if (!isObject(result) || !Array.isArray(result.keys)) return null;
  if (result.last_key !== undefined && result.last_key !== null) return null;
  let full = 0;
  for (const key of result.keys) {
    const permission = isObject(key) && isObject(key.access_key) ? key.access_key.permission : undefined;
    if (permission === 'FullAccess') full += 1;
    else if (!(isObject(permission) && isObject(permission.FunctionCall))) return null;
  }
  return full;
}

/**
 * The fingerprint this visitor first saw at `address`, kept for the browser session: in `storage` (sessionStorage) when the
 * browser lets the page use it, in memory when it does not. `see(hash)` pins the first hash it is given and returns the pin.
 */
export function createArrivalPin(storage, address) {
  const slot = `preflight-arrival:${address}`;
  let pinned = null;
  const stored = () => { try { const value = storage?.getItem(slot); return isHash(value) ? value : null; } catch { return null; } };
  return {
    see(hash) {
      pinned ??= stored() ?? hash;
      try { if (stored() === null) storage?.setItem(slot, pinned); } catch { /* storage is blocked or full: the pin lives in memory */ }
      return pinned;
    },
  };
}
