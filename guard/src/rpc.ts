// Minimal NEAR JSON-RPC `query` client. Every failure (network, timeout, HTTP status, malformed body, RPC error)
// surfaces as an RpcFailure, so callers fail closed with one catch.
import { setTimeout as sleep } from "node:timers/promises";
import { describeError } from "./text.ts";

export class RpcFailure extends Error {
  /** `error.cause.name` of a JSON-RPC error, such as `UNKNOWN_ACCOUNT`; undefined for transport failures. */
  readonly causeName: string | undefined;

  constructor(message: string, causeName?: string) {
    super(message);
    this.name = "RpcFailure";
    this.causeName = causeName;
  }
}

export type JsonObject = Record<string, unknown>;

export function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const DEFAULT_TIMEOUT_MS = 10_000;
/** Node's timers keep a delay in a signed 32-bit integer; a larger one overflows and fires at once. */
export const MAX_TIMER_MS = 2 ** 31 - 1;

/** Whether `value` is a delay a Node timer honors: a whole number of milliseconds from 1 to 2^31-1. */
export function isValidTimeoutMs(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= MAX_TIMER_MS;
}

/**
 * The waits before each retry of a query the node answered with HTTP 429: 0.5, 1, 2 and 4 seconds, so a throttled
 * public endpoint gets about 7.5 seconds to recover before the query fails (and the guard blocks). A query is a read,
 * so repeating it is safe; nothing else is retried. The query's `timeoutMs` covers the retries and these waits too.
 */
export const DEFAULT_RATE_LIMIT_BACKOFF_MS: readonly number[] = [500, 1_000, 2_000, 4_000];
const MAX_BACKOFF_STEPS = 10;

/** Whether `value` is a list of at most 10 delays a Node timer honors (`[]` turns the retry off). */
export function isValidBackoff(value: unknown): value is readonly number[] {
  return Array.isArray(value) && value.length <= MAX_BACKOFF_STEPS && value.every(isValidTimeoutMs);
}

/** What `snapshotBackoff` returns for anything that is not a list of at most 10 entries: a list `isValidBackoff` rejects. */
const INVALID_BACKOFF: readonly number[] = Object.freeze([0]);

/**
 * A copy of a backoff list that cannot change under the caller: `length` is read once, and the entries by index, never
 * through the list's iterator, so an array edited later, or a Proxy that answers differently the second time, is not
 * what gets validated and used, and a Proxy cannot hang the copy with an endless iterator or a huge length. Anything
 * that is not an array with a length from 0 to 10 (or that throws when read) becomes a list `isValidBackoff` rejects.
 */
export function snapshotBackoff(value: unknown): readonly number[] {
  try {
    if (!Array.isArray(value)) return INVALID_BACKOFF;
    const length: unknown = value.length;
    if (typeof length !== "number" || !Number.isInteger(length) || length < 0 || length > MAX_BACKOFF_STEPS) return INVALID_BACKOFF;
    const copy: number[] = [];
    for (let index = 0; index < length; index++) copy.push(value[index] as number);
    return copy;
  } catch {
    return INVALID_BACKOFF;
  }
}

/**
 * Calls the RPC `query` method and returns `result`, which is always a JSON object. `timeoutMs` is one deadline for the
 * whole query: every attempt, every 429 wait and the reading of the answer share it.
 */
export async function rpcQuery(rpcUrl: string, params: JsonObject, timeoutMs = DEFAULT_TIMEOUT_MS, rateLimitBackoffMs: readonly number[] = DEFAULT_RATE_LIMIT_BACKOFF_MS): Promise<JsonObject> {
  const requestType = String(params["request_type"]);
  if (!isValidTimeoutMs(timeoutMs)) throw new RpcFailure(`timeoutMs must be a whole number of milliseconds from 1 to ${MAX_TIMER_MS}`);
  const waits = snapshotBackoff(rateLimitBackoffMs);
  if (!isValidBackoff(waits)) throw new RpcFailure(`rateLimitBackoffMs must be a list of at most ${MAX_BACKOFF_STEPS} whole numbers of milliseconds from 1 to ${MAX_TIMER_MS}`);
  const signal = AbortSignal.timeout(timeoutMs);
  let text: string;
  try {
    for (let retry = 0; ; retry++) {
      const response = await fetch(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "preflight", method: "query", params }),
        signal,
      });
      const wait = waits[retry];
      if (response.status === 429 && wait !== undefined) {
        await response.body?.cancel();
        await sleep(wait, undefined, { signal });
        continue;
      }
      if (!response.ok) throw new Error(response.status === 429 ? `HTTP 429 (rate limited, still after ${retry} retries)` : `HTTP ${response.status}`);
      text = await response.text();
      break;
    }
  } catch (error) {
    const reason = signal.aborted ? `no answer within ${timeoutMs} ms` : describeError(error);
    throw new RpcFailure(`RPC ${requestType} request failed: ${reason}`);
  }

  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new RpcFailure(`RPC ${requestType} response is not valid JSON`);
  }
  if (!isObject(body)) throw new RpcFailure(`RPC ${requestType} response is not a JSON-RPC object`);

  if ("error" in body) {
    const error = body["error"];
    const cause = isObject(error) ? error["cause"] : undefined;
    const causeName = isObject(cause) && typeof cause["name"] === "string" ? cause["name"] : undefined;
    throw new RpcFailure(`RPC ${requestType} returned an error${causeName ? ` (${causeName})` : ""}`, causeName);
  }
  const result = body["result"];
  if (!isObject(result)) throw new RpcFailure(`RPC ${requestType} response has no result object`);
  // A failed view call is HTTP 200 with `result.error` as a message string (docs: "Errors in the result"). Any
  // other non-null `error`, whatever its type, is a failure too: it must never read as "no answer, no verdict".
  const failure = result["error"];
  if (failure !== undefined && failure !== null) {
    throw new RpcFailure(`RPC ${requestType} failed: ${(typeof failure === "string" ? failure : JSON.stringify(failure) ?? String(failure)).slice(0, 200)}`);
  }
  return result;
}

export function requireString(object: JsonObject, key: string, what: string): string {
  const value = object[key];
  if (typeof value !== "string") throw new RpcFailure(`${what} has no string field "${key}"`);
  return value;
}
