import { createHash } from "node:crypto";
import { baseDecode, baseEncode } from "near-api-js";
import { isObject, requireString, rpcQuery, RpcFailure, type JsonObject } from "./rpc.ts";
import { describeError, printable } from "./text.ts";
import { isValidAccountId } from "./validate.ts";
import type { Decision, GuardConfig, GuardResult, Verdict, VerdictStatus } from "./types.ts";

/** The `code_hash` NEAR reports for an account without a local contract (32 zero bytes in base58). */
const NO_CODE_HASH = "11111111111111111111111111111111";

/** Base58 SHA-256 of the bytes: the form NEAR RPC uses for `code_hash` and the registry uses as its key. */
export function codeHashOf(wasm: Uint8Array): string {
  return baseEncode(createHash("sha256").update(wasm).digest());
}

function isCryptoHash(value: string): boolean {
  try {
    return baseDecode(value).length === 32;
  } catch {
    return false;
  }
}

function requireHash(object: JsonObject, key: string, what: string): string {
  const value = requireString(object, key, what);
  if (!isCryptoHash(value)) throw new RpcFailure(`${what} field "${key}" is not a base58 32-byte hash`);
  return value;
}

/** What `view_account` says about an account's code. It never decides that the account has no code: `view_code` does. */
interface AccountClaims {
  /** The hash the account claims for its code: the local one, or `global_contract_hash`. Null when it names none. */
  expectedHash: string | null;
  /** The account claims to have code, even if it names no hash (a global contract by publisher account id). */
  claimsCode: boolean;
}

/** Null when the account does not exist. Throws RpcFailure on anything unexpected. */
async function viewAccount(contractId: string, config: GuardConfig): Promise<AccountClaims | null> {
  let account: JsonObject;
  try {
    account = await rpcQuery(config.rpcUrl, { request_type: "view_account", finality: "optimistic", account_id: contractId }, config.timeoutMs, config.rateLimitBackoffMs);
  } catch (error) {
    if (error instanceof RpcFailure && error.causeName === "UNKNOWN_ACCOUNT") return null;
    throw error;
  }
  const localHash = requireHash(account, "code_hash", "view_account result");
  // Global contracts (nearcore 2.14): `code_hash` stays the all-zero "no code" hash and the account carries
  // `global_contract_hash` (by code hash) or `global_contract_account_id` (by publisher). Older nodes and typed
  // proxies omit both. A field that is present must be a string or null; anything else is not an answer.
  const globalHash = optionalString(account, "global_contract_hash");
  const globalPublisher = optionalString(account, "global_contract_account_id");
  if (globalHash !== null && !isCryptoHash(globalHash)) throw new RpcFailure('view_account field "global_contract_hash" is not a base58 32-byte hash');
  // A global contract leaves `code_hash` at all zeros; a real local hash next to a global field contradicts itself.
  if (localHash !== NO_CODE_HASH && (globalHash !== null || globalPublisher !== null)) {
    throw new RpcFailure("view_account reports both a local code_hash and a global contract");
  }
  const expectedHash = globalHash ?? (localHash === NO_CODE_HASH ? null : localHash);
  return { expectedHash, claimsCode: expectedHash !== null || globalPublisher !== null };
}

function optionalString(object: JsonObject, key: string): string | null {
  const value = object[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw new RpcFailure(`view_account field "${key}" is neither a string nor null`);
  return value;
}

function decodeBase64(value: string): Uint8Array {
  // Buffer.from silently skips invalid characters; a hash over silently corrupted bytes must never be trusted.
  if (value.length % 4 !== 0 || !/^[A-Za-z\d+/]*={0,2}$/.test(value)) throw new RpcFailure("view_code code_base64 is not valid base64");
  return Buffer.from(value, "base64");
}

/**
 * Reads the deployed wasm, hashes it, and cross-checks the hash against what the RPC reports. Null when
 * `view_code` says there is no contract code and `view_account` does not claim any.
 */
async function verifiedCodeHash(contractId: string, claims: AccountClaims, config: GuardConfig): Promise<string | null> {
  let code: JsonObject;
  try {
    code = await rpcQuery(config.rpcUrl, { request_type: "view_code", finality: "optimistic", account_id: contractId }, config.timeoutMs, config.rateLimitBackoffMs);
  } catch (error) {
    if (!(error instanceof RpcFailure) || error.causeName !== "NO_CONTRACT_CODE") throw error;
    if (claims.claimsCode) throw new RpcFailure("view_account claims the account has code but view_code answered NO_CONTRACT_CODE");
    return null;
  }
  const wasm = decodeBase64(requireString(code, "code_base64", "view_code result"));
  const reported = requireHash(code, "hash", "view_code result");
  const actual = codeHashOf(wasm);
  if (actual !== reported) throw new RpcFailure(`view_code bytes hash to ${actual} but the RPC reports ${reported}`);
  if (claims.expectedHash !== null && actual !== claims.expectedHash) {
    throw new RpcFailure(`view_code bytes hash to ${actual} but the account's code hash is ${claims.expectedHash} (redeployed during the check? retry)`);
  }
  return actual;
}

const STATUSES: readonly string[] = ["Safe", "Warn", "Unsafe"] satisfies VerdictStatus[];
const MAX_RULE_IDS = 32;
const RULE_ID = /^PF\d{3}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const U64_MAX = 2n ** 64n - 1n;
const MAX_REPORT_URL_BYTES = 256;
// The registry only requires the scheme prefix and a length. The guard shows this URL to people and to approvers, so it
// also insists on printable ASCII without spaces: nothing that could hide in a log, a terminal or a link.
const REPORT_URL = /^https?:\/\/[\x21-\x7e]*$/;

/**
 * Turns the registry's answer into a Verdict only if every field has the shape the registry contract enforces when it
 * stores one (registry/src/validate.rs); anything else is an RpcFailure, so it becomes a `block`. Error messages name
 * the field and never repeat its value.
 */
function parseVerdict(value: unknown, codeHash: string): Verdict | null {
  if (value === null) return null;
  if (!isObject(value)) throw new RpcFailure("registry get_verdict returned neither null nor an object");
  const bad = (field: string): RpcFailure => new RpcFailure(`registry get_verdict returned a malformed verdict: bad ${field}`);
  const text = (field: string): string => {
    const raw = value[field];
    if (typeof raw !== "string") throw bad(field);
    return raw;
  };

  if (text("code_hash") !== codeHash) throw new RpcFailure("registry answered for a different code hash than the one requested");
  const status = text("status");
  if (!STATUSES.includes(status)) throw bad("status");
  const ruleIds = value["rule_ids"];
  if (!Array.isArray(ruleIds) || ruleIds.length > MAX_RULE_IDS) throw bad("rule_ids");
  if (!ruleIds.every((id) => typeof id === "string" && RULE_ID.test(id)) || new Set(ruleIds).size !== ruleIds.length) throw bad("rule_ids");
  if ((status === "Safe") !== (ruleIds.length === 0)) throw bad("rule_ids");
  const reportUrl = text("report_url");
  if (reportUrl.length > MAX_REPORT_URL_BYTES || !REPORT_URL.test(reportUrl)) throw bad("report_url");
  const reportSha256 = text("report_sha256");
  if (!SHA256_HEX.test(reportSha256)) throw bad("report_sha256");
  const auditor = text("auditor");
  if (!isValidAccountId(auditor)) throw bad("auditor");
  const publishedAtMs = text("published_at_ms");
  if (!/^\d{1,20}$/.test(publishedAtMs) || BigInt(publishedAtMs) > U64_MAX) throw bad("published_at_ms");

  return { code_hash: codeHash, status: status as VerdictStatus, rule_ids: ruleIds as string[], report_url: reportUrl, report_sha256: reportSha256, auditor, published_at_ms: publishedAtMs };
}

async function lookupVerdict(codeHash: string, config: GuardConfig): Promise<Verdict | null> {
  const args = Buffer.from(JSON.stringify({ code_hash: codeHash })).toString("base64");
  const call = await rpcQuery(
    config.rpcUrl,
    { request_type: "call_function", finality: "optimistic", account_id: config.registryId, method_name: "get_verdict", args_base64: args },
    config.timeoutMs,
    config.rateLimitBackoffMs,
  );
  const bytes = call["result"];
  if (!Array.isArray(bytes) || !bytes.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) {
    throw new RpcFailure("registry call_function result is not a byte array");
  }
  let json: unknown;
  try {
    json = JSON.parse(Buffer.from(bytes as number[]).toString("utf8"));
  } catch {
    throw new RpcFailure("registry get_verdict returned invalid JSON");
  }
  return parseVerdict(json, codeHash);
}

function describe(verdict: Verdict): string {
  const rules = verdict.rule_ids.length > 0 ? ` (${verdict.rule_ids.join(", ")})` : "";
  return `registry verdict ${verdict.status}${rules}: published by ${verdict.auditor}, report ${verdict.report_url}`;
}

/**
 * `checkContract` before the text of its reasons is made printable: for callers, like the wrapper, that hand the
 * reasons to something that sanitizes them itself (the decision log), so text is escaped exactly once.
 * Throws only for an invalid `contractId`.
 */
export async function inspectContract(contractId: string, config: GuardConfig): Promise<GuardResult> {
  if (!isValidAccountId(contractId)) throw new TypeError(`invalid NEAR account id: ${printable(describeError(contractId))}`);

  const result = (decision: Decision, reason: string, codeHash: string | null = null, verdict: Verdict | null = null): GuardResult => ({
    decision,
    contractId,
    codeHash,
    verdict,
    reasons: [reason],
  });

  let codeHash: string | null = null;
  try {
    const claims = await viewAccount(contractId, config);
    if (claims === null) return result("allow", "account does not exist; no contract code to audit");
    codeHash = await verifiedCodeHash(contractId, claims, config);
    if (codeHash === null) return result("allow", "account has no contract code; nothing to audit");
    const verdict = await lookupVerdict(codeHash, config);
    if (verdict === null) {
      return result("warn", `code hash ${codeHash} has no verdict in the registry: unaudited code, or code changed since its audit`, codeHash);
    }
    switch (verdict.status) {
      case "Unsafe":
        return result("block", describe(verdict), codeHash, verdict);
      case "Warn":
        return result("warn", describe(verdict), codeHash, verdict);
      case "Safe":
        return result("allow", describe(verdict), codeHash, verdict);
    }
  } catch (error) {
    // Fail closed on every failure, including bugs: an unreadable answer is never an `allow`.
    return result("block", `could not verify ${contractId}: ${describeError(error)}`, codeHash);
  }
}

/**
 * Decides whether an agent may call or pay `contractId`: reads the deployed code over RPC, hashes it and looks
 * the hash up in the registry. Fails closed: network and registry failures are `block`, never an exception.
 * Throws only for an invalid `contractId`. The reasons are safe to print: every unsafe character is escaped.
 */
export async function checkContract(contractId: string, config: GuardConfig): Promise<GuardResult> {
  return sanitizedResult(await inspectContract(contractId, config));
}

/** The result with its reasons made printable. Apply it to a result that has not been through it yet. */
export function sanitizedResult(result: GuardResult): GuardResult {
  return { ...result, reasons: result.reasons.map((reason) => printable(reason)) };
}
