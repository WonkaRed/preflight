import { Account, JsonRpcProvider, decodeSignedTransaction, encodeTransaction, type SignedTransaction, type Signer } from "near-api-js";
import { inspectContract, sanitizedResult } from "./check.ts";
import { DecisionLog, type LogEntry } from "./log.ts";
import { assertAmount, assertValidPolicy, policyViolation, type Policy } from "./policy.ts";
import { isObject, isValidBackoff, isValidTimeoutMs, MAX_TIMER_MS, rpcQuery, RpcFailure, snapshotBackoff } from "./rpc.ts";
import { describeError, printable } from "./text.ts";
import { isValidAccountId, isValidMethodName, MAX_DEPOSIT, MAX_GAS, MAX_METHOD_NAME_LENGTH } from "./validate.ts";
import type { Decision, GuardConfig, GuardResult } from "./types.ts";

export interface CallRequest {
  contractId: string;
  method: string;
  /** JSON-serializable arguments, or raw bytes. */
  args?: Record<string, unknown> | Uint8Array;
  /** yoctoNEAR attached to the call. */
  deposit: bigint;
  /** Gas attached to the call, in gas units (`teraToGas("30")`). */
  gas: bigint;
}

/** What the approver sees: the call as it will be signed, never the caller's own objects. */
export interface ApprovalRequest {
  readonly contractId: string;
  readonly method: string;
  readonly deposit: bigint;
  readonly gas: bigint;
  /**
   * The arguments parsed back from the bytes that will be signed, deep-frozen; undefined unless re-encoding the
   * parsed value with `JSON.stringify` gives exactly those bytes (duplicate keys, huge numbers, whitespace or a BOM
   * in raw byte arguments leave it undefined, and the approver must read `argsBytes`).
   */
  readonly args: unknown;
  /** A fresh copy of the bytes that will be signed; changing it changes nothing that is signed. */
  readonly argsBytes: Uint8Array;
}

/** The request as the whole call uses it: arguments already turned into the bytes that will be signed. */
interface Snapshot {
  readonly contractId: string;
  readonly method: string;
  readonly argsBytes: Uint8Array;
  readonly deposit: bigint;
  readonly gas: bigint;
}

const DEFAULT_APPROVE_TIMEOUT_MS = 120_000;
const TIMED_OUT = Symbol("approval timed out");

export interface GuardedAgentOptions {
  /** The agent's NEAR account. */
  accountId: string;
  /**
   * The agent's key. A function-call key works for one contract only, so an agent that talks to several holds
   * one key per contract: pass a function that picks the signer for a contract.
   */
  signer: Signer | ((contractId: string) => Signer);
  /** RPC endpoint and registry. The same endpoint is used to read code, check the key and send the transaction. */
  guard: GuardConfig;
  policy: Policy;
  /** The JSON-lines decision log; created if missing, appended to otherwise. */
  logPath: string;
  /**
   * Asked on every `warn`, with read-only copies of what will be signed and of the guard result. Without it a
   * `warn` is refused. Return exactly `true` to sign anyway: any other value, truthy or not, declines. Nothing the
   * callback can reach feeds the signed bytes.
   */
  approve?: (request: ApprovalRequest, guard: Readonly<GuardResult>) => boolean | Promise<boolean>;
  /** How long `approve` may take before the call counts as declined and its deposit share is released (default 120000, at most 2147483647). */
  approveTimeoutMs?: number;
  /** Allow signing with a full-access key (default false: the agent must hold a function-call key). */
  allowFullAccessKey?: boolean;
  /** Clock for log timestamps; injected by the demo to make its output deterministic. */
  now?: () => Date;
}

export interface GuardedCallResult {
  guard: GuardResult;
  transaction: Awaited<ReturnType<Account["callFunctionRaw"]>>;
}

/**
 * Thrown when the wrapper refuses to sign. Nothing was signed or sent. `entry` is the sanitized object that was
 * logged (or, if the log write failed, the one that could not be), so the message needs no escaping of its own.
 */
export class RefusedError extends Error {
  readonly entry: LogEntry;

  constructor(entry: LogEntry) {
    super(`refused to call ${entry.contract}.${entry.method}: ${entry.reasons.join("; ")}`);
    this.name = "RefusedError";
    this.entry = entry;
  }
}

/**
 * The key that was checked, and why it cannot make this call (null when it can). The permission comes straight from the
 * chain. The key is read from the signer once, here, and the signed transaction must carry exactly this key.
 */
async function keyProblem(options: GuardedAgentOptions, signer: Signer, request: Snapshot): Promise<{ publicKey: string; problem: string | null }> {
  const publicKey = (await signer.getPublicKey()).toString();
  return { publicKey, problem: await permissionProblem(options, publicKey, request) };
}

async function permissionProblem(options: GuardedAgentOptions, publicKey: string, request: Snapshot): Promise<string | null> {
  let permission: unknown;
  try {
    const key = await rpcQuery(options.guard.rpcUrl, {
      request_type: "view_access_key",
      finality: "optimistic",
      account_id: options.accountId,
      public_key: publicKey,
    }, options.guard.timeoutMs, options.guard.rateLimitBackoffMs);
    permission = key["permission"];
  } catch (error) {
    if (error instanceof RpcFailure) return `cannot read the permissions of key ${publicKey}: ${error.message}`;
    throw error;
  }
  if (permission === "FullAccess") {
    return options.allowFullAccessKey ? null : `key ${publicKey} is full-access; the agent must sign with a function-call key scoped to one contract`;
  }
  const functionCall = isObject(permission) ? permission["FunctionCall"] : undefined;
  if (!isObject(functionCall)) return `key ${publicKey} has an unsupported permission type`;
  const methods = functionCall["method_names"];
  if (functionCall["receiver_id"] !== request.contractId) return `key ${publicKey} is scoped to ${String(functionCall["receiver_id"])}, not ${request.contractId}`;
  if (!Array.isArray(methods)) return `key ${publicKey} has an unsupported permission type: method_names is not a list`;
  if (methods.length > 0 && !methods.includes(request.method)) return `key ${publicKey} may not call method ${request.method}`;
  if (request.deposit > 0n) return `key ${publicKey} is a function-call key, which cannot attach a deposit`;
  return null;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null) {
    for (const inner of Object.values(value)) deepFreeze(inner);
    Object.freeze(value);
  }
  return value;
}

/** The signed bytes as a value, only when that value stands for exactly those bytes. */
function parseJson(bytes: Uint8Array): unknown {
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    const parsed: unknown = JSON.parse(text);
    return JSON.stringify(parsed) === text ? deepFreeze(parsed) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The one copy of the request that the whole call uses, taken before the first await and before the budget is
 * touched. The arguments become bytes exactly once, here: `JSON.stringify` is what near-api-js would run on them
 * anyway, so the chain receives what the caller's own serialization produces (`toJSON`, `Buffer`, `Date` all
 * included), and nothing the caller or the approver holds afterwards can change what is signed. Arguments that
 * cannot be serialized throw here, with nothing committed. So do a contract id or method name outside the grammars
 * of validate.ts: they are the only strings the caller controls that reach a log line, an RPC request and a
 * signature, and they are checked here, once, before any of those can see them.
 */
function snapshot(input: CallRequest): Snapshot {
  const { contractId, method, deposit, gas } = input;
  if (typeof contractId !== "string" || !isValidAccountId(contractId)) throw new TypeError(`request.contractId is not a valid NEAR account id: ${printable(describeError(contractId))}`);
  if (typeof method !== "string" || !isValidMethodName(method)) throw new TypeError(`request.method is not a valid method name (letters, digits and underscores, not starting with a digit, at most ${MAX_METHOD_NAME_LENGTH}): ${printable(describeError(method))}`);
  assertAmount(deposit, "deposit");
  assertAmount(gas, "gas");
  if (deposit > MAX_DEPOSIT) throw new TypeError("deposit does not fit in 128 bits; the transaction encoding would wrap it around");
  if (gas > MAX_GAS) throw new TypeError("gas does not fit in 64 bits; the transaction encoding would wrap it around");
  const { args } = input; // read once: a getter must not be able to answer differently the second time
  let argsBytes: Uint8Array;
  if (args instanceof Uint8Array) {
    argsBytes = Uint8Array.from(args);
  } else {
    let json: string | undefined;
    try {
      json = JSON.stringify(args ?? {});
    } catch (error) {
      throw new TypeError(`request.args cannot be serialized to JSON: ${printable(describeError(error))}`);
    }
    if (json === undefined) throw new TypeError("request.args cannot be serialized to JSON");
    argsBytes = new TextEncoder().encode(json);
  }
  return Object.freeze({ contractId, method, argsBytes, deposit, gas });
}

/**
 * Why `signed` is not the call that was checked, or null. Everything is read from the transaction's own encoding, the
 * bytes that would go out, never from fields a signer could have set to something else.
 */
function signedMismatch(signed: SignedTransaction, accountId: string, publicKey: string, request: Snapshot): string | null {
  const { transaction } = signed;
  const wrong: string[] = [];
  if (transaction.nonceIndex !== undefined || transaction.nonceMode !== undefined) wrong.push("transaction version");
  if (transaction.signerId !== accountId) wrong.push("signer account");
  if (transaction.publicKey.toString() !== publicKey) wrong.push("public key");
  if (transaction.receiverId !== request.contractId) wrong.push("receiver");
  const [action, ...rest] = transaction.actions;
  const call: unknown = action === undefined || rest.length > 0 || Object.keys(action).length !== 1 ? undefined : (action as { functionCall?: unknown }).functionCall;
  if (!isObject(call)) {
    wrong.push("actions (not exactly one function call)");
  } else {
    if (call["methodName"] !== request.method) wrong.push("method");
    const args = call["args"];
    // The decoder hands back the byte vector as a plain array of numbers.
    if (!(Array.isArray(args) || args instanceof Uint8Array) || !Buffer.from(args).equals(request.argsBytes)) wrong.push("arguments");
    if (call["gas"] !== request.gas) wrong.push("gas");
    if (call["deposit"] !== request.deposit) wrong.push("deposit");
  }
  return wrong.length === 0 ? null : `the signed transaction differs from the checked request in: ${wrong.join(", ")}`;
}

/**
 * An Account that runs `beforeHandOff` on the signed transaction before it can go to the network. The transaction is
 * re-read from its own encoding, `beforeHandOff` sees only that, and that decoded copy is what the provider sends, so a
 * signer cannot show one transaction to the check and put another on the wire. `beforeHandOff` throws to stop the send.
 */
class ReportingAccount extends Account {
  readonly #beforeHandOff: (signed: SignedTransaction) => Promise<void>;

  constructor(accountId: string, provider: JsonRpcProvider, signer: Signer, beforeHandOff: (signed: SignedTransaction) => Promise<void>) {
    super(accountId, provider, signer);
    this.#beforeHandOff = beforeHandOff;
  }

  override async createSignedTransaction(params: Parameters<Account["createSignedTransaction"]>[0]): ReturnType<Account["createSignedTransaction"]> {
    const decoded = decodeSignedTransaction(encodeTransaction(await super.createSignedTransaction(params)));
    await this.#beforeHandOff(decoded);
    return decoded;
  }
}

const refusals = new WeakSet<object>();

/**
 * Why a call is refused, raised where it is found and turned into a logged RefusedError in one place. Recognized by
 * membership, not `instanceof`: `instanceof` runs the thrown value's own traps, and a hostile value (a revoked
 * proxy) makes it throw.
 */
class Refusal {
  readonly decision: Decision;
  readonly reasons: string[];
  readonly codeHash: string | null;

  constructor(decision: Decision, reasons: string[], codeHash: string | null) {
    this.decision = decision;
    this.reasons = reasons;
    this.codeHash = codeHash;
    refusals.add(this);
  }
}

function isRefusal(error: unknown): error is Refusal {
  return typeof error === "object" && error !== null && refusals.has(error);
}

/**
 * The log timestamp. A clock that throws or returns garbage must not stop a decision from being logged, and nothing the
 * clock returned may run code of its own: only the time value is read, through the built-in, and a fresh Date is built
 * from that number.
 */
function timestampOf(now: (() => Date) | undefined): string {
  try {
    const time = Date.prototype.getTime.call(now?.());
    if (Number.isFinite(time)) return new Date(time).toISOString();
  } catch {
    // fall through to the real clock
  }
  return new Date().toISOString();
}

/** Checks the options the owner passed, after they were copied: what is checked is what the agent will use. */
function validateOptions(options: GuardedAgentOptions): void {
  if (typeof options.accountId !== "string" || !isValidAccountId(options.accountId)) throw new TypeError(`accountId is not a valid NEAR account id: ${printable(describeError(options.accountId))}`);
  if (typeof options.guard.registryId !== "string" || !isValidAccountId(options.guard.registryId)) throw new TypeError(`guard.registryId is not a valid NEAR account id: ${printable(describeError(options.guard.registryId))}`);
  let protocol: string | undefined;
  try {
    protocol = new URL(options.guard.rpcUrl).protocol;
  } catch {
    protocol = undefined;
  }
  if (protocol !== "http:" && protocol !== "https:") throw new TypeError("guard.rpcUrl must be an http or https URL");
  if (typeof options.logPath !== "string" || options.logPath === "") throw new TypeError("logPath must be a non-empty path");
  if (typeof options.signer !== "function" && (typeof options.signer !== "object" || options.signer === null)) throw new TypeError("signer must be a Signer or a function returning one");
  if (options.approve !== undefined && typeof options.approve !== "function") throw new TypeError("approve must be a function");
  if (options.now !== undefined && typeof options.now !== "function") throw new TypeError("now must be a function");
  const bounds = `a whole number of milliseconds from 1 to ${MAX_TIMER_MS}`;
  if (options.approveTimeoutMs !== undefined && !isValidTimeoutMs(options.approveTimeoutMs)) throw new TypeError(`approveTimeoutMs must be ${bounds}`);
  if (options.guard.timeoutMs !== undefined && !isValidTimeoutMs(options.guard.timeoutMs)) throw new TypeError(`guard.timeoutMs must be ${bounds}`);
  if (options.guard.rateLimitBackoffMs !== undefined && !isValidBackoff(options.guard.rateLimitBackoffMs)) throw new TypeError(`guard.rateLimitBackoffMs must be a list of at most 10 whole numbers of milliseconds from 1 to ${MAX_TIMER_MS}`);
  assertValidPolicy(options.policy);
}

export class GuardedAgent {
  readonly #options: GuardedAgentOptions;
  readonly #log: DecisionLog;
  /** Deposits of every call that was signed or is in flight; a refused call releases its share. */
  #committed = 0n;

  constructor(options: GuardedAgentOptions) {
    // Each property is read once and copied, so neither the owner's later edits nor an object that answers
    // differently the second time can loosen anything mid-run; the copy is what gets validated and kept.
    const { accountId, signer, guard, policy, logPath, approve, approveTimeoutMs, allowFullAccessKey, now } = options;
    const copy: GuardedAgentOptions = {
      accountId,
      signer,
      guard: { ...guard, ...(guard.rateLimitBackoffMs !== undefined && { rateLimitBackoffMs: snapshotBackoff(guard.rateLimitBackoffMs) }) },
      policy: { ...policy, allowedContracts: [...policy.allowedContracts] },
      logPath,
      ...(approve !== undefined && { approve }),
      ...(approveTimeoutMs !== undefined && { approveTimeoutMs }),
      ...(allowFullAccessKey !== undefined && { allowFullAccessKey }),
      ...(now !== undefined && { now }),
    };
    validateOptions(copy);
    this.#options = copy;
    this.#log = DecisionLog.for(copy.logPath);
  }

  /**
   * Checks the policy, the key and the target contract, then signs and sends. Throws RefusedError on a policy breach, a bad key,
   * `block`, a `warn` that is not approved, any failure before the decision to sign was logged (nothing signed), or a
   * signed transaction that differs from the checked request (`not_sent`; on a retry, an earlier attempt may have gone). A request with an invalid contract id, method name, amount or arguments throws
   * TypeError before anything is checked or logged. Every call that gets past that ends in a terminal log line
   * (`refused`, `sent` or `not_sent`) about its last attempt, one `sent` line per attempt handed to the node; the `approved` line is written before anything is signed, and if the log
   * cannot be written, nothing is signed. The deposit stays committed only once the signed transaction is about to
   * be handed to the network (logged `sent`).
   */
  async guardedCall(input: CallRequest): Promise<GuardedCallResult> {
    const request = snapshot(input);
    const { policy, guard: config } = this.#options;
    let reserved = false;
    let approvedLogged = false;
    let handedOff = false;
    let decision: Decision = "block";
    let codeHash: string | null = null;
    let reasons: string[] = [];
    try {
      const violation = policyViolation(policy, request.contractId, request.deposit, this.#committed);
      if (violation !== null) throw new Refusal("block", [violation], null);
      this.#committed += request.deposit;
      reserved = true;

      const signer = typeof this.#options.signer === "function" ? this.#options.signer(request.contractId) : this.#options.signer;
      const { publicKey, problem } = await keyProblem(this.#options, signer, request);
      if (problem !== null) throw new Refusal("block", [problem], null);

      const inspected = await inspectContract(request.contractId, config);
      ({ decision, codeHash } = inspected);
      reasons = inspected.reasons;
      if (decision === "block") throw new Refusal("block", reasons, codeHash);
      if (codeHash === null) {
        // inspectContract allows code-less accounts (SPEC), but guardedCall only makes function calls: against an
        // account with no code that can only fail, or run code deployed after this check.
        throw new Refusal("block", [`${request.contractId} has no contract code; a function call to it can only fail or reach code deployed after this check`, ...reasons], null);
      }
      // The approver and the caller see the printable copy; the log gets the raw reasons and escapes them itself.
      const result = sanitizedResult(inspected);
      if (decision === "warn") {
        const answer = await this.#ask(request, result);
        reasons = [...reasons, answer.reason];
        if (!answer.approved) throw new Refusal("warn", reasons, codeHash);
      }

      await this.#record(request, decision, "approved", reasons, codeHash);
      approvedLogged = true;
      const account = new ReportingAccount(this.#options.accountId, new JsonRpcProvider({ url: config.rpcUrl }), signer, async (signed) => {
        const mismatch = signedMismatch(signed, this.#options.accountId, publicKey, request);
        // A refusal, not a plain Error, whether this is the first attempt or a retry after one that was already sent.
        if (mismatch !== null) throw new Refusal(decision, [...reasons, `not sent${handedOff ? " (a retry after an attempt that was sent)" : ""}: ${mismatch}`], codeHash);
        await this.#record(request, decision, "sent", reasons, codeHash);
        handedOff = true;
      });
      const transaction = await account.callFunctionRaw({
        contractId: request.contractId,
        methodName: request.method,
        args: Uint8Array.from(request.argsBytes),
        deposit: request.deposit,
        gas: request.gas,
      });
      if (!handedOff) {
        // Defensive: the hook above is the only path to a send, but a transaction that went out must keep its budget share and be in the log.
        handedOff = true;
        await this.#record(request, decision, "sent", [...reasons, "recorded after the send: the hand-off hook did not run"], codeHash).catch(() => undefined);
      }
      return { guard: result, transaction };
    } catch (error) {
      if (!approvedLogged) {
        const refusal = isRefusal(error) ? error : new Refusal(decision, [`the guard failed before signing: ${describeError(error)}`], codeHash);
        throw await this.#refusalError(request, refusal);
      }
      if (isRefusal(error)) {
        // The hand-off hook refused this attempt. Its line is `not_sent`: it tells the truth about the last attempt,
        // after an earlier attempt's `sent` line as well. The deposit share stays committed if an attempt was sent.
        throw await this.#refusalError(request, error, "not_sent");
      }
      if (!handedOff) {
        // Best effort: the original error is what the caller needs, and the log already shows "approved" without "sent".
        await this.#record(request, decision, "not_sent", [...reasons, `not sent: ${describeError(error)}`], codeHash).catch(() => undefined);
      }
      throw error;
    } finally {
      // A call whose transaction never reached the hand-off commits no money. One that did keeps its share.
      if (reserved && !handedOff) this.#committed -= request.deposit;
    }
  }

  async #ask(request: Snapshot, result: GuardResult): Promise<{ approved: boolean; reason: string }> {
    const { approve, approveTimeoutMs = DEFAULT_APPROVE_TIMEOUT_MS } = this.#options;
    if (approve === undefined) return { approved: false, reason: "warn needs a human decision and no approval callback was supplied" };
    let timer: NodeJS.Timeout | undefined;
    try {
      const shown: ApprovalRequest = Object.freeze({
        contractId: request.contractId,
        method: request.method,
        deposit: request.deposit,
        gas: request.gas,
        args: parseJson(request.argsBytes),
        argsBytes: Uint8Array.from(request.argsBytes),
      });
      const timeout = new Promise<typeof TIMED_OUT>((resolve) => {
        timer = setTimeout(() => resolve(TIMED_OUT), approveTimeoutMs);
      });
      // Whatever the callback returns, typed or not: only the boolean `true` signs.
      const answer: unknown = await Promise.race([approve(shown, deepFreeze(structuredClone(result))), timeout]);
      if (answer === TIMED_OUT) return { approved: false, reason: `approval callback gave no answer within ${approveTimeoutMs} ms; treated as declined` };
      if (answer === true) return { approved: true, reason: "approved by the approval callback" };
      if (answer === false) return { approved: false, reason: "not approved by the approval callback" };
      return { approved: false, reason: `approval callback returned ${typeof answer}, not true; treated as declined` };
    } catch (error) {
      return { approved: false, reason: `approval callback failed: ${describeError(error)}` };
    } finally {
      clearTimeout(timer);
    }
  }

  /** Writes one line. The draft is sanitized by the log, which is the only thing that turns text into a line. */
  async #record(request: Snapshot, decision: Decision, outcome: LogEntry["outcome"], reasons: string[], codeHash: string | null): Promise<LogEntry> {
    const entry = this.#log.entry(this.#draft(request, decision, outcome, reasons, codeHash));
    await this.#log.write(entry);
    return entry;
  }

  #draft(request: Snapshot, decision: Decision, outcome: LogEntry["outcome"], reasons: string[], codeHash: string | null): LogEntry {
    return {
      timestamp: timestampOf(this.#options.now),
      contract: request.contractId,
      method: request.method,
      deposit: request.deposit.toString(),
      codeHash,
      decision,
      outcome,
      reasons,
    };
  }

  /**
   * The terminal line of a refused call, and the error that carries it. It cannot throw: a failing disk, or an entry that
   * cannot be built, still ends in a RefusedError, whose entry then says so and is made from validated fields only.
   */
  async #refusalError(request: Snapshot, refusal: Refusal, outcome: "refused" | "not_sent" = "refused"): Promise<RefusedError> {
    let entry: LogEntry;
    try {
      const draft = this.#draft(request, refusal.decision, outcome, refusal.reasons, refusal.codeHash);
      entry = this.#log.entry(draft);
      try {
        await this.#log.write(entry);
      } catch (error) {
        entry = this.#log.entry({ ...draft, reasons: [`this decision could not be logged: ${describeError(error)}`, ...refusal.reasons] });
      }
    } catch (error) {
      entry = {
        timestamp: new Date().toISOString(),
        contract: request.contractId,
        method: request.method,
        deposit: request.deposit.toString(),
        codeHash: null,
        decision: "block",
        outcome,
        reasons: [printable(`this decision could not be logged: ${describeError(error)}`)],
      };
      await this.#log.write(entry).catch(() => undefined);
    }
    return new RefusedError(entry);
  }
}
