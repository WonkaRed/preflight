// Every shape that crosses the MCP boundary, in both directions. The SDK validates a tool call against these before a
// handler runs and its result before it leaves, so the handlers only ever see input that already has the right shape.
import * as z from "zod/v4";
import { isValidAccountId, isValidMethodName, MAX_DEPOSIT, MAX_METHOD_NAME_LENGTH } from "../src/validate.ts";

export const NETWORKS = ["testnet", "mainnet"] as const;
export type Network = (typeof NETWORKS)[number];

/** The most bytes of JSON arguments one guarded call may carry: far above any escrow call, far below the 4 MiB transport cap. */
export const MAX_ARGS_BYTES = 16 * 1024;
/** The most entries one decision log read returns. */
export const MAX_LOG_ENTRIES = 100;

export const accountId = z.string().refine(isValidAccountId, "not a valid NEAR account id (2 to 64 lowercase letters, digits and single . - _ separators)");
export const testnetAccountId = accountId.refine((id) => id.endsWith(".testnet"), "not a testnet account (must end in .testnet)");

export const methodName = z.string().refine(isValidMethodName, `not a valid method name (letters, digits and underscores, not starting with a digit, at most ${MAX_METHOD_NAME_LENGTH})`);

/** yoctoNEAR as a canonical decimal string: no sign, no point, no leading zeros, and it fits the 128 bits a deposit has on the wire. */
const isYoctoNear = (text: string): boolean => /^(0|[1-9]\d{0,38})$/.test(text) && BigInt(text) <= MAX_DEPOSIT;
export const yoctoNear = z.string().refine(isYoctoNear, "not a decimal string of yoctoNEAR (digits only, no sign, point or leading zeros, at most 2^128 - 1)");

export const callArgs = z.record(z.string(), z.unknown()).refine((args) => Buffer.byteLength(JSON.stringify(args)) <= MAX_ARGS_BYTES, `arguments larger than ${MAX_ARGS_BYTES} bytes of JSON`);

export const checkInput = z.strictObject({
  account_id: accountId.describe("NEAR account whose deployed contract code to check, for example shop-patched.preflight-guard.testnet"),
  network: z.enum(NETWORKS).default("testnet").describe("Which chain to read. Defaults to testnet. The registry asked is the operator's, never yours to choose."),
});

export const checkOutput = z.object({
  decision: z.enum(["allow", "warn", "block"]),
  account_id: z.string(),
  network: z.enum(NETWORKS),
  registry_id: z.string(),
  /** Base58 SHA-256 of the code deployed at the account right now; null when the account has no contract or the code could not be read. */
  code_hash: z.string().nullable(),
  /** The registry's verdict on that code hash; null when it has none (unaudited, or changed since its audit). */
  verdict: z.object({ status: z.enum(["Safe", "Warn", "Unsafe"]), auditor: z.string(), report_url: z.string(), published_at_ms: z.string() }).nullable(),
  rule_ids: z.array(z.string()),
  reasons: z.array(z.string()),
});

export const callInput = z.strictObject({
  contract_id: accountId.describe("The contract to call. It must be on the operator's allow list."),
  method: methodName.describe("The contract method to call."),
  args: callArgs.optional().describe("JSON object passed to the method as its arguments. Defaults to {}."),
  deposit: yoctoNear.default("0").describe("Deposit to attach, in yoctoNEAR as a decimal string. Defaults to 0; the operator's policy caps it."),
});

export const logInput = z.strictObject({
  limit: z.number().int().min(1).max(MAX_LOG_ENTRIES).default(20).describe(`How many of the most recent decisions to return, newest last (1 to ${MAX_LOG_ENTRIES}).`),
});

/** One line of the guard's decision log (src/log.ts `LogEntry`). */
export const logEntry = z.object({
  timestamp: z.string(),
  contract: z.string(),
  method: z.string(),
  deposit: z.string(),
  codeHash: z.string().nullable(),
  decision: z.enum(["allow", "warn", "block"]),
  outcome: z.enum(["approved", "sent", "not_sent", "refused"]),
  reasons: z.array(z.string()),
});

export const logOutput = z.object({ entries: z.array(logEntry) });

export type CheckOutput = z.infer<typeof checkOutput>;
