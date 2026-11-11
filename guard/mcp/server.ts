// The MCP face of the guard: three tools over the guard's own code (`checkContract`, `GuardedAgent`, the decision log).
// No policy logic lives here: the shapes are checked by the schemas, every decision is the guard's.
import { McpServer, type CallToolResult } from "@modelcontextprotocol/server";
import { assertTestnetChain } from "../demo/testnet-deployment.ts";
import { checkContract, RefusedError } from "../src/index.ts";
import { describeError, printable } from "../src/text.ts";
import { CALL_GAS, type ServerConfig } from "./config.ts";
import { lastLines } from "./log-tail.ts";
import { checkInput, checkOutput, callInput, logEntry, logInput, logOutput, type CheckOutput } from "./schemas.ts";
import type * as z from "zod/v4";
import pkg from "../package.json" with { type: "json" };

const INSTRUCTIONS = "Preflight tells an agent whether the code deployed at a NEAR address is code an auditor checked, keyed on the hash of the code running right now. Call preflight_check_contract before sending funds to or calling a contract: allow means audited safe, warn means unaudited or changed since its audit (needs a human), block means unsafe or unverifiable (do not call). The registry that answers is the operator's: you cannot choose or change it, and a call that asks for one is refused.";

/** A tool error: the model reads the message and recovers. `message` must already be printable. */
const fail = (message: string): CallToolResult => ({ isError: true, content: [{ type: "text", text: message }] });

const reply = (structuredContent: Record<string, unknown>): CallToolResult => ({ content: [{ type: "text", text: JSON.stringify(structuredContent) }], structuredContent });

/** One log line as a typed entry, or undefined when it is not one. */
function parseEntry(line: string): z.infer<typeof logEntry> | undefined {
  try {
    const parsed = logEntry.safeParse(JSON.parse(line));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

export function createPreflightServer(config: ServerConfig): McpServer {
  const server = new McpServer({ name: "preflight", version: pkg.version }, { instructions: INSTRUCTIONS });

  // An endpoint URL can carry an API key; no message that leaves this process may repeat one.
  const endpoints = Object.values(config.rpc);
  const redact = (text: string): string => endpoints.reduce((redacted, url) => redacted.replaceAll(url, "[rpc url]"), text);
  /** Reasons are already printable (the guard escaped them): only the endpoints are taken out, so nothing is escaped twice. */
  const redactAll = (reasons: readonly string[]): string[] => reasons.map(redact);
  const plain = (error: unknown): string => printable(redact(describeError(error)));
  /** Anything a handler throws becomes a short tool error, never a stack. A RefusedError's message is already printable. */
  const describe = (error: unknown): string => (error instanceof RefusedError ? redact(error.message) : plain(error));
  const safely =
    <Args>(run: (args: Args) => Promise<CallToolResult>) =>
    async (args: Args): Promise<CallToolResult> => {
      try {
        return await run(args);
      } catch (error) {
        return fail(describe(error));
      }
    };

  server.registerTool(
    "preflight_check_contract",
    {
      title: "Check a contract against the Preflight registry",
      description: "Read-only, needs no key. Reads the contract code deployed at a NEAR account right now, hashes it, and asks the operator's Preflight registry (never one you name) what an auditor said about that exact code. Returns allow (audited safe), warn (no verdict for this code, or the auditor warned: ask a human first) or block (audited unsafe, or the code could not be verified: do not call it), with the code hash, the registry verdict and auditor, the rule ids and the reasons.",
      inputSchema: checkInput,
      outputSchema: checkOutput,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    },
    safely(async ({ account_id, network }) => {
      const registryId = network === "testnet" ? config.testnetRegistry : config.mainnetRegistry;
      if (registryId === undefined) return fail("the operator has configured no registry for mainnet, so mainnet cannot be checked");
      const { decision, codeHash, verdict, reasons } = await checkContract(account_id, { rpcUrl: config.rpc[network], registryId });
      const output: CheckOutput = {
        decision,
        account_id,
        network,
        registry_id: registryId,
        code_hash: codeHash,
        verdict: verdict && { status: verdict.status, auditor: verdict.auditor, report_url: redact(verdict.report_url), published_at_ms: verdict.published_at_ms },
        rule_ids: verdict?.rule_ids ?? [],
        reasons: redactAll(reasons),
      };
      return reply(output);
    }),
  );

  const { call } = config;
  if (call === undefined) return server;

  server.registerTool(
    "preflight_guarded_call",
    {
      title: "Call a contract through the Preflight guard (testnet)",
      description: `Sends a function call on NEAR testnet through the Preflight guard, signed with the operator's key (you never see it). The guard checks the operator's policy, the key's scope and the contract's audited code hash first, and signs only on allow; block and warn are refused and nothing is sent. Allowed contracts: ${call.allowedContracts.join(", ")}. Returns the decision and the transaction hash, or the reason it was refused.`,
      inputSchema: callInput,
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    safely(async ({ contract_id, method, args, deposit }) => {
      try {
        await assertTestnetChain(config.rpc.testnet);
      } catch (error) {
        return fail(`nothing was sent: the testnet RPC did not confirm chain_id testnet (${plain(error)})`);
      }
      const { guard, transaction } = await call.agent.guardedCall({ contractId: contract_id, method, args: args ?? {}, deposit: BigInt(deposit), gas: CALL_GAS });
      const status: unknown = transaction.status;
      const execution = typeof status === "object" && status !== null && "SuccessValue" in status ? "success" : typeof status === "object" && status !== null && "Failure" in status ? "failure" : "not final";
      const hash: unknown = transaction.transaction?.hash;
      return reply({ decision: guard.decision, contract_id, code_hash: guard.codeHash, reasons: redactAll(guard.reasons), transaction_hash: typeof hash === "string" ? hash : "unknown", execution });
    }),
  );

  server.registerTool(
    "preflight_decision_log",
    {
      title: "Read the guard's recent decisions",
      description: "Read-only. The most recent entries of the guard's decision log, oldest first: every guarded call, whether it was refused, approved or sent, with the decision, code hash and reasons. An approved entry is written before anything is signed.",
      inputSchema: logInput,
      outputSchema: logOutput,
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    safely(async ({ limit }) => {
      const entries = [];
      for (const line of await lastLines(call.logPath, limit)) {
        const entry = parseEntry(line);
        if (entry === undefined) return fail("the decision log holds a line that is not a decision entry; it was left untouched");
        entries.push({ ...entry, reasons: redactAll(entry.reasons) });
      }
      return reply({ entries });
    }),
  );

  return server;
}
