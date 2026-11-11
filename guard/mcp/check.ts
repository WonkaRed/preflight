// `npm run mcp-check`: starts the MCP server as a host would (a child process over stdio, with no key), lists its tools,
// and asks it about the three demo contracts deployed on testnet. Read-only. Exit status: 0 when the tools and the three
// decisions are what the deployment record promises, 1 when they are not or the server could not be reached.
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { DEFAULT_DEPLOYMENT, loadDeployment, shopAccount, type ShopRole } from "../demo/testnet-deployment.ts";
import { describeError, printable } from "../src/text.ts";
import type { Decision } from "../src/types.ts";
import { checkOutput } from "./schemas.ts";

const EXPECTED: ReadonlyArray<readonly [ShopRole, Decision]> = [["patched", "allow"], ["vulnerable", "block"], ["swapped", "warn"]];

/** The server's environment is the transport's safe default (no keys, no secrets from here); only an RPC override is passed on. */
const rpcOverride = process.env["PREFLIGHT_TESTNET_RPC"];
const client = new Client({ name: "preflight-mcp-check", version: "1.0.0" });

try {
  const deployment = await loadDeployment(DEFAULT_DEPLOYMENT);
  await client.connect(new StdioClientTransport({
    command: process.execPath,
    args: ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "main.ts")],
    env: rpcOverride ? { PREFLIGHT_TESTNET_RPC: rpcOverride } : {},
  }));

  const tools = (await client.listTools()).tools.map((tool) => tool.name);
  console.log(`MCP server started over stdio with no key. Tools offered: ${tools.join(", ")}`);

  let sound = tools.length === 1 && tools[0] === "preflight_check_contract";
  for (const [role, expected] of EXPECTED) {
    const accountId = shopAccount(deployment, role);
    const result = await client.callTool({ name: "preflight_check_contract", arguments: { account_id: accountId } });
    const parsed = checkOutput.safeParse(result.structuredContent);
    console.log("");
    if (result.isError || !parsed.success) {
      console.log(`${accountId} (${role}): the tool returned an error: ${JSON.stringify(result.content)}`);
      sound = false;
      continue;
    }
    const output = parsed.data;
    console.log(`${accountId} (${role})`);
    console.log(`  decision:  ${output.decision}`);
    console.log(`  code hash: ${output.code_hash}`);
    console.log(`  verdict:   ${output.verdict ? `${output.verdict.status}, auditor ${output.verdict.auditor}` : "none for this code hash"}`);
    console.log(`  rule ids:  ${output.rule_ids.length > 0 ? output.rule_ids.join(", ") : "none"}`);
    console.log(`  reason:    ${output.reasons.join("; ")}`);
    sound &&= output.decision === expected;
  }

  console.log("");
  console.log(sound ? "Self-check passed: patched allow, vulnerable block, swapped warn." : "Self-check FAILED: the tools or decisions are not what the deployment record promises (patched allow, vulnerable block, swapped warn).");
  process.exitCode = sound ? 0 : 1;
} catch (error) {
  console.error(`mcp-check failed: ${printable(describeError(error))}`);
  process.exitCode = 1;
} finally {
  await client.close();
}
