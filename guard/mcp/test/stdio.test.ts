// The real processes: main.ts as a host starts it, and check.ts, the script a judge runs.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { makeTempDir } from "../../testkit/tempdir.ts";
import { AUDITED, REGISTRY, UNAUDITED, UNSAFE, demoChain, writeOperator } from "./harness.ts";
import type { FakeNear } from "../../testkit/fake-rpc.ts";

const run = promisify(execFile);
const NODE = ["--disable-warning=ExperimentalWarning"];
const MAIN = join(import.meta.dirname, "..", "main.ts");
const CHECK = join(import.meta.dirname, "..", "check.ts");

let chain: FakeNear;
let rpc: string;
let dir: string;
beforeEach(async () => {
  chain = demoChain(REGISTRY);
  rpc = await chain.start();
  dir = await makeTempDir("mcp-stdio");
});
afterEach(async () => {
  await chain.stop();
  await rm(dir, { recursive: true, force: true });
});

/** Starts main.ts the way a host does, with exactly this environment, and returns the client and the line the server writes to stderr when it is ready. */
async function connect(env: Record<string, string>, client = new Client({ name: "stdio-test", version: "1.0.0" })) {
  const transport = new StdioClientTransport({ command: process.execPath, args: [...NODE, MAIN], env, stderr: "pipe" });
  const banner = new Promise<string>((resolve) => transport.stderr?.once("data", (chunk: Buffer) => resolve(chunk.toString())));
  await client.connect(transport);
  return { client, banner };
}

describe("main.ts over stdio", () => {
  it("serves the read-only check to a client that opens with initialize, and to one that opens with server/discover", async () => {
    for (const [mode, era] of [["legacy", "legacy"], ["auto", "modern"]] as const) {
      const { client, banner } = await connect({ PREFLIGHT_TESTNET_RPC: rpc }, new Client({ name: "stdio-test", version: "1.0.0" }, { versionNegotiation: { mode } }));
      try {
        assert.equal(client.getProtocolEra(), era);
        assert.deepEqual((await client.listTools()).tools.map((tool) => tool.name), ["preflight_check_contract"]);
        const result = await client.callTool({ name: "preflight_check_contract", arguments: { account_id: AUDITED } });
        assert.equal((result.structuredContent as { decision: string }).decision, "allow");
        assert.match(await banner, /read-only, preflight_check_contract only/);
      } finally {
        await client.close();
      }
    }
  });

  it("offers all three tools when started with a key directory and a policy, and says so on stderr", async () => {
    const { env } = await writeOperator(dir);
    const { client, banner } = await connect({ PREFLIGHT_TESTNET_RPC: rpc, ...env } as Record<string, string>);
    try {
      assert.equal((await client.listTools()).tools.length, 3);
      assert.match(await banner, /guarded calls enabled for 3 contract\(s\) on testnet/);
    } finally {
      await client.close();
    }
  });

  it("exits with a plain message and no stack when half configured", async () => {
    const error = await run(process.execPath, [...NODE, MAIN], { env: { PREFLIGHT_MCP_KEYS: dir } }).then(() => undefined, (e: { code: number; stderr: string }) => e);
    assert.equal(error?.code, 1);
    assert.match(error?.stderr ?? "", /^preflight-mcp: set both PREFLIGHT_MCP_KEYS/);
    assert.doesNotMatch(error?.stderr ?? "", /\n\s+at /);
  });
});

describe("mcp-check", () => {
  const check = (env: Record<string, string>) => run(process.execPath, [...NODE, CHECK], { env });

  it("prints the three decisions and passes when the chain is the deployment's", async () => {
    const { stdout } = await check({ PREFLIGHT_TESTNET_RPC: rpc });
    assert.match(stdout, /Tools offered: preflight_check_contract\n/);
    for (const account of [AUDITED, UNSAFE, UNAUDITED]) assert.match(stdout, new RegExp(`${account.replaceAll(".", "\\.")} \\(\\w+\\)\\n  decision:  (allow|block|warn)`));
    assert.match(stdout, /decision:  allow[\s\S]*decision:  block[\s\S]*decision:  warn/);
    assert.match(stdout, /Self-check passed/);
  });

  it("fails, with exit status 1, when a decision is not the one promised", async () => {
    chain.verdicts.clear();
    const error = await check({ PREFLIGHT_TESTNET_RPC: rpc }).then(() => undefined, (e: { code: number; stdout: string }) => e);
    assert.equal(error?.code, 1);
    assert.match(error?.stdout ?? "", /Self-check FAILED/);
  });
});
