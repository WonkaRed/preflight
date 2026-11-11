// A chain of fake testnet accounts, an MCP server over it and a client wired to it in memory. The server is configured
// the way main.ts configures it (`loadServerConfig` on an environment), so the tests cover the operator's path too.
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { KeyPair } from "near-api-js";
import { codeHashOf } from "../../src/check.ts";
import { FakeNear, fakeWasm } from "../../testkit/fake-rpc.ts";
import { makeTempDir } from "../../testkit/tempdir.ts";
import { loadServerConfig } from "../config.ts";
import { createPreflightServer } from "../server.ts";

/** The registry the deployment record names: `loadServerConfig` reads it from there. */
export const REGISTRY = "registry.preflight-guard.testnet";
export const AGENT = "agent.preflight-guard.testnet";
export const AUDITED = "shop-patched.preflight-guard.testnet";
export const UNSAFE = "shop-vulnerable.preflight-guard.testnet";
export const UNAUDITED = "shop-swapped.preflight-guard.testnet";
export const ALLOWED = [AUDITED, UNSAFE, UNAUDITED];

export interface Reply {
  isError: boolean;
  text: string;
  data: Record<string, unknown> | undefined;
}

export interface Harness {
  client: Client;
  testnet: FakeNear;
  mainnet: FakeNear;
  /** The testnet endpoint the server was configured with: text that must never leave it. */
  testnetUrl: string;
  /** Where the operator's files live: `policy.json`, `keys/`. */
  dir: string;
  /** The secret keys the operator holds, as written in the key files. */
  secrets: string[];
  /** Everything the client ever received, as JSON text. */
  transcript: string[];
  call(name: string, args: Record<string, unknown>): Promise<Reply>;
  close(): Promise<void>;
}

export interface Options {
  /** Give the server a key directory and a policy file. */
  keys?: boolean;
  /** Fields of the policy file, over the defaults. */
  policy?: Record<string, unknown>;
  /** The operator's mainnet registry (PREFLIGHT_MAINNET_REGISTRY); none by default. */
  mainnetRegistry?: string;
}

/** The operator's side: one key file per allowed contract and a policy file in `dir`; returns the environment that names them and the keys. */
export async function writeOperator(dir: string, policy: Record<string, unknown> = {}): Promise<{ env: NodeJS.ProcessEnv; keys: Map<string, KeyPair> }> {
  await mkdir(join(dir, "keys"), { recursive: true });
  const keys = new Map<string, KeyPair>();
  for (const id of ALLOWED) {
    const key = KeyPair.fromRandom("ed25519");
    keys.set(id, key);
    await writeFile(join(dir, "keys", `${id}.key`), `${key.toString()}\n`);
  }
  await writeFile(join(dir, "policy.json"), JSON.stringify({ accountId: AGENT, allowedContracts: ALLOWED, maxDepositPerCall: "0", maxTotalDeposit: "0", ...policy }));
  return { env: { PREFLIGHT_MCP_KEYS: join(dir, "keys"), PREFLIGHT_MCP_POLICY: join(dir, "policy.json") }, keys };
}

/** Makes the registry's verdict for the code at `accountId` name `reportUrl`, so a reason carries it. */
export function setReportUrl(chain: FakeNear, accountId: string, reportUrl: string): void {
  const hash = codeHashOf(fakeWasm(accountId));
  const verdict = chain.verdicts.get(hash);
  if (verdict === undefined) throw new Error(`no verdict for ${accountId}`);
  chain.verdicts.set(hash, { ...verdict, report_url: reportUrl });
}

/** A fake chain holding the three demo shops the way the testnet deployment does: one audited safe, one audited unsafe, one with no verdict. */
export function demoChain(registryId: string): FakeNear {
  const chain = new FakeNear(registryId);
  for (const id of ALLOWED) chain.accounts.set(id, { wasm: fakeWasm(id) });
  chain.publish(AUDITED, "Safe");
  chain.publish(UNSAFE, "Unsafe", ["PF001"]);
  return chain;
}

export async function startHarness({ keys = false, policy = {}, mainnetRegistry }: Options = {}): Promise<Harness> {
  const testnet = demoChain(REGISTRY);
  const mainnet = new FakeNear("registry.near");
  mainnet.chainId = "mainnet";
  const env: NodeJS.ProcessEnv = { PREFLIGHT_TESTNET_RPC: await testnet.start(), PREFLIGHT_MAINNET_RPC: await mainnet.start() };
  if (mainnetRegistry !== undefined) env["PREFLIGHT_MAINNET_REGISTRY"] = mainnetRegistry;

  const dir = await makeTempDir("mcp-test");
  const secrets: string[] = [];
  if (keys) {
    const operator = await writeOperator(dir, policy);
    Object.assign(env, operator.env);
    for (const [id, key] of operator.keys) {
      secrets.push(key.toString());
      testnet.addKey(AGENT, key.getPublicKey().toString(), { FunctionCall: { allowance: "250000000000000000000000", receiver_id: id, method_names: [] } });
    }
  }

  const server = createPreflightServer(await loadServerConfig(env));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "mcp-test", version: "1.0.0" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const transcript: string[] = [];
  return {
    client,
    testnet,
    mainnet,
    testnetUrl: env["PREFLIGHT_TESTNET_RPC"] ?? "",
    dir,
    secrets,
    transcript,
    async call(name, args) {
      const result = await client.callTool({ name, arguments: args });
      transcript.push(JSON.stringify(result));
      const first = result.content[0];
      return { isError: result.isError === true, text: first?.type === "text" ? first.text : "", data: result.structuredContent as Reply["data"] };
    },
    async close() {
      await client.close();
      await server.close();
      await testnet.stop();
      await mainnet.stop();
      await rm(dir, { recursive: true, force: true });
    },
  };
}
