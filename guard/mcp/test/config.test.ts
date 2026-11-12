import assert from "node:assert/strict";
import { chmod, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { makeTempDir } from "../../testkit/tempdir.ts";
import { loadServerConfig } from "../config.ts";
import { AGENT, ALLOWED, AUDITED, REGISTRY, writeOperator } from "./harness.ts";

let dir: string;
beforeEach(async () => {
  dir = await makeTempDir("mcp-config");
});
afterEach(() => rm(dir, { recursive: true, force: true }));

const operator = async (policy: Record<string, unknown> = {}) => (await writeOperator(dir, policy)).env;
const rejects = (env: NodeJS.ProcessEnv, message: RegExp) => assert.rejects(loadServerConfig(env), message);

describe("loadServerConfig", () => {
  it("reads nothing but the defaults when the environment is empty: read-only, public endpoints, the deployment's registry", async () => {
    const config = await loadServerConfig({});
    assert.equal(config.call, undefined);
    assert.equal(config.testnetRegistry, REGISTRY);
    assert.deepEqual(config.rpc, { testnet: "https://test.rpc.fastnear.com", mainnet: "https://free.rpc.fastnear.com" });
  });

  it("takes endpoint overrides from the environment, and only http(s) ones", async () => {
    assert.equal((await loadServerConfig({ PREFLIGHT_TESTNET_RPC: "http://127.0.0.1:1" })).rpc.testnet, "http://127.0.0.1:1");
    await rejects({ PREFLIGHT_TESTNET_RPC: "ftp://example.org" }, /PREFLIGHT_TESTNET_RPC must be an http or https URL/);
    await rejects({ PREFLIGHT_MAINNET_RPC: "not a url" }, /PREFLIGHT_MAINNET_RPC must be an http or https URL/);
  });

  it("refuses an endpoint with a user name or password in it, without repeating it", async () => {
    await assert.rejects(loadServerConfig({ PREFLIGHT_TESTNET_RPC: "https://user:hunter2@rpc.example.org" }), (error: Error) => /PREFLIGHT_TESTNET_RPC must not carry a user name or password/.test(error.message) && !/hunter2|user:/.test(error.message));
    await rejects({ PREFLIGHT_MAINNET_RPC: "https://token@rpc.example.org" }, /PREFLIGHT_MAINNET_RPC must not carry a user name or password/);
  });

  it("takes a mainnet registry only from the operator, and only a valid account id", async () => {
    assert.equal((await loadServerConfig({})).mainnetRegistry, undefined);
    assert.equal((await loadServerConfig({ PREFLIGHT_MAINNET_REGISTRY: "registry.near" })).mainnetRegistry, "registry.near");
    await rejects({ PREFLIGHT_MAINNET_REGISTRY: "Not A Registry" }, /PREFLIGHT_MAINNET_REGISTRY must be a NEAR account id/);
  });

  it("leaves the chain-fact checks off unless the operator names a mode, and takes only the modes it knows", async () => {
    assert.equal((await loadServerConfig({})).mutability, undefined);
    assert.deepEqual((await loadServerConfig({ PREFLIGHT_MCP_MUTABILITY: "keys" })).mutability, { testnet: {}, mainnet: {} });
    const pinned = (await loadServerConfig({ PREFLIGHT_MCP_MUTABILITY: "pin-block" })).mutability;
    assert.equal(pinned?.testnet.onCodeChange, "block");
    assert.notEqual(pinned?.testnet.pins, pinned?.mainnet.pins, "pins are per network");
    assert.equal((await loadServerConfig({ PREFLIGHT_MCP_MUTABILITY: "pin-warn" })).mutability?.mainnet.onCodeChange, "warn");
    await rejects({ PREFLIGHT_MCP_MUTABILITY: "everything" }, /PREFLIGHT_MCP_MUTABILITY must be keys, pin-warn or pin-block/);
    await rejects({ PREFLIGHT_MCP_MUTABILITY: "toString" }, /PREFLIGHT_MCP_MUTABILITY must be/);
  });

  it("keeps pins in a directory when the operator names one, and refuses a pin directory with no pin mode", async () => {
    const pinsDir = join(dir, "pins");
    const env = { PREFLIGHT_MCP_MUTABILITY: "pin-warn", PREFLIGHT_MCP_PINS: pinsDir };
    const first = (await loadServerConfig(env)).mutability;
    await first?.testnet.pins?.set("a.testnet", "Bvocsc7xBZmcjwLLNJbLBJpvV5SqcWKsT6fNZZGKySTj", undefined);
    first?.testnet.pins?.close();
    first?.mainnet.pins?.close();
    const second = (await loadServerConfig(env)).mutability;
    assert.equal(second?.testnet.pins?.get("a.testnet"), "Bvocsc7xBZmcjwLLNJbLBJpvV5SqcWKsT6fNZZGKySTj");
    assert.equal(second?.mainnet.pins?.get("a.testnet"), undefined);
    await rejects(env, /pin file lock .* is held by process \d+: one process per pin file/);
    second?.testnet.pins?.close();
    second?.mainnet.pins?.close();
    await rejects({ PREFLIGHT_MCP_PINS: pinsDir }, /PREFLIGHT_MCP_PINS needs PREFLIGHT_MCP_MUTABILITY/);
    await rejects({ PREFLIGHT_MCP_MUTABILITY: "keys", PREFLIGHT_MCP_PINS: pinsDir }, /PREFLIGHT_MCP_PINS needs/);
  });

  it("refuses a relative pin directory, and a variable that is set but empty, instead of reading it as off or in memory", async () => {
    await rejects({ PREFLIGHT_MCP_MUTABILITY: "pin-warn", PREFLIGHT_MCP_PINS: "pins" }, /PREFLIGHT_MCP_PINS must be an absolute path/);
    await rejects({ PREFLIGHT_MCP_MUTABILITY: "pin-warn", PREFLIGHT_MCP_PINS: "" }, /PREFLIGHT_MCP_PINS must be an absolute path/);
    await rejects({ PREFLIGHT_MCP_MUTABILITY: "" }, /PREFLIGHT_MCP_MUTABILITY must be keys, pin-warn or pin-block/);
  });

  it("enables guarded calls with a key directory and a policy, and keeps the log next to the policy by default", async () => {
    const config = await loadServerConfig(await operator());
    assert.deepEqual(config.call?.allowedContracts, ALLOWED);
    assert.equal(config.call?.logPath, join(dir, "decisions.jsonl"));
  });

  it("takes the testnet registry from the policy when it names one, and only a testnet one", async () => {
    assert.equal((await loadServerConfig(await operator({ registryId: "mine.preflight-guard.testnet" }))).testnetRegistry, "mine.preflight-guard.testnet");
    await rejects(await operator({ registryId: "registry.near" }), /registryId: not a testnet account/);
  });

  it("resolves a relative log path against the policy file, and keeps an absolute one", async () => {
    assert.equal((await loadServerConfig(await operator({ logPath: "logs/d.jsonl" }))).call?.logPath, join(dir, "logs", "d.jsonl"));
    assert.equal((await loadServerConfig(await operator({ logPath: join(dir, "elsewhere.jsonl") }))).call?.logPath, join(dir, "elsewhere.jsonl"));
  });

  it("refuses the key directory without the policy, and the policy without the key directory", async () => {
    const env = await operator();
    await rejects({ PREFLIGHT_MCP_KEYS: env["PREFLIGHT_MCP_KEYS"] }, /set both PREFLIGHT_MCP_KEYS .* and PREFLIGHT_MCP_POLICY .*, or neither/);
    await rejects({ PREFLIGHT_MCP_POLICY: env["PREFLIGHT_MCP_POLICY"] }, /set both PREFLIGHT_MCP_KEYS/);
  });

  const badPolicies: Array<[string, Record<string, unknown>, RegExp]> = [
    ["no allow list", { allowedContracts: [] }, /allowedContracts/],
    ["a mainnet agent account", { accountId: "agent.near" }, /accountId: not a testnet account/],
    ["a mainnet contract on the allow list", { allowedContracts: [AUDITED, "token.near"] }, /allowedContracts\.1: not a testnet account/],
    ["an invalid account id", { accountId: "Agent" }, /accountId: not a valid NEAR account id/],
    ["a fractional deposit cap", { maxDepositPerCall: "0.5" }, /maxDepositPerCall: not a decimal string/],
    ["a deposit cap that is a number", { maxTotalDeposit: 5 }, /maxTotalDeposit/],
    ["a field it does not know", { maxDepositPerCal: "1" }, /Unrecognized key/],
    ["an empty log path", { logPath: "" }, /logPath/],
  ];
  for (const [name, policy, message] of badPolicies) {
    it(`refuses a policy with ${name}`, async () => {
      await rejects(await operator(policy), message);
    });
  }

  it("refuses a policy that lacks a cap: there is no default allowance", async () => {
    const env = await operator();
    await writeFile(env["PREFLIGHT_MCP_POLICY"] as string, JSON.stringify({ accountId: AGENT, allowedContracts: ALLOWED, maxDepositPerCall: "0" }));
    await rejects(env, /maxTotalDeposit/);
  });

  it("refuses a policy file that is not JSON, naming the file", async () => {
    const env = await operator();
    await writeFile(env["PREFLIGHT_MCP_POLICY"] as string, "{ allowedContracts: ");
    await rejects(env, /cannot read the policy file .*policy\.json as JSON/);
  });

  it("refuses a missing key file, naming the file", async () => {
    const env = await operator();
    await rm(join(dir, "keys", `${AUDITED}.key`));
    await rejects(env, new RegExp(`cannot read the key file .*${AUDITED.replaceAll(".", "\\.")}\\.key`));
  });

  it("refuses a key file that holds no ed25519 key, without repeating what it holds", async () => {
    const env = await operator();
    await writeFile(join(dir, "keys", `${AUDITED}.key`), "this-is-not-a-key-TOPSECRET\n");
    await assert.rejects(loadServerConfig(env), (error: Error) => /does not hold an ed25519 secret key/.test(error.message) && !error.message.includes("TOPSECRET"));
    await writeFile(join(dir, "keys", `${AUDITED}.key`), "ed25519:0OIl-TOPSECRET\n");
    await assert.rejects(loadServerConfig(env), (error: Error) => /does not hold a valid ed25519 secret key/.test(error.message) && !error.message.includes("TOPSECRET"));
  });

  it("refuses an unreadable key file as a missing one", async (t) => {
    if (process.getuid?.() === 0) return t.skip("root reads any file");
    const env = await operator();
    await chmod(join(dir, "keys", `${AUDITED}.key`), 0o000);
    await rejects(env, /cannot read the key file/);
  });
});
