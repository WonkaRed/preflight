// The testnet scripts' shared pieces against the fake chain: the chain-id and account-id guards (and that the demo applies
// them before it reads anything else), and a send that survives HTTP 429 without ever running a transaction twice.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { promisify } from "node:util";
import { Account, KeyPair, KeyPairSigner, JsonRpcProvider, actions, baseEncode, decodeSignedTransaction, encodeTransaction, teraToGas } from "near-api-js";
import { codeHashOf } from "../src/check.ts";
import { assertTestnetChain, loadDeployment, sendSigned, type Deployment } from "../demo/testnet-deployment.ts";
import { FakeNear, LANDED, REFUSED, fakeWasm } from "../testkit/fake-rpc.ts";
import { makeTempDir } from "../testkit/tempdir.ts";

const AGENT = "agent.parent.testnet";
const FAILED = { jsonrpc: "2.0", result: { final_execution_status: "FINAL", status: { Failure: { ActionError: { index: 0, kind: { LackBalanceForState: { account_id: "agent.test.near", amount: "1" } } } } }, transaction: { hash: "x" }, transaction_outcome: {}, receipts_outcome: [] }, id: "dontcare" };
const SHOP = "shop.parent.testnet";

let fake: FakeNear;
let rpcUrl: string;
let dir: string;

beforeEach(async () => {
  fake = new FakeNear("registry.parent.testnet");
  rpcUrl = await fake.start();
  dir = await makeTempDir("testnet-test");
});
afterEach(async () => {
  await fake.stop();
  await rm(dir, { recursive: true, force: true });
});

const record = (accounts: Record<string, string>, parent = "parent.testnet"): Deployment => ({
  network: "testnet",
  deployedAt: "2026-11-11T00:00:00Z",
  parent,
  accounts,
  codeHashes: {},
  agentKeys: { vulnerable: "k1", patched: "k2", swapped: "k3" },
  orders: { patched: [1], vulnerable: [1] },
  transactions: [],
});
const roles = (suffix: string): Record<string, string> => Object.fromEntries(["registry", "auditor", "vulnerable", "patched", "swapped", "agent", "payee"].map((role) => [role, `${role}.parent${suffix}`]));

describe("the testnet-only guards", () => {
  it("accepts a node that reports chain_id testnet", async () => {
    await assertTestnetChain(rpcUrl);
  });

  it("refuses a node that reports any other chain, or no chain at all", async () => {
    fake.chainId = "mainnet";
    await assert.rejects(assertTestnetChain(rpcUrl), /reports chain_id "mainnet", not "testnet"/);
    fake.faults.set("status", { kind: "body", text: "not json" });
    await assert.rejects(assertTestnetChain(rpcUrl), /reports chain_id undefined/);
  });

  it("loads a record whose accounts all end in .testnet and refuses one that has an account that does not", async () => {
    const good = join(dir, "good.json");
    await writeFile(good, JSON.stringify(record(roles(".testnet"))));
    assert.equal((await loadDeployment(good)).parent, "parent.testnet");
    const bad = join(dir, "bad.json");
    await writeFile(bad, JSON.stringify(record({ ...roles(".testnet"), agent: "agent.parent.near" })));
    await assert.rejects(loadDeployment(bad), /not a testnet deployment record/);
  });

  describe("the demo script", () => {
    const demo = (...args: string[]) => promisify(execFile)(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "..", "demo", "testnet-demo.ts"), ...args], { env: { ...process.env, PREFLIGHT_AGENT_KEYS: dir } });
    const refusal = (promise: Promise<unknown>) => promise.then(() => undefined, (error: { code?: number; stderr?: string }) => error);

    it("refuses an RPC that is not testnet before it reads anything else from it", async () => {
      const path = join(dir, "deployment.json");
      await writeFile(path, JSON.stringify(record(roles(".testnet"))));
      fake.chainId = "mainnet";
      const failure = await refusal(demo("--rpc", rpcUrl, "--deployment", path));
      assert.equal(failure?.code, 3);
      assert.match(failure?.stderr ?? "", /not "testnet"/);
      assert.deepEqual(fake.queries, []);
    });

    it("refuses a deployment record with an account outside .testnet", async () => {
      const path = join(dir, "deployment.json");
      await writeFile(path, JSON.stringify(record(roles(".near"), "parent.near")));
      const failure = await refusal(demo("--rpc", rpcUrl, "--deployment", path));
      assert.equal(failure?.code, 3);
      assert.match(failure?.stderr ?? "", /not a testnet deployment record/);
      assert.deepEqual(fake.queries, []);
    });
  });
});

describe("the deploy script", () => {
  const deploy = (...args: string[]) => promisify(execFile)(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "..", "scripts", "testnet-deploy.ts"), ...args], { env: { ...process.env, PREFLIGHT_TESTNET_KEYS: dir } });

  it("stops on an existing --out that is not a testnet record, and leaves the file as it was", async () => {
    const out = join(dir, "deployment.json");
    const notMine = JSON.stringify({ ...record(roles(".testnet")), network: "mainnet" });
    await writeFile(out, notMine);
    const failure = await deploy("--parent", "parent.testnet", "--wasm-dir", dir, "--rpc", rpcUrl, "--out", out).then(() => undefined, (error: { code?: number; stderr?: string }) => error);
    assert.equal(failure?.code, 1);
    assert.match(failure?.stderr ?? "", /not a testnet deployment record/);
    assert.equal(await readFile(out, "utf8"), notMine);
    assert.deepEqual(fake.queries, []);
  });
});

describe("sendSigned", () => {
  let signer: Account;
  const call = [actions.functionCall("release", { id: 1 }, teraToGas("30"), 0n)];
  const hashOfReceived = (index: number): string => {
    const { transaction } = decodeSignedTransaction(Buffer.from(fake.receivedTransactions[index] ?? "", "base64"));
    return baseEncode(createHash("sha256").update(encodeTransaction(transaction)).digest());
  };

  beforeEach(() => {
    const key = KeyPair.fromRandom("ed25519");
    fake.addKey(AGENT, key.getPublicKey().toString(), "FullAccess");
    signer = new Account(AGENT, new JsonRpcProvider({ url: rpcUrl }), new KeyPairSigner(key));
  });

  it("answers HTTP 429 with the same signed transaction after each wait, and it lands once", async () => {
    fake.faults.set("send_tx", { kind: "http", status: 429, times: 2 });
    const waits: number[] = [];
    const hash = await sendSigned(signer, SHOP, call, [5, 5, 5], (wait) => waits.push(wait));
    assert.deepEqual(waits, [5, 5]);
    assert.equal(fake.receivedTransactions.length, 1, "the throttled sends were never applied, the third was, once");
    assert.equal(hash, hashOfReceived(0));
  });

  it("does not run a step twice when the node applied the transaction and then answered 429", async () => {
    fake.lateRateLimits = 1;
    const hash = await sendSigned(signer, SHOP, call, [5, 5], () => undefined);
    assert.equal(fake.receivedTransactions.length, 1, "the resend was refused as the same transaction, not applied again");
    assert.equal(fake.sent.length, 1);
    assert.equal(hash, hashOfReceived(0));
  });

  it("throws for a transaction the node reports as failed, instead of recording it as done", async () => {
    fake.faults.set("send_tx", { kind: "json", body: FAILED });
    await assert.rejects(sendSigned(signer, SHOP, call, [5], () => undefined), /^Error: transaction [1-9A-HJ-NP-Za-km-z]{43,44} did not succeed: .*LackBalanceForState/);
  });

  it("throws for a status that is neither success nor failure", async () => {
    fake.faults.set("send_tx", { kind: "json", body: { jsonrpc: "2.0", result: { final_execution_status: "INCLUDED", status: "NotStarted" }, id: "dontcare" } });
    await assert.rejects(sendSigned(signer, SHOP, call, [5], () => undefined), /did not succeed.*NotStarted/);
  });

  it("does not call a step done after a 429 unless the transaction's own status says success", async () => {
    fake.lateRateLimits = 1;
    fake.faults.set("tx", { kind: "json", body: FAILED });
    await assert.rejects(sendSigned(signer, SHOP, call, [5], () => undefined));
  });

  it("throws without asking for the status when the node refuses the transaction (here: not enough allowance)", async () => {
    fake.faults.set("send_tx", { kind: "json", body: REFUSED });
    fake.faults.set("tx", { kind: "json", body: LANDED });
    await assert.rejects(sendSigned(signer, SHOP, call, [5], () => undefined), (error: Error) => {
      assert.match(error.message, /^the node refused transaction [1-9A-HJ-NP-Za-km-z]{43,44}: it was not included in a block, so the hash does not resolve: Not enough allowance/);
      assert.ok(error.cause instanceof Error, "the node's error is kept as the cause");
      return true;
    });
  });

  it("throws when the node is still throttling after the last wait, and the transaction never landed", async () => {
    fake.faults.set("send_tx", { kind: "http", status: 429 });
    await assert.rejects(sendSigned(signer, SHOP, call, [5], () => undefined), (error: Error) => {
      assert.match(error.message, /^transaction [1-9A-HJ-NP-Za-km-z]{43,44} was sent, but .* may or may not have landed/);
      assert.ok(error.cause instanceof Error, "the node's error is kept as the cause");
      return true;
    });
    assert.equal(fake.receivedTransactions.length, 0);
  });
});

describe("the verify script", () => {
  const verify = (...args: string[]) => promisify(execFile)(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "..", "scripts", "testnet-verify.ts"), ...args]);
  const outcome = (promise: Promise<{ stdout: string }>) => promise.then((done) => ({ code: 0, stdout: done.stdout }), (error: { code?: number; stdout?: string }) => ({ code: error.code, stdout: error.stdout ?? "" }));

  // A whole deployment on the fake chain: registry, three shops, one verdict each for the first two and one for the swapped shop's audited build.
  // `setupKeyDeleted` is whether the record carries the delete step (the recorded deployment does; a fresh `testnet-deploy` does not).
  async function deployed(setupKeyDeleted = true): Promise<{ path: string; reports: string }> {
    const reports = join(dir, "reports");
    await mkdir(reports);
    const accounts = roles(".testnet");
    fake.auditors = [accounts["auditor"] ?? ""];
    const codeHashes: Record<string, string> = {};
    fake.accounts.set(accounts["registry"] ?? "", { wasm: fakeWasm("registry") });
    for (const [role, label] of [["vulnerable", "vulnerable"], ["patched", "patched"], ["swapped", "other"]] as const) fake.accounts.set(accounts[role] ?? "", { wasm: fakeWasm(label) });
    for (const [role, key] of [["vulnerable", "k1"], ["patched", "k2"], ["swapped", "k3"]] as const) fake.addKey(accounts["agent"] ?? "", key, { FunctionCall: { allowance: "1", receiver_id: accounts[role] ?? "", method_names: ["release"] } });
    const audited = fake.publish(accounts["patched"] ?? "", "Safe");
    fake.publish(accounts["vulnerable"] ?? "", "Unsafe", ["PF001"]);
    for (const [role, verdict] of [["vulnerable", fake.verdicts.get(codeHashOf(fakeWasm("vulnerable")))], ["patched", fake.verdicts.get(audited)]] as const) {
      const bytes = `{"report":"${role}"}\n`;
      await writeFile(join(reports, `shop-${role}.json`), bytes);
      if (verdict !== undefined) verdict.report_sha256 = createHash("sha256").update(bytes).digest("hex");
    }
    for (const role of ["registry", "vulnerable", "patched", "swapped"]) codeHashes[role] = codeHashOf(fake.accounts.get(accounts[role] ?? "")?.wasm ?? new Uint8Array());
    codeHashes["swappedAudited"] = audited;
    const path = join(dir, "deployment.json");
    const transactions = setupKeyDeleted ? [{ step: "delete-agent-full-access-key", signer: accounts["agent"] ?? "", receiver: accounts["agent"] ?? "", hash: "h", what: "delete the setup key" }] : [];
    await writeFile(path, JSON.stringify({ ...record(accounts), codeHashes, transactions }));
    return { path, reports };
  }

  it("passes when the chain, the registry and the committed report files agree", async () => {
    const { path, reports } = await deployed();
    const result = await outcome(verify("--rpc", rpcUrl, "--deployment", path, "--reports", reports));
    assert.equal(result.code, 0, result.stdout);
    assert.match(result.stdout, /OK {2}the verdict's report_sha256 .* is the SHA-256 of .*shop-vulnerable\.json/);
    assert.match(result.stdout, /^OK {2}vulnerable\.parent\.testnet: expected block, got block \(registry verdict Unsafe/m);
    assert.match(result.stdout, /^OK {2}patched\.parent\.testnet: expected allow, got allow \(registry verdict Safe/m);
    assert.match(result.stdout, /^OK {2}swapped\.parent\.testnet: expected warn, got warn \(code hash \S+ has no verdict/m);
    assert.match(result.stdout, /^OK {2}registry verdict for the code now on swapped\.parent\.testnet \(\S+\): expected no verdict, got no verdict/m);
    assert.doesNotMatch(result.stdout, /PASS/);
    assert.match(result.stdout, /^OK {2}the agent agent\.parent\.testnet: expected no full-access key, got no full-access key \(it holds 3 access keys\)/m);
    assert.match(result.stdout, /^OK {2}the agent's access keys are exactly the 3 recorded function-call keys, each limited to release on one shop/m);
  });

  it("fails when the agent account holds a full-access key", async () => {
    const { path, reports } = await deployed();
    fake.addKey("agent.parent.testnet", "kfull", "FullAccess");
    const result = await outcome(verify("--rpc", rpcUrl, "--deployment", path, "--reports", reports));
    assert.equal(result.code, 1);
    assert.match(result.stdout, /^FAIL {2}the agent agent\.parent\.testnet: expected no full-access key, got 1 full-access key\(s\) \(it holds 4 access keys\)/m);
    assert.match(result.stdout, /^FAIL {2}the agent's access keys are exactly/m);
  });

  it("on a fresh deployment, whose record has no delete step, expects the agent's setup key, says so in a non-failing line and still checks the three keys", async () => {
    const { path, reports } = await deployed(false);
    fake.addKey("agent.parent.testnet", "ksetup", "FullAccess");
    const result = await outcome(verify("--rpc", rpcUrl, "--deployment", path, "--reports", reports));
    assert.equal(result.code, 0, result.stdout);
    assert.match(result.stdout, /^NOTE {2}the agent agent\.parent\.testnet holds 1 full-access key\(s\): this record has no delete-agent-full-access-key step/m);
    assert.match(result.stdout, /^OK {2}the agent's function-call keys are exactly the 3 recorded function-call keys, each limited to release on one shop/m);
    assert.doesNotMatch(result.stdout, /FAIL/);
  });

  it("on a fresh deployment, still passes when the setup key is already gone", async () => {
    const { path, reports } = await deployed(false);
    const result = await outcome(verify("--rpc", rpcUrl, "--deployment", path, "--reports", reports));
    assert.equal(result.code, 0, result.stdout);
    assert.match(result.stdout, /^NOTE {2}the agent agent\.parent\.testnet holds 0 full-access key\(s\)/m);
  });

  it("on a fresh deployment, fails on a second full-access key", async () => {
    const { path, reports } = await deployed(false);
    fake.addKey("agent.parent.testnet", "ksetup", "FullAccess");
    fake.addKey("agent.parent.testnet", "kextra", "FullAccess");
    const result = await outcome(verify("--rpc", rpcUrl, "--deployment", path, "--reports", reports));
    assert.equal(result.code, 1);
    assert.match(result.stdout, /^FAIL {2}the agent agent\.parent\.testnet: expected at most 1 full-access key \(its setup key\), got 2/m);
  });

  it("on a fresh deployment, fails on a widened function-call key even beside the setup key", async () => {
    const { path, reports } = await deployed(false);
    fake.addKey("agent.parent.testnet", "ksetup", "FullAccess");
    fake.addKey("agent.parent.testnet", "k2", { FunctionCall: { allowance: "1", receiver_id: "patched.parent.testnet", method_names: [] } });
    const result = await outcome(verify("--rpc", rpcUrl, "--deployment", path, "--reports", reports));
    assert.equal(result.code, 1);
    assert.match(result.stdout, /^FAIL {2}the agent's function-call keys are exactly/m);
  });

  it("fails when a recorded function-call key has been widened to every method", async () => {
    const { path, reports } = await deployed();
    fake.addKey("agent.parent.testnet", "k2", { FunctionCall: { allowance: "1", receiver_id: "patched.parent.testnet", method_names: [] } });
    const result = await outcome(verify("--rpc", rpcUrl, "--deployment", path, "--reports", reports));
    assert.equal(result.code, 1);
    assert.match(result.stdout, /^FAIL {2}the agent's access keys are exactly/m);
  });

  it("fails when a report file is not the one whose SHA-256 the registry holds", async () => {
    const { path, reports } = await deployed();
    await writeFile(join(reports, "shop-vulnerable.json"), "edited after publishing\n");
    const result = await outcome(verify("--rpc", rpcUrl, "--deployment", path, "--reports", reports));
    assert.equal(result.code, 1);
    assert.match(result.stdout, /FAIL {2}the verdict's report_sha256 .* is NOT the SHA-256 of .*shop-vulnerable\.json/);
  });
});
