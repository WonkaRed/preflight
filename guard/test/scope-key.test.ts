import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, it } from "node:test";
import { KeyPair, KeyPairSigner, baseEncode, decodeSignedTransaction, encodeTransaction, nearToYocto, teraToGas } from "near-api-js";
import { addScopedKey, GuardedAgent } from "../src/index.ts";
import { FakeNear, LANDED, REFUSED, fakeWasm } from "../testkit/fake-rpc.ts";
import { makeTempDir } from "../testkit/tempdir.ts";

const REGISTRY = "registry.test.near";
const AGENT = "agent.test.near";
const TARGET = "escrow.test.near";

let fake: FakeNear;
let rpcUrl: string;
let ownerKey: KeyPair;
let dir: string;

beforeEach(async () => {
  fake = new FakeNear(REGISTRY);
  rpcUrl = await fake.start();
  dir = await makeTempDir("guard-test");
  ownerKey = KeyPair.fromRandom("ed25519");
  fake.addKey(AGENT, ownerKey.getPublicKey().toString(), "FullAccess");
});
afterEach(async () => {
  await fake.stop();
  await rm(dir, { recursive: true, force: true });
});

const scoped = (overrides: Partial<Parameters<typeof addScopedKey>[0]> = {}): Parameters<typeof addScopedKey>[0] => ({
  rpcUrl,
  accountId: AGENT,
  ownerSecretKey: ownerKey.toString() as `ed25519:${string}`,
  contractId: TARGET,
  methodNames: ["release", "refund"],
  allowance: nearToYocto("0.25"),
  ...overrides,
});

const FAILED = { jsonrpc: "2.0", result: { final_execution_status: "FINAL", status: { Failure: { ActionError: { index: 0, kind: { LackBalanceForState: { account_id: "agent.test.near", amount: "1" } } } } }, transaction: { hash: "x" }, transaction_outcome: {}, receipts_outcome: [] }, id: "dontcare" };

describe("addScopedKey", () => {
  it("adds a function-call key limited to one contract, the named methods and a gas allowance", async () => {
    const { publicKey, transactionHash } = await addScopedKey(scoped());
    assert.match(transactionHash, /^[1-9A-HJ-NP-Za-km-z]{43,44}$/);
    assert.deepEqual(fake.keys.get(`${AGENT}|${publicKey.toString()}`), {
      FunctionCall: { allowance: nearToYocto("0.25").toString(), receiver_id: TARGET, method_names: ["release", "refund"] },
    });
  });

  it("returns the hash of the transaction the node received, worked out locally", async () => {
    const { transactionHash } = await addScopedKey(scoped());
    assert.equal(fake.receivedTransactions.length, 1);
    const { transaction } = decodeSignedTransaction(Buffer.from(fake.receivedTransactions[0] ?? "", "base64"));
    assert.equal(transactionHash, baseEncode(createHash("sha256").update(encodeTransaction(transaction)).digest()));
  });

  it("still returns the new key and the hash when the node's answer carries no transaction", async () => {
    fake.faults.set("send_tx", { kind: "json", body: { jsonrpc: "2.0", result: { final_execution_status: "FINAL", status: { SuccessValue: "" } }, id: "dontcare" } });
    const { publicKey, secretKey, transactionHash } = await addScopedKey(scoped());
    assert.match(secretKey, /^ed25519:/);
    assert.match(transactionHash, /^[1-9A-HJ-NP-Za-km-z]{43,44}$/);
    assert.ok(publicKey.toString().startsWith("ed25519:"));
  });

  it("rejects when the node reports the transaction as failed (it returns the outcome instead of throwing)", async () => {
    fake.faults.set("send_tx", { kind: "json", body: FAILED });
    await assert.rejects(addScopedKey(scoped()), /^Error: transaction [1-9A-HJ-NP-Za-km-z]{43,44} did not succeed: .*LackBalanceForState/);
  });

  it("rejects when the node's status is neither success nor failure", async () => {
    fake.faults.set("send_tx", { kind: "json", body: { jsonrpc: "2.0", result: { final_execution_status: "INCLUDED", status: "NotStarted" }, id: "dontcare" } });
    await assert.rejects(addScopedKey(scoped()), /did not succeed.*NotStarted/);
  });

  it("still returns the key when the send threw but the node executed the transaction (a late 429)", async () => {
    fake.lateRateLimits = 1;
    const { publicKey, transactionHash } = await addScopedKey(scoped());
    assert.ok(fake.keys.has(`${AGENT}|${publicKey.toString()}`), "the key is on the chain");
    assert.equal(fake.receivedTransactions.length, 1);
    assert.match(transactionHash, /^[1-9A-HJ-NP-Za-km-z]{43,44}$/);
  });

  it("rejects when the send threw and the transaction is not known to the node", async () => {
    fake.faults.set("send_tx", { kind: "http", status: 429 });
    await assert.rejects(addScopedKey(scoped()), (error: Error) => {
      assert.match(error.message, /^transaction [1-9A-HJ-NP-Za-km-z]{43,44} was sent, but .* may or may not have landed/);
      assert.ok(error.cause instanceof Error, "the node's error is kept as the cause");
      return true;
    });
    assert.equal(fake.receivedTransactions.length, 0);
  });

  it("rejects without asking for the status when the node refuses the transaction (here: not enough allowance)", async () => {
    fake.faults.set("send_tx", { kind: "json", body: REFUSED });
    fake.faults.set("tx", { kind: "json", body: LANDED });
    await assert.rejects(addScopedKey(scoped()), (error: Error) => {
      assert.match(error.message, /^the node refused transaction [1-9A-HJ-NP-Za-km-z]{43,44}: it was not included in a block, so the hash does not resolve: Not enough allowance/);
      assert.ok(error.cause instanceof Error, "the node's error is kept as the cause");
      return true;
    });
  });

  it("returns a key the guarded wrapper can use for exactly that contract", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const { secretKey } = await addScopedKey(scoped());
    const agent = new GuardedAgent({
      accountId: AGENT,
      signer: KeyPairSigner.fromSecretKey(secretKey as `ed25519:${string}`),
      guard: { rpcUrl, registryId: REGISTRY },
      policy: { allowedContracts: [TARGET], maxDepositPerCall: 0n, maxTotalDeposit: 0n },
      logPath: join(dir, "log.jsonl"),
    });
    await agent.guardedCall({ contractId: TARGET, method: "release", deposit: 0n, gas: teraToGas("30") });
    assert.equal(fake.sent.length, 1);
  });

  it("refuses requests that would not be scoped", async () => {
    await assert.rejects(addScopedKey(scoped({ methodNames: [] })), /every method/);
    await assert.rejects(addScopedKey(scoped({ allowance: 0n })), /allowance/);
    await assert.rejects(addScopedKey(scoped({ contractId: "Not A Contract" })), TypeError);
    await assert.rejects(addScopedKey(scoped({ methodNames: ["release", "bad\u202ename"] })), /invalid method name: bad\\u202ename/);
    assert.equal([...fake.keys.keys()].length, 1);
  });

  it("validates the owner account with the account-id grammar, and adds no key", async () => {
    for (const accountId of ["Agent.near", "a", "agent.test.near\nforged", "agent\u202e.near", "", "a".repeat(65), 5 as unknown as string, null as unknown as string]) {
      const error = await addScopedKey(scoped({ accountId })).then(() => undefined, (e: unknown) => e);
      assert.ok(error instanceof TypeError, String(accountId));
      assert.match(error.message, /invalid account id/);
      assert.doesNotMatch(error.message, /[\u0000-\u001f\u202e]/);
    }
    assert.deepEqual(fake.queries, []);
    assert.equal([...fake.keys.keys()].length, 1);
  });
});

describe("scope-key script", () => {
  const run = (env: Record<string, string>, ...args: string[]) =>
    promisify(execFile)(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "..", "scripts", "scope-key.ts"), ...args], { env: { ...process.env, ...env } });

  it("adds the key, writes the new secret to a private file and does not print it", async () => {
    const out = join(dir, "agent.key");
    const { stdout } = await run({ NEAR_OWNER_KEY: ownerKey.toString() }, "--rpc", rpcUrl, "--account", AGENT, "--contract", TARGET, "--methods", "release,refund", "--allowance", "0.25", "--out", out);
    const secret = (await readFile(out, "utf8")).trim();
    assert.match(secret, /^ed25519:/);
    assert.equal(stdout.includes(secret), false);
    assert.match(stdout, /^transaction [1-9A-HJ-NP-Za-km-z]{43,44}$/m, "the add-key transaction hash is printed, so the key can be traced on an explorer");
    assert.equal((await stat(out)).mode & 0o777, 0o600);
    const added = [...fake.keys.entries()].find(([key]) => key.startsWith(`${AGENT}|`) && key !== `${AGENT}|${ownerKey.getPublicKey().toString()}`);
    assert.deepEqual(added?.[1], { FunctionCall: { allowance: nearToYocto("0.25").toString(), receiver_id: TARGET, method_names: ["release", "refund"] } });
  });

  it("refuses an output file that already exists before it adds any key, so no secret is lost", async () => {
    const out = join(dir, "taken.key");
    await writeFile(out, "keep me\n");
    const before = fake.keys.size;
    const failure = await run({ NEAR_OWNER_KEY: ownerKey.toString() }, "--rpc", rpcUrl, "--account", AGENT, "--contract", TARGET, "--methods", "a", "--allowance", "1", "--out", out).then(() => undefined, (error: { code?: number; stderr?: string }) => error);
    assert.equal(failure?.code, 1);
    assert.match(failure?.stderr ?? "", /already exists; nothing was added/);
    assert.equal(fake.keys.size, before);
    assert.equal(await readFile(out, "utf8"), "keep me\n");
  });

  it("writes no file and prints no success when the transaction failed", async () => {
    fake.faults.set("send_tx", { kind: "json", body: FAILED });
    const out = join(dir, "never.key");
    const failure = await run({ NEAR_OWNER_KEY: ownerKey.toString() }, "--rpc", rpcUrl, "--account", AGENT, "--contract", TARGET, "--methods", "a", "--allowance", "1", "--out", out).then(() => undefined, (error: { code?: number; stdout?: string; stderr?: string }) => error);
    assert.equal(failure?.code, 1);
    assert.match(failure?.stderr ?? "", /did not succeed/);
    assert.doesNotMatch(failure?.stdout ?? "", /added/);
    await assert.rejects(stat(out), { code: "ENOENT" });
  });

  it("exits 2 without the owner key in the environment", async () => {
    await assert.rejects(run({ NEAR_OWNER_KEY: "" }, "--rpc", rpcUrl, "--account", AGENT, "--contract", TARGET, "--methods", "a", "--allowance", "1", "--out", join(dir, "k")), (error: { code?: number }) => error.code === 2);
  });

  it("rejects an allowance that is not a plain decimal, such as 1,5 (which a lax parser reads as 15), and adds no key", async () => {
    for (const allowance of ["1,5", "1e3", "-1", ".5", "1.", "0x10", " 1", "1 ", "1.0000000000000000000000001", "NaN"]) {
      const failure = await run({ NEAR_OWNER_KEY: ownerKey.toString() }, "--rpc", rpcUrl, "--account", AGENT, "--contract", TARGET, "--methods", "a", `--allowance=${allowance}`, "--out", join(dir, "k")).then(() => undefined, (error: { code?: number; stderr?: string }) => error);
      assert.equal(failure?.code, 1, allowance);
      assert.match(failure?.stderr ?? "", /--allowance must be a plain decimal/, allowance);
    }
    assert.equal([...fake.keys.keys()].length, 1);
  });

  it("prints a failure's text escaped: no control, bidi or forged line reaches the terminal", async () => {
    // The JSON parser quotes the start of the body in its error message, so the chain's text reaches the catch.
    fake.faults.set("view_access_key", { kind: "body", text: "boom\u001b[31m\u202e\nscope-key succeeded: forged" });
    const failure = await run({ NEAR_OWNER_KEY: ownerKey.toString() }, "--rpc", rpcUrl, "--account", AGENT, "--contract", TARGET, "--methods", "a", "--allowance", "1", "--out", join(dir, "k")).then(() => undefined, (error: { code?: number; stderr?: string }) => error);
    assert.equal(failure?.code, 1);
    assert.match(failure?.stderr ?? "", /^scope-key failed: .*boom\\u001b\[31m\\u202e/, "the hostile text arrived, escaped");
    assert.equal((failure?.stderr ?? "").trimEnd().split("\n").length, 1, failure?.stderr);
    assert.doesNotMatch((failure?.stderr ?? "").trimEnd(), /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/);
  });

  it("prints a bad option as an escaped message and the usage, exit 2, not a stack trace", async () => {
    const failure = await run({ NEAR_OWNER_KEY: ownerKey.toString() }, "--bogus\u001b[31m").then(() => undefined, (error: { code?: number; stderr?: string }) => error);
    assert.equal(failure?.code, 2);
    assert.match(failure?.stderr ?? "", /^Unknown option '--bogus\\u001b\[31m'/);
    assert.match(failure?.stderr ?? "", /\nusage: /);
    assert.doesNotMatch(failure?.stderr ?? "", /\u001b|at .*\.ts|node:internal/);
  });
});
