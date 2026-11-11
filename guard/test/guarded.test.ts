import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { Account, KeyPair, KeyPairSigner, actions, nearToYocto, teraToGas, type Transaction } from "near-api-js";
import { DecisionLog } from "../src/log.ts";
import { GuardedAgent, RefusedError, type CallRequest, type GuardedAgentOptions, type LogEntry, type Policy } from "../src/index.ts";
import { FakeNear, fakeWasm, type KeyPermission } from "../testkit/fake-rpc.ts";
import { makeTempDir } from "../testkit/tempdir.ts";

const REGISTRY = "registry.test.near";
const AGENT = "agent.test.near";
const TARGET = "escrow.test.near";

let fake: FakeNear;
let rpcUrl: string;
let dir: string;
let logPath: string;

beforeEach(async () => {
  fake = new FakeNear(REGISTRY);
  rpcUrl = await fake.start();
  dir = await makeTempDir("guard-test");
  logPath = join(dir, "decisions.jsonl");
});
afterEach(async () => {
  await fake.stop();
  await rm(dir, { recursive: true, force: true });
});

const functionCallKey = (contract: string, methods: string[] = []): KeyPermission => ({
  FunctionCall: { allowance: "250000000000000000000000", receiver_id: contract, method_names: methods },
});

/** An agent whose single key has `permission` on the fake chain; null leaves the key unknown to the chain. */
async function agentWith(permission: KeyPermission | null, overrides: Partial<GuardedAgentOptions> = {}, policy: Partial<Policy> = {}): Promise<GuardedAgent> {
  const signer = new KeyPairSigner(KeyPair.fromRandom("ed25519"));
  if (permission !== null) fake.addKey(AGENT, (await signer.getPublicKey()).toString(), permission);
  return new GuardedAgent({
    accountId: AGENT,
    signer,
    guard: { rpcUrl, registryId: REGISTRY, timeoutMs: 2_000 },
    policy: { allowedContracts: [TARGET], maxDepositPerCall: 0n, maxTotalDeposit: 0n, ...policy },
    logPath,
    now: () => new Date("2026-11-14T12:00:00.000Z"),
    ...overrides,
  });
}

const request = (overrides: Partial<CallRequest> = {}): CallRequest => ({
  contractId: TARGET,
  method: "release",
  args: { order_id: 42 },
  deposit: 0n,
  gas: teraToGas("30"),
  ...overrides,
});

async function readLog(): Promise<LogEntry[]> {
  const text = await readFile(logPath, "utf8").catch(() => "");
  return text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as LogEntry);
}

async function refusal(promise: Promise<unknown>): Promise<RefusedError> {
  const error = await promise.then(() => undefined, (e: unknown) => e);
  assert.ok(error instanceof RefusedError, `expected RefusedError, got ${String(error)}`);
  return error;
}

describe("decisions", () => {
  it("signs and sends when the guard allows, and logs the decision", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    const codeHash = fake.publish(TARGET, "Safe");
    const agent = await agentWith(functionCallKey(TARGET, ["release"]));

    const result = await agent.guardedCall(request());
    assert.equal(result.guard.decision, "allow");
    assert.equal(fake.sent.length, 1);
    const [sent] = fake.sent;
    assert.equal(sent?.receiverId, TARGET);
    assert.equal(sent?.signerId, AGENT);
    assert.equal(sent?.methodName, "release");
    assert.deepEqual(JSON.parse(sent?.args ?? ""), { order_id: 42 });
    assert.equal(sent?.gas, teraToGas("30"));

    const [entry, handOff, ...rest] = await readLog();
    assert.equal(rest.length, 0);
    assert.deepEqual(entry, {
      timestamp: "2026-11-14T12:00:00.000Z",
      contract: TARGET,
      method: "release",
      deposit: "0",
      codeHash,
      decision: "allow",
      outcome: "approved",
      reasons: entry?.reasons,
    });
    assert.deepEqual(handOff, { ...entry, outcome: "sent" });
    assert.match(entry?.reasons.join() ?? "", /Safe/);
  });

  it("refuses on block: nothing is signed, the log names the rule", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("bad") });
    fake.publish(TARGET, "Unsafe", ["PF004"]);
    const agent = await agentWith(functionCallKey(TARGET));

    const error = await refusal(agent.guardedCall(request()));
    assert.equal(error.entry.decision, "block");
    assert.deepEqual(fake.sent, []);
    const [entry] = await readLog();
    assert.equal(entry?.outcome, "refused");
    assert.match(entry?.reasons.join() ?? "", /PF004/);
  });

  it("refuses a warn when no approval callback is supplied", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    const agent = await agentWith(functionCallKey(TARGET));

    const error = await refusal(agent.guardedCall(request()));
    assert.equal(error.entry.decision, "warn");
    assert.match(error.message, /no approval callback/);
    assert.deepEqual(fake.sent, []);
  });

  it("refuses a warn the approver declines or the approver crashes on", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    const declined = await agentWith(functionCallKey(TARGET), { approve: () => false });
    const crashed = await agentWith(functionCallKey(TARGET), { approve: () => { throw new Error("operator offline"); } });

    assert.match((await refusal(declined.guardedCall(request()))).message, /not approved/);
    assert.match((await refusal(crashed.guardedCall(request()))).message, /operator offline/);
    assert.deepEqual(fake.sent, []);
  });

  it("signs a warn the approver accepts, passing it the request and the guard result", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    const seen: string[] = [];
    const agent = await agentWith(functionCallKey(TARGET), {
      approve: (req, guard) => {
        seen.push(`${req.method}:${guard.decision}:${guard.codeHash === null}`);
        return true;
      },
    });

    await agent.guardedCall(request());
    assert.deepEqual(seen, ["release:warn:false"]);
    assert.equal(fake.sent.length, 1);
    const [entry] = await readLog();
    assert.equal(entry?.decision, "warn");
    assert.equal(entry?.outcome, "approved");
  });

  it("refuses when the RPC is down: the guard fails closed and nothing is signed", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.faults.set("view_account", { kind: "drop" });
    const agent = await agentWith(functionCallKey(TARGET));
    const error = await refusal(agent.guardedCall(request()));
    assert.equal(error.entry.decision, "block");
    assert.deepEqual(fake.sent, []);
  });

  it("signs nothing when the decision cannot be logged, and says so in the RefusedError", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith(functionCallKey(TARGET), { logPath: join(dir, "missing-dir", "log.jsonl") });
    const error = await refusal(agent.guardedCall(request()));
    assert.match(error.message, /could not be logged: .*ENOENT/);
    assert.equal(error.entry.outcome, "refused");
    assert.match(error.entry.reasons.join(), /the guard failed before signing: .*ENOENT/);
    assert.deepEqual(fake.sent, []);
  });
});

describe("policy", () => {
  it("refuses a contract outside the allow list before any RPC call", async () => {
    fake.accounts.set("other.test.near", { wasm: fakeWasm("safe") });
    fake.publish("other.test.near", "Safe");
    const agent = await agentWith(functionCallKey("other.test.near"));
    const error = await refusal(agent.guardedCall(request({ contractId: "other.test.near" })));
    assert.match(error.message, /not in the allowed contracts/);
    assert.deepEqual(fake.queries, []);
    assert.equal(error.entry.codeHash, null);
  });

  it("refuses a deposit above the per-call cap before any RPC call", async () => {
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: nearToYocto("1"), maxTotalDeposit: nearToYocto("100") });
    const error = await refusal(agent.guardedCall(request({ deposit: nearToYocto("50") })));
    assert.match(error.message, /per-call cap/);
    assert.deepEqual(fake.queries, []);
  });

  it("refuses a deposit that would pass the total cap, counting earlier signed calls", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: nearToYocto("2"), maxTotalDeposit: nearToYocto("3") });

    await agent.guardedCall(request({ deposit: nearToYocto("2") }));
    const error = await refusal(agent.guardedCall(request({ deposit: nearToYocto("2") })));
    assert.match(error.message, /total cap/);
    await agent.guardedCall(request({ deposit: nearToYocto("1") }));
    assert.deepEqual(fake.sent.map((call) => call.deposit), [nearToYocto("2"), nearToYocto("1")]);
  });

  it("does not count a refused call against the total cap", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("bad") });
    fake.publish(TARGET, "Unsafe", ["PF004"]);
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: nearToYocto("2"), maxTotalDeposit: nearToYocto("2") });

    await refusal(agent.guardedCall(request({ deposit: nearToYocto("2") })));
    fake.accounts.set(TARGET, { wasm: fakeWasm("good") });
    fake.publish(TARGET, "Safe");
    await agent.guardedCall(request({ deposit: nearToYocto("2") }));
    assert.equal(fake.sent.length, 1);
  });

  it("commits deposits before awaiting, so concurrent calls cannot jointly exceed the total cap", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: nearToYocto("6"), maxTotalDeposit: nearToYocto("10") });

    const outcomes = await Promise.allSettled([agent.guardedCall(request({ deposit: nearToYocto("6") })), agent.guardedCall(request({ deposit: nearToYocto("6") }))]);
    assert.deepEqual(outcomes.map((o) => o.status).sort(), ["fulfilled", "rejected"]);
    assert.equal(fake.sent.length, 1);
  });

  it("rejects a negative cap at construction", async () => {
    await assert.rejects(agentWith("FullAccess", {}, { maxDepositPerCall: -1n }), TypeError);
  });
});

describe("key scope", () => {
  it("refuses a full-access key unless the owner opted in", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith("FullAccess");
    assert.match((await refusal(agent.guardedCall(request()))).message, /full-access/);
    assert.deepEqual(fake.sent, []);
  });

  it("refuses a function-call key scoped to another contract, or without the method", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const wrongContract = await agentWith(functionCallKey("elsewhere.test.near"));
    const wrongMethod = await agentWith(functionCallKey(TARGET, ["view_only"]));
    assert.match((await refusal(wrongContract.guardedCall(request()))).message, /scoped to elsewhere.test.near/);
    assert.match((await refusal(wrongMethod.guardedCall(request()))).message, /may not call method release/);
    assert.deepEqual(fake.sent, []);
  });

  it("refuses a deposit on a function-call key, which the chain would reject", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith(functionCallKey(TARGET), {}, { maxDepositPerCall: nearToYocto("1"), maxTotalDeposit: nearToYocto("1") });
    assert.match((await refusal(agent.guardedCall(request({ deposit: 1n })))).message, /cannot attach a deposit/);
  });

  it("refuses a key the chain does not know", async () => {
    const agent = await agentWith(null);
    assert.match((await refusal(agent.guardedCall(request()))).message, /cannot read the permissions/);
  });

  it("picks the signer per contract when given a function", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const signer = new KeyPairSigner(KeyPair.fromRandom("ed25519"));
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), functionCallKey(TARGET));
    const asked: string[] = [];
    const agent = new GuardedAgent({
      accountId: AGENT,
      signer: (contractId) => {
        asked.push(contractId);
        return signer;
      },
      guard: { rpcUrl, registryId: REGISTRY },
      policy: { allowedContracts: [TARGET], maxDepositPerCall: 0n, maxTotalDeposit: 0n },
      logPath,
    });
    await agent.guardedCall(request());
    assert.deepEqual(asked, [TARGET]);
    assert.equal(fake.sent.length, 1);
  });
});

describe("the request that is checked is the request that is signed", () => {
  const BAD = "bad.test.near";

  it("signs the original request when the approve callback mutates the caller's object", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    const original = request({ deposit: 0n });
    const agent = await agentWith(functionCallKey(TARGET), {
      approve: () => {
        original.contractId = BAD;
        original.deposit = nearToYocto("50");
        return true;
      },
    }, { maxDepositPerCall: nearToYocto("1"), maxTotalDeposit: nearToYocto("1") });

    await agent.guardedCall(original);
    assert.deepEqual(fake.sent.map((call) => [call.receiverId, call.deposit]), [[TARGET, 0n]]);
    const [entry] = await readLog();
    assert.equal(entry?.contract, TARGET);
    assert.equal(entry?.deposit, "0");
  });

  it("hands the approver a frozen snapshot that cannot be changed", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    let frozen = false;
    let argsFrozen = false;
    const agent = await agentWith(functionCallKey(TARGET), {
      approve: (seen) => {
        frozen = Object.isFrozen(seen);
        argsFrozen = Object.isFrozen(seen.args);
        return true;
      },
    });
    await agent.guardedCall(request());
    assert.equal(frozen, true);
    assert.equal(argsFrozen, true);
  });

  it("ignores changes the caller makes to its request after the call has started", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    fake.accounts.set(BAD, { wasm: fakeWasm("bad") });
    fake.publish(BAD, "Unsafe", ["PF004"]);
    const args = { order_id: 42 };
    const original = request({ args });
    const agent = await agentWith(functionCallKey(TARGET), {}, { allowedContracts: [TARGET] });

    const pending = agent.guardedCall(original);
    original.contractId = BAD;
    original.method = "drain";
    original.deposit = nearToYocto("50");
    args.order_id = 99;
    await pending;

    assert.deepEqual(fake.sent.map((call) => [call.receiverId, call.methodName, call.args]), [[TARGET, "release", '{"order_id":42}']]);
    const [entry] = await readLog();
    assert.deepEqual([entry?.contract, entry?.method, entry?.deposit], [TARGET, "release", "0"]);
  });

  it("releases the original deposit, not a mutated one, when the call is refused", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("bad") });
    fake.publish(TARGET, "Unsafe", ["PF004"]);
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: nearToYocto("2"), maxTotalDeposit: nearToYocto("2") });

    const original = request({ deposit: nearToYocto("2") });
    const pending = agent.guardedCall(original);
    original.deposit = nearToYocto("100");
    await refusal(pending);

    // A negative committed total would let both of these through.
    fake.accounts.set(TARGET, { wasm: fakeWasm("good") });
    fake.publish(TARGET, "Safe");
    await agent.guardedCall(request({ deposit: nearToYocto("2") }));
    await refusal(agent.guardedCall(request({ deposit: nearToYocto("2") })));
    assert.equal(fake.sent.length, 1);
  });
});

describe("calls with nothing to audit", () => {
  it("refuses an account without contract code: a function call there can only fail or hit later code", async () => {
    fake.accounts.set(TARGET, {});
    const agent = await agentWith(functionCallKey(TARGET));
    const error = await refusal(agent.guardedCall(request()));
    assert.match(error.message, /no contract code/);
    assert.equal(error.entry.decision, "block");
    assert.deepEqual(fake.sent, []);
  });

  it("refuses an account that does not exist", async () => {
    const agent = await agentWith(functionCallKey(TARGET));
    assert.match((await refusal(agent.guardedCall(request()))).message, /no contract code/);
    assert.deepEqual(fake.sent, []);
  });
});

describe("input validation", () => {
  it("refuses a function-call key whose method_names is not an array", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith(null);
    // The key above is unknown to the chain; answer every view_access_key with a malformed permission instead.
    fake.faults.set("view_access_key", {
      kind: "json",
      body: { jsonrpc: "2.0", result: { nonce: 1, permission: { FunctionCall: { allowance: "1", receiver_id: TARGET, method_names: "release" } }, block_hash: "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW", block_height: 1 }, id: "dontcare" },
    });
    assert.match((await refusal(agent.guardedCall(request()))).message, /unsupported permission/);
    assert.deepEqual(fake.sent, []);
  });

  it("throws a TypeError for a deposit that is not a non-negative bigint", async () => {
    const agent = await agentWith(functionCallKey(TARGET));
    for (const deposit of ["50", 50, -1n, null]) {
      await assert.rejects(agent.guardedCall({ ...request(), deposit: deposit as unknown as bigint }), TypeError, String(deposit));
    }
    await assert.rejects(agent.guardedCall({ ...request(), gas: "30" as unknown as bigint }), TypeError);
    assert.deepEqual(fake.queries, []);
  });

  it("throws a TypeError for caps that are not non-negative bigints", async () => {
    await assert.rejects(agentWith("FullAccess", {}, { maxTotalDeposit: 5 as unknown as bigint }), TypeError);
    await assert.rejects(agentWith("FullAccess", {}, { maxDepositPerCall: -1n }), TypeError);
  });
});

describe("arguments become bytes once, before anything awaits", () => {
  const unaudited = (): void => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
  };
  const sentOnly = (): { args: string; argsBytes: Uint8Array } => {
    assert.equal(fake.sent.length, 1);
    return { args: fake.sent[0]?.args ?? "", argsBytes: fake.sent[0]?.argsBytes ?? new Uint8Array() };
  };

  it("signs the original bytes when the approver mutates a nested typed array", async () => {
    unaudited();
    const args = { payload: new Uint8Array([1, 2, 3]) };
    const expected = JSON.stringify(args);
    const agent = await agentWith(functionCallKey(TARGET), {
      approve: (seen) => {
        args.payload[0] = 99; // the caller's own array, reachable from the callback's closure
        const view = seen.args as { payload: Record<string, number> };
        try { view.payload["0"] = 98; } catch { /* the parsed view is frozen */ }
        seen.argsBytes[0] = 0; // a copy
        return true;
      },
    });

    await agent.guardedCall(request({ args }));
    assert.equal(sentOnly().args, expected);
    assert.equal(sentOnly().args, '{"payload":{"0":1,"1":2,"2":3}}');
  });

  it("signs the original value when the approver changes a Date argument", async () => {
    unaudited();
    const args = { deadline: new Date("2026-11-14T00:00:00.000Z") };
    const agent = await agentWith(functionCallKey(TARGET), {
      approve: (seen) => {
        args.deadline.setTime(0); // the caller's own Date, reachable from the callback's closure
        (seen.args as { deadline: { setTime?: (time: number) => void } }).deadline.setTime?.(0); // a Date inside the view, if it had one
        return true;
      },
    });

    await agent.guardedCall(request({ args }));
    assert.equal(sentOnly().args, '{"deadline":"2026-11-14T00:00:00.000Z"}');
  });

  it("signs the caller's own JSON.stringify output for a Buffer and for a toJSON class", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    class Money {
      toJSON(): string {
        return "12.50 NEAR";
      }
    }
    const args = { blob: Buffer.from("hi"), price: new Money(), seen: new Map([["a", 1]]) };
    const agent = await agentWith(functionCallKey(TARGET));

    await agent.guardedCall(request({ args }));
    const { args: signed, argsBytes } = sentOnly();
    assert.equal(signed, JSON.stringify(args));
    assert.match(signed, /"type":"Buffer","data":\[104,105\]/);
    assert.match(signed, /"price":"12.50 NEAR"/);
    assert.deepEqual(argsBytes, new TextEncoder().encode(JSON.stringify(args)));
  });

  it("sends raw byte arguments to the chain exactly, and copies them at the start", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const raw = new Uint8Array([0, 255, 7, 123]);
    const agent = await agentWith(functionCallKey(TARGET));

    const pending = agent.guardedCall(request({ args: raw }));
    raw[0] = 1;
    await pending;
    assert.deepEqual(sentOnly().argsBytes, new Uint8Array([0, 255, 7, 123]));
  });

  it("shows the approver the parsed arguments and a copy of the signed bytes", async () => {
    unaudited();
    let shown: unknown;
    let bytes: Uint8Array | undefined;
    const agent = await agentWith(functionCallKey(TARGET), {
      approve: (seen) => {
        shown = seen.args;
        bytes = seen.argsBytes;
        return true;
      },
    });
    await agent.guardedCall(request({ args: { order_id: 42, nested: { ok: true } } }));
    assert.deepEqual(shown, { order_id: 42, nested: { ok: true } });
    assert.equal(Object.isFrozen(shown), true);
    assert.equal(Object.isFrozen((shown as { nested: object }).nested), true);
    assert.deepEqual(bytes, new TextEncoder().encode('{"order_id":42,"nested":{"ok":true}}'));
  });

  it("throws for a bigint argument before the budget is touched, so the next call at the cap succeeds", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: nearToYocto("2"), maxTotalDeposit: nearToYocto("2") });

    await assert.rejects(agent.guardedCall(request({ args: { n: 1n }, deposit: nearToYocto("2") })), /cannot be serialized/);
    assert.deepEqual(fake.queries, []);
    await agent.guardedCall(request({ deposit: nearToYocto("2") }));
    assert.equal(fake.sent.length, 1);
  });

  it("releases the budget and logs not_sent when the transaction cannot be built, as with a failed block fetch", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: nearToYocto("2"), maxTotalDeposit: nearToYocto("2") });

    fake.faults.set("block", { kind: "body", text: "not json" });
    await assert.rejects(agent.guardedCall(request({ deposit: nearToYocto("2") })));
    assert.deepEqual(fake.sent, []);
    const entries = await readLog();
    assert.deepEqual(entries.map((entry) => entry.outcome), ["approved", "not_sent"]);
    assert.match(entries[1]?.reasons.join() ?? "", /not sent/);

    fake.faults.delete("block");
    await agent.guardedCall(request({ deposit: nearToYocto("2") }));
    assert.equal(fake.sent.length, 1);
    assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["approved", "not_sent", "approved", "sent"]);
  });

  it("keeps the budget once the transaction was handed to the network, even when the send then fails", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: nearToYocto("2"), maxTotalDeposit: nearToYocto("2") });

    fake.faults.set("send_tx", { kind: "http", status: 400 });
    await assert.rejects(agent.guardedCall(request({ deposit: nearToYocto("2") })));
    assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["approved", "sent"]);
    fake.faults.delete("send_tx");
    assert.match((await refusal(agent.guardedCall(request({ deposit: nearToYocto("2") })))).message, /total cap/);
  });
});

describe("approval that never answers", () => {
  it("treats a timeout as declined, logs the refusal and releases the budget share", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    let asked = 0;
    const agent = await agentWith("FullAccess", {
      allowFullAccessKey: true,
      approveTimeoutMs: 50,
      approve: () => (++asked === 1 ? new Promise<boolean>(() => undefined) : true),
    }, { maxDepositPerCall: nearToYocto("2"), maxTotalDeposit: nearToYocto("2") });

    const error = await refusal(agent.guardedCall(request({ deposit: nearToYocto("2") })));
    assert.match(error.message, /no answer within 50 ms/);
    assert.equal(error.entry.outcome, "refused");
    await agent.guardedCall(request({ deposit: nearToYocto("2") }));
    assert.equal(fake.sent.length, 1);
  });

  it("rejects a timeout that is not a positive number at construction", async () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Infinity, 2 ** 31]) {
      await assert.rejects(agentWith(null, { approveTimeoutMs: bad }), TypeError, String(bad));
    }
    await agentWith(null, { approveTimeoutMs: 2 ** 31 - 1 });
  });

  it("rejects an RPC timeout that Node's timer would overflow, at construction", async () => {
    for (const bad of [0, 1.5, 2 ** 31]) {
      await assert.rejects(agentWith(null, { guard: { rpcUrl, registryId: REGISTRY, timeoutMs: bad } }), /guard\.timeoutMs/, String(bad));
    }
  });

  it("rejects a rate-limit backoff that is not a short list of timer delays, at construction", async () => {
    for (const bad of [[0], [2 ** 31], [1.5], new Array<number>(11).fill(5)]) {
      await assert.rejects(agentWith(null, { guard: { rpcUrl, registryId: REGISTRY, rateLimitBackoffMs: bad } }), /guard\.rateLimitBackoffMs/, JSON.stringify(bad));
    }
    await agentWith(null, { guard: { rpcUrl, registryId: REGISTRY, rateLimitBackoffMs: [] } });
  });

  it("rejects a backoff list that is a Proxy with a huge length, at construction, without hanging", async () => {
    const huge = new Proxy([5], { get: (target, key, receiver) => (key === "length" ? 2 ** 31 : (Reflect.get(target, key, receiver) as unknown)) });
    await assert.rejects(agentWith(null, { guard: { rpcUrl, registryId: REGISTRY, rateLimitBackoffMs: huge } }), /guard\.rateLimitBackoffMs/);
  });

  it("backs off when the key lookup is rate limited, then signs", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("audited") });
    fake.publish(TARGET, "Safe");
    fake.faults.set("view_access_key", { kind: "http", status: 429, times: 1 });
    const agent = await agentWith(functionCallKey(TARGET), { guard: { rpcUrl, registryId: REGISTRY, timeoutMs: 2_000, rateLimitBackoffMs: [20] } });
    await agent.guardedCall({ contractId: TARGET, method: "release", deposit: 0n, gas: teraToGas("30") });
    assert.equal(fake.sent.length, 1);
    assert.equal(fake.queries.filter((type) => type === "view_access_key").length, 3, "the throttled lookup, the retry that answered, and near-api-js's own nonce lookup");
  });

  it("hands the backoff to the key lookup: a list of [] means one request, not the default retries", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("audited") });
    fake.publish(TARGET, "Safe");
    fake.faults.set("view_access_key", { kind: "http", status: 429 });
    const agent = await agentWith(functionCallKey(TARGET), { guard: { rpcUrl, registryId: REGISTRY, timeoutMs: 2_000, rateLimitBackoffMs: [] } });
    await assert.rejects(agent.guardedCall({ contractId: TARGET, method: "release", deposit: 0n, gas: teraToGas("30") }), RefusedError);
    assert.equal(fake.queries.filter((type) => type === "view_access_key").length, 1);
    assert.equal(fake.sent.length, 0);
  });

  it("keeps its own copy of the backoff list: edits after construction change nothing", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("audited") });
    fake.publish(TARGET, "Safe");
    fake.faults.set("view_access_key", { kind: "http", status: 429 });
    const list = [5];
    const agent = await agentWith(functionCallKey(TARGET), { guard: { rpcUrl, registryId: REGISTRY, timeoutMs: 2_000, rateLimitBackoffMs: list } });
    list.push(...new Array<number>(9).fill(1));
    await assert.rejects(agent.guardedCall({ contractId: TARGET, method: "release", deposit: 0n, gas: teraToGas("30") }), RefusedError);
    assert.equal(fake.queries.filter((type) => type === "view_access_key").length, 2, "the one retry the list held at construction");
  });

  it("leaves no timer pending after the approver has answered", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    const agent = await agentWith(functionCallKey(TARGET), { approveTimeoutMs: 600_000, approve: () => true });
    const timers = (): number => process.getActiveResourcesInfo().filter((resource) => resource === "Timeout").length;
    const before = timers();
    await agent.guardedCall(request());
    assert.equal(timers(), before);
  });
});

describe("untrusted text in the thrown message", () => {
  it("blocks a registry rule id with a newline as a malformed verdict, and the refusal stays one line", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("bad") });
    const codeHash = fake.publish(TARGET, "Unsafe", ["PF004"]);
    const published = fake.verdicts.get(codeHash);
    if (published !== undefined) published.rule_ids = ["PF004\n2026-11-14T12:00:00.000Z allow forged"];
    const agent = await agentWith(functionCallKey(TARGET));

    const error = await refusal(agent.guardedCall(request()));
    assert.doesNotMatch(error.message, /[\u0000-\u001f]|forged/);
    assert.match(error.message, /malformed verdict: bad rule_ids/);
    assert.equal(error.entry.decision, "block");
  });
});

describe("only the boolean true approves", () => {
  const answers: Array<[string, () => unknown, RegExp]> = [
    ['the string "false"', () => "false", /returned string, not true/],
    ['the string "no"', () => "no", /returned string, not true/],
    ["the number 1", () => 1, /returned number, not true/],
    ["an object", () => ({ approved: false }), /returned object, not true/],
    ["undefined", () => undefined, /returned undefined, not true/],
    ['a promise resolving to the string "true"', () => Promise.resolve("true"), /returned string, not true/],
  ];
  for (const [name, answer, message] of answers) {
    it(`declines ${name}`, async () => {
      fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
      const agent = await agentWith(functionCallKey(TARGET), { approve: answer as unknown as () => boolean });
      const error = await refusal(agent.guardedCall(request()));
      assert.match(error.message, message);
      assert.match(error.message, /treated as declined/);
      assert.deepEqual(fake.sent, []);
      assert.equal(error.entry.outcome, "refused");
    });
  }
});

describe("every reason in the log and the thrown error is escaped", () => {
  const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

  it("escapes an ESC byte in the receiver_id the chain reports for the key", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith(functionCallKey("evil\u001b[31m.near"));
    const error = await refusal(agent.guardedCall(request()));
    assert.doesNotMatch(error.entry.reasons.join(), CONTROL);
    assert.match(error.entry.reasons[0] ?? "", /evil\\u001b\[31m\.near/);
    for (const entry of await readLog()) assert.doesNotMatch(entry.reasons.join(), CONTROL);
  });

  it("escapes the message of an approver that throws", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    const agent = await agentWith(functionCallKey(TARGET), { approve: () => { throw new Error("boom\nline2"); } });
    const error = await refusal(agent.guardedCall(request()));
    assert.doesNotMatch(error.entry.reasons.join(), CONTROL);
    assert.match(error.entry.reasons.join(), /boom\\u000aline2/);
  });

  it("escapes the error message of a call that fails before the hand-off", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    class FailingSigner extends KeyPairSigner {
      override async signTransaction(): ReturnType<KeyPairSigner["signTransaction"]> {
        throw new Error("hsm\nforged line");
      }
    }
    const signer = new FailingSigner(KeyPair.fromRandom("ed25519"));
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), "FullAccess");
    const agent = await agentWith(null, { signer, allowFullAccessKey: true });

    await assert.rejects(agent.guardedCall(request()), /hsm/);
    const entries = await readLog();
    assert.equal(entries.at(-1)?.outcome, "not_sent");
    assert.doesNotMatch(entries.at(-1)?.reasons.join() ?? "", CONTROL);
    assert.match(entries.at(-1)?.reasons.join() ?? "", /hsm\\u000aforged line/);
  });

  it("cuts a very long outside reason and escapes bidi controls in it", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("bad") });
    const agent = await agentWith(functionCallKey("evil\u202e" + "x".repeat(50_000)));
    const error = await refusal(agent.guardedCall(request()));
    for (const reason of error.entry.reasons) assert.ok(reason.length <= 500, String(reason.length));
    assert.match(error.entry.reasons.join(), /evil\\u202e/);
    assert.match(error.entry.reasons.join(), /\.\.\.\[truncated\]/);
    assert.ok(error.message.length < 1_000);
  });
});

describe("what the approver is shown of raw byte arguments is exactly what is signed, or nothing", () => {
  async function shownFor(bytes: Uint8Array): Promise<{ args: unknown; argsBytes: Uint8Array | undefined }> {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    let args: unknown = "not called";
    let argsBytes: Uint8Array | undefined;
    const agent = await agentWith(functionCallKey(TARGET), {
      approve: (seen) => {
        args = seen.args;
        argsBytes = seen.argsBytes;
        return true;
      },
    });
    await agent.guardedCall(request({ args: bytes }));
    assert.deepEqual(fake.sent[0]?.argsBytes, bytes);
    return { args, argsBytes };
  }
  const encode = (text: string): Uint8Array => new TextEncoder().encode(text);

  it("shows nothing for duplicate keys, where JSON.parse would keep only the last", async () => {
    const bytes = encode('{"to":"alice.near","to":"mallory.near"}');
    assert.deepEqual(await shownFor(bytes), { args: undefined, argsBytes: bytes });
  });

  it("shows nothing for a number that does not survive parsing", async () => {
    const bytes = encode('{"amount":100000000000000000000001}');
    assert.deepEqual(await shownFor(bytes), { args: undefined, argsBytes: bytes });
  });

  it("shows nothing when a byte order mark leads the JSON", async () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, ...encode('{"a":1}')]);
    assert.deepEqual(await shownFor(bytes), { args: undefined, argsBytes: bytes });
  });

  it("still shows the parsed value when it re-encodes to exactly the bytes", async () => {
    const bytes = encode('{"to":"alice.near","n":[1,2,{"ok":true}]}');
    assert.deepEqual(await shownFor(bytes), { args: { to: "alice.near", n: [1, 2, { ok: true }] }, argsBytes: bytes });
  });
});

describe("the request is read once, and every read is at the optimistic head", () => {
  it("reads a getter-backed args property exactly once", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith(functionCallKey(TARGET));
    let reads = 0;
    const input = request();
    Object.defineProperty(input, "args", { get: () => ({ order_id: ++reads }) });

    await agent.guardedCall(input);
    assert.equal(reads, 1);
    assert.equal(fake.sent[0]?.args, '{"order_id":1}');
  });

  it("asks the chain for the access key, the account, the code and the registry at finality optimistic", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith(functionCallKey(TARGET));

    await agent.guardedCall(request());
    assert.ok(fake.queries.includes("view_access_key"));
    assert.ok(fake.queries.length >= 4);
    assert.deepEqual(fake.queryParams.map((params) => params["finality"]), fake.queries.map(() => "optimistic"));
  });
});

describe("a send that went out is never released from the budget", () => {
  it("keeps the share and says so in the log when the hand-off hook was bypassed", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: nearToYocto("2"), maxTotalDeposit: nearToYocto("2") });

    // Replace the send path so it never calls the overridden createSignedTransaction, as if the hook were skipped.
    const proto = Account.prototype;
    const original = proto.signAndSendTransaction;
    proto.signAndSendTransaction = async function bypass(this: Account, params: Parameters<Account["signAndSendTransaction"]>[0]) {
      const signed = await Account.prototype.createSignedTransaction.call(this, params);
      return this.provider.sendTransactionUntil(signed, "EXECUTED_OPTIMISTIC");
    };
    try {
      await agent.guardedCall(request({ deposit: nearToYocto("2") }));
    } finally {
      proto.signAndSendTransaction = original;
    }
    assert.equal(fake.sent.length, 1);
    const entries = await readLog();
    assert.deepEqual(entries.map((entry) => entry.outcome), ["approved", "sent"]);
    assert.match(entries[1]?.reasons.join() ?? "", /hand-off hook did not run/);
    assert.match((await refusal(agent.guardedCall(request({ deposit: nearToYocto("2") })))).message, /total cap/);
  });
});

/** The whole log file as written: no parsing first, so a torn or forged line shows. */
async function rawLog(): Promise<string> {
  return readFile(logPath, "utf8").catch(() => "");
}

const FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060\ufeff\u00ad]|[\u{e0000}-\u{e007f}]/u;

describe("what crosses the boundary is validated before anything is touched", () => {
  const badContracts = ["evil.near\nforged line", "evil\u202e.near", "evil\u2028.near", "evil\u0085.near", "UPPER.near", "a", "", "a".repeat(65), "has space.near"];
  const badMethods = ["rel\u202ease", "rel\u2028ease", "rel\u0085ease", "release\nforged", "", "2fast", "a.b", "a".repeat(257), "x".repeat(8_000_000)];

  for (const [field, values] of [["contractId", badContracts], ["method", badMethods]] as const) {
    it(`throws a TypeError for a bad ${field}, with nothing logged, queried or committed`, async () => {
      fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
      fake.publish(TARGET, "Safe");
      const agent = await agentWith(functionCallKey(TARGET), {}, { maxDepositPerCall: 0n, maxTotalDeposit: 0n });
      for (const value of values) {
        const error = await agent.guardedCall(request({ [field]: value })).then(() => undefined, (e: unknown) => e);
        assert.ok(error instanceof TypeError, `${field} ${JSON.stringify(value).slice(0, 30)}: ${String(error)}`);
        assert.doesNotMatch(error.message, FORBIDDEN);
        assert.ok(error.message.length < 1_500, `message of ${error.message.length} characters`);
      }
      assert.equal(await rawLog(), "");
      assert.deepEqual(fake.queries, []);
      await agent.guardedCall(request());
      assert.equal(fake.sent.length, 1, "a rejected request leaves the agent working");
    });
  }

  it("proves a concurrent legitimate call's lines stay parseable next to a giant method name", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith(functionCallKey(TARGET));
    const [giant, legit] = await Promise.allSettled([agent.guardedCall(request({ method: "m".repeat(8_000_000) })), agent.guardedCall(request())]);
    assert.equal(giant.status, "rejected");
    assert.equal(legit.status, "fulfilled");
    const lines = (await rawLog()).trimEnd().split("\n");
    assert.deepEqual(lines.map((line) => (JSON.parse(line) as LogEntry).outcome), ["approved", "sent"]);
    for (const line of lines) assert.ok(Buffer.byteLength(line, "utf8") < 16 * 1024);
  });

  const hostileValues = "\u202e\u2028\u0085\u200b\ufeff\u00ad\u{e0041}\u001b";
  it("rejects a policy, registry, account or rpc setting that is not valid, at construction", async () => {
    const good = { accountId: AGENT, signer: new KeyPairSigner(KeyPair.fromRandom("ed25519")), guard: { rpcUrl, registryId: REGISTRY }, policy: { allowedContracts: [TARGET], maxDepositPerCall: 0n, maxTotalDeposit: 0n }, logPath };
    const variants: Array<[string, Partial<Record<keyof GuardedAgentOptions, unknown>>]> = [
      ["an allowedContracts entry with a newline", { policy: { ...good.policy, allowedContracts: ["ok.near", "evil.near\nx"] } }],
      ["an allowedContracts entry with hostile characters", { policy: { ...good.policy, allowedContracts: [`a${hostileValues}.near`] } }],
      ["allowedContracts that is not an array", { policy: { ...good.policy, allowedContracts: "escrow.test.near" } }],
      ["an invalid accountId", { accountId: "Agent\n.near" }],
      ["an invalid registryId", { guard: { rpcUrl, registryId: "reg\u202e.near" } }],
      ["an rpcUrl that is not http(s)", { guard: { rpcUrl: "ftp://example.com", registryId: REGISTRY } }],
      ["an rpcUrl that is not a URL", { guard: { rpcUrl: "not a url", registryId: REGISTRY } }],
      ["an approve that is not a function", { approve: "yes" }],
      ["a now that is not a function", { now: "yesterday" }],
      ["an empty logPath", { logPath: "" }],
      ["no signer", { signer: undefined }],
    ];
    for (const [name, change] of variants) {
      assert.throws(() => new GuardedAgent({ ...good, ...change } as GuardedAgentOptions), (error: unknown) => error instanceof TypeError && !FORBIDDEN.test(error.message), name);
    }
    assert.doesNotThrow(() => new GuardedAgent(good));
  });

  it("validates the copy it keeps, so an options object that answers differently on a second read changes nothing", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const signer = new KeyPairSigner(KeyPair.fromRandom("ed25519"));
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), functionCallKey(TARGET));
    let guardReads = 0;
    let policyReads = 0;
    const options = {
      accountId: AGENT,
      signer,
      logPath,
      get guard() {
        guardReads += 1;
        return guardReads === 1 ? { rpcUrl, registryId: REGISTRY, timeoutMs: 2_000 } : { rpcUrl: "ftp://elsewhere", registryId: "x" };
      },
      get policy() {
        policyReads += 1;
        return policyReads === 1 ? { allowedContracts: [TARGET], maxDepositPerCall: 0n, maxTotalDeposit: 0n } : { allowedContracts: ["evil\n.near"], maxDepositPerCall: -1n, maxTotalDeposit: 5n };
      },
    } as GuardedAgentOptions;
    const agent = new GuardedAgent(options);
    await agent.guardedCall(request());
    assert.equal(fake.sent.length, 1);
    assert.equal(guardReads, 1);
    assert.equal(policyReads, 1);
  });
});

describe("the log file, read raw, holds only escaped text and exactly what RefusedError.entry says", () => {
  it("escapes bidi, separators, NEL, zero-width and tag characters that the chain reports", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith(functionCallKey("evil\u202e\u2028\u0085\u200b\ufeff\u00ad\u{e0041}\\u000a.near"));
    const error = await refusal(agent.guardedCall(request()));

    const raw = await rawLog();
    assert.doesNotMatch(raw.trimEnd(), FORBIDDEN);
    const lines = raw.trimEnd().split("\n");
    assert.equal(lines.length, 1);
    assert.deepEqual(JSON.parse(lines[0] ?? ""), error.entry, "the thrown entry is the logged object");
    assert.match(error.entry.reasons[0] ?? "", /evil\\u202e\\u2028\\u0085\\u200b\\ufeff\\u00ad\\u\{e0041\}\\u005cu000a\.near/);
    assert.doesNotMatch(error.message, FORBIDDEN);
  });

  it("keeps the line within its byte cap for a refusal with a 50000-character reason", async () => {
    const agent = await agentWith(functionCallKey("x".repeat(50_000)));
    const error = await refusal(agent.guardedCall(request()));
    const [line] = (await rawLog()).trimEnd().split("\n");
    assert.ok(Buffer.byteLength(line ?? "", "utf8") < 16 * 1024);
    assert.ok(error.message.length < 1_000);
  });
});

/** Values that a throw can carry and `String()` cannot print. */
const unprintableThrows: Array<[string, () => unknown]> = [
  ["a null-prototype object", () => Object.create(null)],
  ["an object whose toString throws", () => ({ toString() { throw new Error("no"); } })],
  ["an Error whose message getter throws", () => Object.defineProperty(new Error("x"), "message", { get() { throw new Error("no"); } })],
  ["a revoked proxy", () => { const { proxy, revoke } = Proxy.revocable({}, {}); revoke(); return proxy; }],
  ["a symbol", () => Symbol("s")],
];

describe("an approver or signer that throws something unprintable still ends in one logged refusal", () => {
  for (const [name, make] of unprintableThrows) {
    it(`approver throws ${name}`, async () => {
      fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
      const agent = await agentWith(functionCallKey(TARGET), { approve: () => { throw make(); } });
      const error = await refusal(agent.guardedCall(request()));
      assert.match(error.entry.reasons.join(), /approval callback failed: /);
      assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["refused"]);
      assert.deepEqual(fake.sent, []);
    });

    it(`approver rejects with ${name}`, async () => {
      fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
      const agent = await agentWith(functionCallKey(TARGET), { approve: () => Promise.reject(make()) });
      const error = await refusal(agent.guardedCall(request()));
      assert.match(error.entry.reasons.join(), /approval callback failed: /);
      assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["refused"]);
    });

    it(`signer factory throws ${name}`, async () => {
      const agent = await agentWith(null, { signer: () => { throw make(); } });
      const error = await refusal(agent.guardedCall(request()));
      assert.match(error.entry.reasons.join(), /the guard failed before signing: /);
      assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["refused"]);
      assert.deepEqual(fake.queries, []);
    });
  }

  it("approver returns a thenable whose then getter throws", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    const thenable = Object.defineProperty({}, "then", { get() { throw new Error("no"); } });
    const agent = await agentWith(functionCallKey(TARGET), { approve: () => thenable as unknown as boolean });
    const error = await refusal(agent.guardedCall(request()));
    assert.match(error.entry.reasons.join(), /approval callback failed: /);
    assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["refused"]);
  });

  it("approver returns a thenable whose then throws an unprintable value", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("unaudited") });
    const agent = await agentWith(functionCallKey(TARGET), { approve: () => ({ then() { throw Object.create(null); } }) as unknown as boolean });
    const error = await refusal(agent.guardedCall(request()));
    assert.match(error.entry.reasons.join(), /approval callback failed: an unprintable object was thrown/);
  });

  it("signTransaction throws something unprintable after the approval: one not_sent line, original error rethrown", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const thrown = Object.create(null) as object;
    class Failing extends KeyPairSigner {
      override async signTransaction(): ReturnType<KeyPairSigner["signTransaction"]> {
        throw thrown;
      }
    }
    const signer = new Failing(KeyPair.fromRandom("ed25519"));
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), functionCallKey(TARGET));
    const agent = await agentWith(null, { signer });
    const error = await agent.guardedCall(request()).then(() => undefined, (e: unknown) => e);
    assert.equal(error, thrown);
    const entries = await readLog();
    assert.deepEqual(entries.map((entry) => entry.outcome), ["approved", "not_sent"]);
    assert.match(entries[1]?.reasons.join() ?? "", /not sent: an unprintable object was thrown/);
  });
});

describe("every exit after the request is accepted ends in exactly one terminal log line", () => {
  const terminal = (entries: LogEntry[]): string[] => entries.map((entry) => entry.outcome).filter((outcome) => outcome !== "approved");

  it("getPublicKey rejects", async () => {
    class NoKey extends KeyPairSigner {
      override async getPublicKey(): ReturnType<KeyPairSigner["getPublicKey"]> {
        throw new Error("hsm offline\nforged");
      }
    }
    const agent = await agentWith(null, { signer: new NoKey(KeyPair.fromRandom("ed25519")) });
    const error = await refusal(agent.guardedCall(request()));
    assert.match(error.message, /the guard failed before signing: hsm offline/);
    assert.deepEqual(terminal(await readLog()), ["refused"]);
    assert.doesNotMatch((await rawLog()).trimEnd(), FORBIDDEN);
  });

  it("the signer factory throws", async () => {
    const agent = await agentWith(null, { signer: () => { throw new Error("no key for this contract"); } });
    const error = await refusal(agent.guardedCall(request()));
    assert.match(error.message, /no key for this contract/);
    assert.deepEqual(terminal(await readLog()), ["refused"]);
  });

  it("a refusal whose log write fails still throws a RefusedError, and the error says the disk failed", async () => {
    const agent = await agentWith(null, { logPath: join(dir, "missing-dir", "log.jsonl") });
    const error = await refusal(agent.guardedCall(request({ contractId: "other.test.near" })));
    assert.match(error.message, /not in the allowed contracts/);
    assert.match(error.message, /could not be logged: .*ENOENT/);
    assert.equal(error.entry.outcome, "refused");
  });

  it("a failed approved write refuses without signing, and the error carries the disk failure", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const agent = await agentWith(functionCallKey(TARGET), { logPath: dir });
    const error = await refusal(agent.guardedCall(request()));
    assert.match(error.entry.reasons.join(), /could not be logged: .*(EISDIR|illegal operation)/);
    assert.deepEqual(fake.sent, []);
  });

  it("a request that passes the key check and is blocked ends in one refused line, none approved", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("bad") });
    fake.publish(TARGET, "Unsafe", ["PF001"]);
    const agent = await agentWith(functionCallKey(TARGET));
    await refusal(agent.guardedCall(request()));
    assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["refused"]);
  });

  it("a clock that throws or returns garbage does not stop the decision from being logged", async () => {
    for (const now of [() => { throw new Error("clock"); }, () => new Date(Number.NaN), () => "2026-01-01" as unknown as Date]) {
      await rm(logPath, { force: true });
      const agent = await agentWith(null, { now });
      await refusal(agent.guardedCall(request({ contractId: "other.test.near" })));
      const [entry] = await readLog();
      assert.match(entry?.timestamp ?? "", /^\d{4}-\d\d-\d\dT/);
    }
  });
});

describe("the transaction that is signed is the request that was checked", () => {
  type Mutation = (transaction: Transaction) => void;

  /** A signer that, as it signs, changes the transaction it was handed. */
  const rewriting = (mutate: Mutation): KeyPairSigner => {
    class Rewriter extends KeyPairSigner {
      override async signTransaction(transaction: Transaction): ReturnType<KeyPairSigner["signTransaction"]> {
        mutate(transaction);
        return super.signTransaction(transaction);
      }
    }
    return new Rewriter(KeyPair.fromRandom("ed25519"));
  };

  async function sendThrough(mutate: Mutation): Promise<unknown> {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const signer = rewriting(mutate);
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), functionCallKey(TARGET));
    const agent = await agentWith(null, { signer });
    return agent.guardedCall(request({ deposit: 0n })).then(() => undefined, (e: unknown) => e);
  }

  const functionCall = (transaction: Transaction) => {
    const action = transaction.actions[0];
    assert.ok(action?.functionCall, "the transaction carries a function call");
    return action.functionCall;
  };

  const rewrites: [string, Mutation, RegExp][] = [
    ["receiver and method", (t) => { t.receiverId = "drain.test.near"; t.actions = [actions.functionCall("withdraw_all", new Uint8Array(), teraToGas("30"), 0n)]; }, /receiver, method/],
    ["receiver alone", (t) => { t.receiverId = "drain.test.near"; }, /receiver/],
    ["method alone", (t) => { t.actions = [actions.functionCall("withdraw_all", Buffer.from(JSON.stringify({ order_id: 42 })), teraToGas("30"), 0n)]; }, /method/],
    ["arguments", (t) => { functionCall(t).args = new Uint8Array(Buffer.from(JSON.stringify({ order_id: 43 }))); }, /arguments/],
    ["deposit", (t) => { functionCall(t).deposit = 1n; }, /deposit/],
    ["gas", (t) => { functionCall(t).gas = teraToGas("31"); }, /gas/],
    ["signer account", (t) => { t.signerId = "other.test.near"; }, /signer account/],
    ["an extra transfer action", (t) => { t.actions = [...t.actions, actions.transfer(1n)]; }, /actions \(not exactly one function call\)/],
    ["a transfer in place of the call", (t) => { t.actions = [actions.transfer(1n)]; }, /actions \(not exactly one function call\)/],
    ["a second call", (t) => { t.actions = [...t.actions, ...t.actions]; }, /actions \(not exactly one function call\)/],
  ];
  for (const [name, mutate, field] of rewrites) {
    it(`a signer that rewrites the ${name} sends nothing and the log says not_sent`, async () => {
      const error = await sendThrough(mutate);
      assert.match(String((error as Error | undefined)?.message), /differs from the checked request/);
      assert.deepEqual(fake.sent, []);
      const entries = await readLog();
      assert.deepEqual(entries.map((entry) => entry.outcome), ["approved", "not_sent"]);
      assert.match(entries[1]?.reasons.join() ?? "", field);
    });
  }

  it("sends a transaction the signer left alone, and only then logs sent", async () => {
    assert.equal(await sendThrough(() => undefined), undefined);
    assert.equal(fake.sent.length, 1);
    assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["approved", "sent"]);
  });

  it("refuses a transaction made under another key than the one that was checked", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const scoped = KeyPair.fromRandom("ed25519");
    const fullAccess = KeyPair.fromRandom("ed25519");
    fake.addKey(AGENT, scoped.getPublicKey().toString(), functionCallKey(TARGET, ["release"]));
    fake.addKey(AGENT, fullAccess.getPublicKey().toString(), "FullAccess");
    // The key read for the permission check is the function-call key; every later read, and the signature, are the full-access key.
    let reads = 0;
    class Switching extends KeyPairSigner {
      override async getPublicKey(): ReturnType<KeyPairSigner["getPublicKey"]> {
        reads += 1;
        return reads === 1 ? scoped.getPublicKey() : super.getPublicKey();
      }
    }
    const agent = await agentWith(null, { signer: new Switching(fullAccess) });
    const error = await agent.guardedCall(request()).then(() => undefined, (e: unknown) => e);
    assert.match(String((error as Error | undefined)?.message), /differs from the checked request in: public key/);
    assert.ok(reads >= 2, "the key was read again for the transaction");
    assert.deepEqual(fake.sent, []);
    assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["approved", "not_sent"]);
  });

  it("puts on the wire only what it checked, when the signer's transaction object answers differently on every read", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    class Shifty extends KeyPairSigner {
      override async signTransaction(transaction: Transaction): ReturnType<KeyPairSigner["signTransaction"]> {
        const result = await super.signTransaction(transaction);
        let reads = 0;
        Object.defineProperty(result.signedTransaction.transaction, "receiverId", { get: () => (reads++ % 2 === 0 ? TARGET : "drain.test.near"), configurable: true });
        return result;
      }
    }
    const signer = new Shifty(KeyPair.fromRandom("ed25519"));
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), functionCallKey(TARGET));
    const agent = await agentWith(null, { signer });
    await agent.guardedCall(request()).then(() => undefined, () => undefined);
    assert.ok(fake.sent.every((call) => call.receiverId === TARGET), `the chain received ${fake.sent.map((call) => call.receiverId).join()}`);
    const entries = await readLog();
    assert.ok(entries.every((entry) => entry.contract === TARGET));
  });
});

describe("a retry after a stale nonce is checked like the first attempt", () => {
  /** An honest signer until its `swapAfter`-th signing, then it changes the transaction as `mutate` says. */
  const swapping = (swapAfter: number, mutate: (transaction: Transaction) => void): KeyPairSigner => {
    let signings = 0;
    class Swapper extends KeyPairSigner {
      override async signTransaction(transaction: Transaction): ReturnType<KeyPairSigner["signTransaction"]> {
        signings += 1;
        if (signings > swapAfter) mutate(transaction);
        return super.signTransaction(transaction);
      }
    }
    return new Swapper(KeyPair.fromRandom("ed25519"));
  };

  /** Honest on the first attempt; from the second it reports, and signs with, another key (KeyPairSigner refuses to sign a transaction whose key it does not hold, so the swap is made in `getPublicKey`). */
  const keySwapping = (): KeyPairSigner => {
    const otherPair = KeyPair.fromRandom("ed25519");
    // The chain knows the second key too: near-api-js looks a key up before it builds a transaction with it.
    fake.addKey(AGENT, otherPair.getPublicKey().toString(), "FullAccess");
    const other = new KeyPairSigner(otherPair);
    let swapped = false;
    class KeySwapper extends KeyPairSigner {
      override async getPublicKey(): ReturnType<KeyPairSigner["getPublicKey"]> {
        return swapped ? other.getPublicKey() : super.getPublicKey();
      }
      override async signTransaction(transaction: Transaction): ReturnType<KeyPairSigner["signTransaction"]> {
        const signed = await (swapped ? other : { signTransaction: (t: Transaction) => super.signTransaction(t) }).signTransaction(transaction);
        swapped = true;
        return signed;
      }
    }
    return new KeySwapper(KeyPair.fromRandom("ed25519"));
  };

  async function agentFor(signer: KeyPairSigner, policy: Partial<Policy> = {}): Promise<GuardedAgent> {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), "FullAccess");
    return agentWith(null, { signer, allowFullAccessKey: true }, policy);
  }

  const swaps: [string, () => KeyPairSigner, RegExp][] = [
    ["public key", keySwapping, /public key/],
    ["receiver", () => swapping(1, (t) => { t.receiverId = "drain.test.near"; }), /receiver/],
  ];
  for (const [name, makeSigner, field] of swaps) {
    it(`refuses a retry whose ${name} was swapped: RefusedError, a not_sent line after the sent one, nothing sent, the deposit stays committed`, async () => {
      const agent = await agentFor(makeSigner(), { maxDepositPerCall: nearToYocto("1"), maxTotalDeposit: nearToYocto("1") });
      fake.staleNonces = 1;
      const error = await refusal(agent.guardedCall(request({ deposit: nearToYocto("1") })));
      assert.match(error.message, /differs from the checked request/);
      assert.match(error.message, /a retry after an attempt that was sent/);
      assert.equal(fake.staleNonces, 0, "attempt 1 reached the chain and was answered InvalidNonce");
      assert.deepEqual(fake.sent, [], "attempt 2 never went out");
      const entries = await readLog();
      assert.deepEqual(entries.map((entry) => entry.outcome), ["approved", "sent", "not_sent"]);
      assert.match(entries[2]?.reasons.join() ?? "", field);
      assert.deepEqual(error.entry, entries[2]);
      assert.match((await refusal(agent.guardedCall(request({ deposit: nearToYocto("1") })))).message, /total cap/);
    });
  }

  it("still ends in a RefusedError when the line for the refused retry cannot be written", async () => {
    const agent = await agentFor(swapping(1, (t) => { t.receiverId = "drain.test.near"; }));
    fake.staleNonces = 1;
    // Make every write after the sent line fail: the log path becomes a directory once the first two lines are down.
    const original = DecisionLog.prototype.write;
    let writes = 0;
    DecisionLog.prototype.write = function failing(this: DecisionLog, ...args: Parameters<DecisionLog["write"]>) {
      writes += 1;
      return writes > 2 ? Promise.reject(new Error("disk full")) : original.apply(this, args);
    };
    try {
      const error = await refusal(agent.guardedCall(request()));
      assert.match(error.message, /differs from the checked request/);
      assert.match(error.message, /could not be logged: disk full/);
      assert.deepEqual(fake.sent, []);
    } finally {
      DecisionLog.prototype.write = original;
    }
  });

  it("refuses a swapped transaction on the first attempt with exactly one refusal line", async () => {
    const agent = await agentFor(swapping(0, (t) => { t.receiverId = "drain.test.near"; }));
    const error = await refusal(agent.guardedCall(request()));
    assert.match(error.message, /differs from the checked request/);
    assert.doesNotMatch(error.message, /a retry after/);
    assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["approved", "not_sent"]);
    assert.deepEqual(fake.sent, []);
  });

  it("logs one sent line per attempt for an honest retry, and the call succeeds", async () => {
    const agent = await agentFor(swapping(99, () => undefined));
    fake.staleNonces = 1;
    await agent.guardedCall(request());
    assert.deepEqual((await readLog()).map((entry) => entry.outcome), ["approved", "sent", "sent"]);
    assert.equal(fake.sent.length, 1);
    assert.equal(fake.staleNonces, 0);
  });
});

describe("what the signed bytes must equal, exactly", () => {
  async function through(mutate: (transaction: Transaction) => void): Promise<{ error: unknown }> {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    class Mutating extends KeyPairSigner {
      override async signTransaction(transaction: Transaction): ReturnType<KeyPairSigner["signTransaction"]> {
        mutate(transaction);
        return super.signTransaction(transaction);
      }
    }
    const signer = new Mutating(KeyPair.fromRandom("ed25519"));
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), functionCallKey(TARGET));
    const agent = await agentWith(null, { signer });
    return { error: await agent.guardedCall(request()).then(() => undefined, (e: unknown) => e) };
  }
  const call = (transaction: Transaction) => {
    const action = transaction.actions[0];
    assert.ok(action?.functionCall);
    return action.functionCall;
  };

  it("refuses a gas-key (V1) transaction, which carries a nonce index or mode", async () => {
    for (const mutate of [(t: Transaction) => { t.nonceIndex = 0; }, (t: Transaction) => { t.nonceMode = "monotonic"; }]) {
      await rm(logPath, { force: true });
      const { error } = await through(mutate);
      assert.ok(error instanceof RefusedError, String(error));
      assert.match(error.message, /transaction version/);
      assert.deepEqual(fake.sent, []);
    }
  });

  it("refuses arguments with bytes appended, and arguments cut short", async () => {
    for (const change of [(args: Buffer) => Buffer.concat([args, Buffer.from(" ")]), (args: Buffer) => Buffer.concat([args, Buffer.from(',"extra":1')]), (args: Buffer) => args.subarray(0, args.length - 1)]) {
      await rm(logPath, { force: true });
      const { error } = await through((t) => { call(t).args = new Uint8Array(change(Buffer.from(call(t).args))); });
      assert.ok(error instanceof RefusedError, String(error));
      assert.match(error.message, /arguments/);
      assert.deepEqual(fake.sent, []);
    }
  });

  it("sends the copy it checked when the signer signs differently the second time it is asked within one attempt", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    let signings = 0;
    class Twofaced extends KeyPairSigner {
      override async signTransaction(transaction: Transaction): ReturnType<KeyPairSigner["signTransaction"]> {
        signings += 1;
        if (signings > 1) transaction.receiverId = "drain.test.near";
        return super.signTransaction(transaction);
      }
    }
    const signer = new Twofaced(KeyPair.fromRandom("ed25519"));
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), functionCallKey(TARGET));
    const agent = await agentWith(null, { signer });
    await agent.guardedCall(request());
    assert.equal(signings, 1, "one signing per attempt");
    assert.deepEqual(fake.sent.map((sent) => sent.receiverId), [TARGET]);
  });
});

describe("amounts must fit the width the transaction encoding gives them", () => {
  it("throws a TypeError for gas above 2^64-1 and a deposit above 2^128-1, with nothing logged or queried", async () => {
    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: 2n ** 130n, maxTotalDeposit: 2n ** 130n });
    await assert.rejects(agent.guardedCall(request({ gas: 2n ** 70n })), { name: "TypeError", message: /gas does not fit in 64 bits/ });
    await assert.rejects(agent.guardedCall(request({ gas: 2n ** 64n })), TypeError);
    await assert.rejects(agent.guardedCall(request({ deposit: 2n ** 128n + 7n })), { name: "TypeError", message: /deposit does not fit in 128 bits/ });
    await assert.rejects(agent.guardedCall(request({ deposit: 2n ** 128n })), TypeError);
    assert.equal(await rawLog(), "");
    assert.deepEqual(fake.queries, []);
  });

  it("accepts the largest gas and the largest deposit: the policy, not the width check, decides", async () => {
    fake.accounts.set(TARGET, { wasm: fakeWasm("safe") });
    fake.publish(TARGET, "Safe");
    const capped = await agentWith("FullAccess", { allowFullAccessKey: true });
    const error = await refusal(capped.guardedCall(request({ deposit: 2n ** 128n - 1n })));
    assert.match(error.message, /per-call cap/);

    const agent = await agentWith("FullAccess", { allowFullAccessKey: true }, { maxDepositPerCall: 2n ** 128n - 1n, maxTotalDeposit: 2n ** 128n - 1n });
    await agent.guardedCall(request({ gas: 2n ** 64n - 1n, deposit: 2n ** 128n - 1n }));
    assert.equal(fake.sent[0]?.gas, 2n ** 64n - 1n);
    assert.equal(fake.sent[0]?.deposit, 2n ** 128n - 1n);
  });
});

describe("a refusal cannot be stopped by the clock or the log", () => {
  const revoked = (): object => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  };
  const hostileClocks: [string, () => Date][] = [
    ["toISOString returns a revoked proxy", () => Object.assign(new Date(0), { toISOString: revoked }) as Date],
    ["toISOString returns an object", () => Object.assign(new Date(0), { toISOString: () => ({ nope: true }) }) as unknown as Date],
    ["toISOString throws", () => Object.assign(new Date(0), { toISOString: () => { throw new Error("no"); } }) as Date],
    ["getTime is replaced", () => Object.assign(new Date(0), { getTime: () => 1e99 }) as Date],
    ["the clock returns a revoked proxy", () => revoked() as Date],
  ];
  for (const [name, now] of hostileClocks) {
    it(`${name}: one refused line with a real timestamp`, async () => {
      const agent = await agentWith(null, { now });
      const error = await refusal(agent.guardedCall(request({ contractId: "other.test.near" })));
      const lines = await readLog();
      assert.equal(lines.length, 1);
      assert.equal(typeof lines[0]?.timestamp, "string");
      assert.match(lines[0]?.timestamp ?? "", /^\d{4}-\d\d-\d\dT[\d:.]+Z$/);
      assert.deepEqual(error.entry, lines[0]);
    });
  }

  it("uses the clock's own time when the clock is a Date whose toISOString lies", async () => {
    const date = Object.assign(new Date("2026-11-14T12:00:00.000Z"), { toISOString: () => "not a time" });
    const agent = await agentWith(null, { now: () => date });
    await refusal(agent.guardedCall(request({ contractId: "other.test.near" })));
    assert.equal((await readLog())[0]?.timestamp, "2026-11-14T12:00:00.000Z");
  });

  it("still throws a RefusedError, and logs the refusal, when building the log entry itself fails", async () => {
    const original = DecisionLog.prototype.entry;
    let calls = 0;
    DecisionLog.prototype.entry = function failing(this: DecisionLog, ...args: Parameters<DecisionLog["entry"]>) {
      calls += 1;
      if (calls === 1) throw new Error("entry exploded");
      return original.apply(this, args);
    };
    try {
      const agent = await agentWith(null);
      const error = await refusal(agent.guardedCall(request({ contractId: "other.test.near" })));
      assert.equal(error.entry.outcome, "refused");
      assert.match(error.entry.reasons.join(), /could not be logged: entry exploded/);
      assert.equal((await readLog()).length, 1);
    } finally {
      DecisionLog.prototype.entry = original;
    }
  });

  it("still throws a RefusedError when even the fallback write fails", async () => {
    const original = DecisionLog.prototype.entry;
    DecisionLog.prototype.entry = function failing() {
      throw new Error("entry exploded");
    };
    try {
      const agent = await agentWith(null, { logPath: join(dir, "missing-dir", "log.jsonl") });
      const error = await refusal(agent.guardedCall(request({ contractId: "other.test.near" })));
      assert.equal(error.entry.outcome, "refused");
    } finally {
      DecisionLog.prototype.entry = original;
    }
  });
});
