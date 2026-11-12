import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it, mock } from "node:test";
import { KeyPair, KeyPairSigner, teraToGas } from "near-api-js";
import { checkContract, codeHashOf, CodePins, describeMutability, GuardedAgent, MUTABILITY_LIMITS, readMutability, RefusedError, type GuardConfig, type GuardedAgentOptions } from "../src/index.ts";
import { stricter } from "../src/mutability.ts";
import { FakeNear, fakeWasm, type KeyPermission } from "../testkit/fake-rpc.ts";
import { makeTempDir } from "../testkit/tempdir.ts";

const REGISTRY = "registry.test.near";
const TARGET = "escrow.test.near";
const AGENT = "agent.test.near";
const WASM = fakeWasm("v1");
const HASH = codeHashOf(WASM);
const SWAPPED = fakeWasm("v2");
const SWAPPED_HASH = codeHashOf(SWAPPED);
const KEY_A = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";
const KEY_B = "ed25519:3tysLvy7KGoE8pznUgXvSHa4vYyGvrDZFcT8jgb8PEQ6";
const CALL_KEY: KeyPermission = { FunctionCall: { allowance: "250000000000000000000000", receiver_id: TARGET, method_names: [] } };

let fake: FakeNear;
let rpcUrl: string;
let dir: string;
let config: GuardConfig;

beforeEach(async () => {
  fake = new FakeNear(REGISTRY);
  rpcUrl = await fake.start();
  dir = await makeTempDir("mutability-test");
  fake.accounts.set(TARGET, { wasm: WASM });
  config = { rpcUrl, registryId: REGISTRY, timeoutMs: 2_000, mutability: {} };
});
afterEach(async () => {
  for (const pins of openStores.splice(0)) pins.close();
  await fake.stop();
  await rm(dir, { recursive: true, force: true });
});

/** A file-backed store whose next write fails: a directory sits where the file goes, so the rename onto it is refused. */
async function unsavablePins(): Promise<CodePins> {
  const path = join(dir, "pins.json");
  const pins = await CodePins.open(path);
  openStores.push(pins);
  await mkdir(path);
  return pins;
}

/** File-backed stores a test opened: closed after it, so their lock files do not outlive it. */
const openStores: CodePins[] = [];
async function openPins(path?: string): Promise<CodePins> {
  const pins = await CodePins.open(path);
  openStores.push(pins);
  return pins;
}

const KEY_FACT = /can be replaced by a key holder at any time/;

describe("the key fact on code with no registry verdict", () => {
  it("says a key holder can replace the code, and how many keys there are, and keeps the warn", async () => {
    fake.addKey(TARGET, KEY_A, "FullAccess");
    fake.addKey(TARGET, KEY_B, "FullAccess");
    fake.addKey(TARGET, "ed25519:11111111111111111111111111111111", CALL_KEY);
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "warn");
    assert.equal(result.codeHash, HASH);
    assert.match(result.reasons[0] ?? "", /no verdict in the registry/);
    assert.match(result.reasons[1] ?? "", /code at this address can be replaced by a key holder at any time \(2 full-access keys\)/);
    assert.equal(result.reasons[2], "the guard cannot see whether the contract upgrades itself through a method");
  });

  it("uses the singular for one key", async () => {
    fake.addKey(TARGET, KEY_A, "FullAccess");
    assert.match((await checkContract(TARGET, config)).reasons[1] ?? "", /\(1 full-access key\)/);
  });

  it("with no full-access key says so for this account, and that a method still might replace the code", async () => {
    fake.addKey(TARGET, KEY_A, CALL_KEY);
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "warn");
    assert.doesNotMatch(result.reasons.join(), KEY_FACT);
    assert.match(result.reasons[1] ?? "", /^no full-access key on this account, so no key holder can deploy new code to it$/);
    assert.match(result.reasons[2] ?? "", /upgrades itself through a method/);
  });

  it("names the publisher of a global contract followed by publisher id, who can replace it whatever the keys", async () => {
    fake.accounts.set(TARGET, { wasm: WASM, globalPublisher: "publisher.test.near" });
    const result = await checkContract(TARGET, config);
    assert.match(result.reasons[1] ?? "", /global contract published by publisher\.test\.near, who can replace it at any time; no full-access key on this account$/);
    assert.doesNotMatch(result.reasons[1] ?? "", /no key holder/, "the publisher can replace it, so no sentence may say nobody can");
  });

  it("is silent about keys when the registry has a verdict: the audit answers, and no extra read is made", async () => {
    fake.addKey(TARGET, KEY_A, "FullAccess");
    fake.publish(TARGET, "Safe");
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "allow");
    assert.equal(result.reasons.length, 1);
    assert.ok(!fake.queries.includes("view_access_key_list"));
  });

  it("is off by default: no key read, the reasons are the registry's alone", async () => {
    fake.addKey(TARGET, KEY_A, "FullAccess");
    const { mutability: _off, ...plain } = config;
    const result = await checkContract(TARGET, plain);
    assert.equal(result.decision, "warn");
    assert.equal(result.reasons.length, 1);
    assert.ok(!fake.queries.includes("view_access_key_list"));
  });

  it("reads the key list at the optimistic head, like the rest of the check", async () => {
    await checkContract(TARGET, config);
    const index = fake.queries.indexOf("view_access_key_list");
    assert.equal(fake.queryParams[index]?.["finality"], "optimistic");
  });

  it("blocks when the key list cannot be read: an answer that is missing is never an allow", async () => {
    fake.faults.set("view_access_key_list", { kind: "http", status: 500 });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /could not verify/);
  });

  it("blocks on a key with a permission it does not know, and on a list that is not a list", async () => {
    const answer = (keys: unknown) => ({ kind: "json", body: { jsonrpc: "2.0", result: { block_hash: "x", block_height: 1, keys }, id: "dontcare" } }) as const;
    fake.faults.set("view_access_key_list", answer([{ public_key: KEY_A, access_key: { nonce: 0, permission: { SomethingNew: {} } } }]));
    assert.equal((await checkContract(TARGET, config)).decision, "block");
    fake.faults.set("view_access_key_list", answer("none"));
    assert.equal((await checkContract(TARGET, config)).decision, "block");
  });

  it("blocks a key list the node says it cut short (last_key set), and accepts an explicit null", async () => {
    const answer = (extra: Record<string, unknown>) => ({ kind: "json", body: { jsonrpc: "2.0", result: { block_hash: "x", block_height: 1, keys: [], ...extra }, id: "dontcare" } }) as const;
    fake.faults.set("view_access_key_list", answer({ last_key: "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp" }));
    const partial = await checkContract(TARGET, config);
    assert.equal(partial.decision, "block");
    assert.match(partial.reasons.join(), /partial list/);
    fake.faults.set("view_access_key_list", answer({ last_key: null }));
    assert.equal((await checkContract(TARGET, config)).decision, "warn");
  });

  it("never lowers a block", async () => {
    fake.publish(TARGET, "Unsafe", ["PF001"]);
    assert.equal((await checkContract(TARGET, config)).decision, "block");
  });
});

describe("a setting or a decision the guard does not know never reads as the milder one", () => {
  it("stricter picks the stricter of two decisions and throws on anything that is not one", () => {
    assert.equal(stricter("allow", "warn"), "warn");
    assert.equal(stricter("warn", "allow"), "warn");
    assert.equal(stricter("block", "warn"), "block");
    assert.equal(stricter("warn", "warn"), "warn");
    assert.throws(() => stricter("allow", "Block" as never), TypeError);
    assert.throws(() => stricter("Block" as never, "allow"), TypeError);
    assert.throws(() => stricter("allow", undefined as never), TypeError);
  });

  it("checkContract throws for an onCodeChange that is neither warn nor block, and leaves the pin alone", async () => {
    const pins = await openPins();
    fake.publish(TARGET, "Safe");
    await pins.set(TARGET, HASH, undefined);
    fake.accounts.set(TARGET, { wasm: SWAPPED });
    fake.publish(TARGET, "Safe");
    for (const onCodeChange of ["Block", "allow", "", null]) {
      await assert.rejects(checkContract(TARGET, { ...config, mutability: { pins, onCodeChange } as never }), /onCodeChange must be "warn" or "block"/);
    }
    assert.equal(pins.get(TARGET), HASH, "the swapped code was not pinned");
  });

  it("checkContract throws for pins that are not a CodePins and a mutability that is not an object", async () => {
    await assert.rejects(checkContract(TARGET, { ...config, mutability: { pins: new Map() } as never }), /must be a CodePins/);
    await assert.rejects(checkContract(TARGET, { ...config, mutability: null as never }), /must be an object/);
    await assert.rejects(checkContract(TARGET, { ...config, mutability: "block" as never }), /must be an object/);
  });

  it("reads the setting once: a getter that answers differently the second time cannot loosen it", async () => {
    const pins = await openPins();
    await pins.set(TARGET, HASH, undefined);
    fake.accounts.set(TARGET, { wasm: SWAPPED });
    let reads = 0;
    const mutability = { pins, get onCodeChange() { return reads++ === 0 ? "block" : "warn"; } } as unknown as GuardConfig["mutability"];
    assert.equal((await checkContract(TARGET, { ...config, mutability })).decision, "block");
  });
});

describe("one process per pin file", () => {
  it("refuses a second open of a file store that is open, and opens it again once the first is closed", async () => {
    const path = join(dir, "pins.json");
    const first = await openPins(path);
    await assert.rejects(CodePins.open(path), new RegExp(`pin file lock .* is held by process ${process.pid}: one process per pin file`));
    first.close();
    first.close();
    await readFile(`${path}.lock`).then(() => assert.fail("the lock file should be gone"), () => undefined);
    await openPins(path);
  });

  it("replaces the lock of a process that is gone, and refuses one it cannot read", async () => {
    const path = join(dir, "pins.json");
    const gone = spawnSync(process.execPath, ["-e", ""]).pid;
    await writeFile(`${path}.lock`, `${gone}\n`);
    const pins = await openPins(path);
    assert.equal((await readFile(`${path}.lock`, "utf8")).trim(), String(process.pid));
    pins.close();
    await writeFile(`${path}.lock`, "garbage");
    await assert.rejects(CodePins.open(path), /is held: one process per pin file/);
  });

  it("does not leave a stale lock or a temp file when the file cannot be read or written", async () => {
    const path = join(dir, "pins.json");
    await writeFile(path, "not json");
    await assert.rejects(CodePins.open(path), /not valid JSON/);
    assert.ok(!(await readdir(dir)).some((name) => name.endsWith(".lock")), "a failed open releases its lock");
    await rm(path);
    const pins = await unsavablePins();
    await assert.rejects(pins.set(TARGET, HASH, undefined), /could not save the code pin/);
    assert.ok(!(await readdir(dir)).some((name) => name.endsWith(".tmp")), "a failed write removes its temp file");
  });

  it("writes through a temp file named for this process, never a fixed name two processes would share", async () => {
    const path = join(dir, "pins.json");
    const pins = await openPins(path);
    const seen: string[] = [];
    const watcher = setInterval(() => void readdir(dir).then((names) => seen.push(...names.filter((name) => name.endsWith(".tmp")))), 0);
    await Promise.all(Array.from({ length: 20 }, (_, n) => pins.set(`a${n}.test.near`, HASH, undefined)));
    clearInterval(watcher);
    assert.ok(seen.every((name) => name.includes(`.${process.pid}.`) && name !== "pins.json.tmp"), seen.join());
    assert.equal(Object.keys(JSON.parse(await readFile(path, "utf8")) as object).length, 20);
  });
});

describe("a pin moves only from the value the caller read", () => {
  it("throws when the pin moved since it was read, and keeps what is there", async () => {
    const pins = await openPins();
    await pins.set(TARGET, HASH, undefined);
    await assert.rejects(pins.set(TARGET, SWAPPED_HASH, undefined), /changed while it was being checked/);
    await assert.rejects(pins.set(TARGET, SWAPPED_HASH, SWAPPED_HASH), /changed while it was being checked/);
    assert.equal(pins.get(TARGET), HASH);
    await pins.set(TARGET, SWAPPED_HASH, HASH);
    assert.equal(pins.get(TARGET), SWAPPED_HASH);
    await pins.set(TARGET, SWAPPED_HASH, undefined);
  });

  it("lets only one of two concurrent first pins win", async () => {
    const pins = await openPins(join(dir, "pins.json"));
    const outcomes = await Promise.allSettled([pins.set(TARGET, HASH, undefined), pins.set(TARGET, SWAPPED_HASH, undefined)]);
    assert.deepEqual(outcomes.map((outcome) => outcome.status), ["fulfilled", "rejected"]);
    assert.equal(pins.get(TARGET), HASH);
    assert.equal(JSON.parse(await readFile(join(dir, "pins.json"), "utf8"))[TARGET], HASH);
  });

  it("checkContract blocks, rather than overwrite, a pin another check set between its read and its write", async () => {
    const pins = await openPins();
    fake.publish(TARGET, "Safe");
    const original = pins.set.bind(pins);
    let raced = false;
    mock.method(pins, "set", async (id: string, hash: string, expected: string | undefined) => {
      if (!raced) {
        raced = true;
        await original(id, SWAPPED_HASH, undefined);
      }
      return original(id, hash, expected);
    });
    const result = await checkContract(TARGET, { ...config, mutability: { pins } });
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /changed while it was being checked/);
    assert.equal(pins.get(TARGET), SWAPPED_HASH);
  });
});

describe("a failed save says nothing about the file system to the caller", () => {
  it("keeps the path out of the reasons of a check and of a refused call, and puts the detail on stderr", async () => {
    const pins = await unsavablePins();
    fake.publish(TARGET, "Safe");
    const stderr = mock.method(console, "error", () => undefined);
    try {
      const result = await checkContract(TARGET, { ...config, mutability: { pins } });
      assert.equal(result.decision, "block");
      assert.ok(result.reasons.includes(`could not save the code pin for ${TARGET}`), result.reasons.join());
      assert.ok(!result.reasons.join().includes(dir), "no path in the reasons");
      assert.match(String(stderr.mock.calls[0]?.arguments[0]), new RegExp(`could not save the code pin for ${TARGET} to ${dir}`));
    } finally {
      stderr.mock.restore();
    }
  });
});

describe("pinning the code hash at first allow", () => {
  let pins: CodePins;
  beforeEach(async () => {
    pins = await openPins();
    config = { ...config, mutability: { pins } };
    fake.publish(TARGET, "Safe");
  });

  it("remembers the hash at the first allow and allows the same code again", async () => {
    assert.equal(pins.get(TARGET), undefined);
    assert.equal((await checkContract(TARGET, config)).decision, "allow");
    assert.equal(pins.get(TARGET), HASH);
    assert.equal((await checkContract(TARGET, config)).decision, "allow");
  });

  it("warns, naming both hashes, when the code differs from the pin, even if the new code has a Safe verdict", async () => {
    await checkContract(TARGET, config);
    fake.accounts.set(TARGET, { wasm: SWAPPED });
    fake.publish(TARGET, "Safe");
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "warn");
    assert.match(result.reasons.join(), new RegExp(`code changed since you last approved it: approved hash ${HASH}, hash now ${SWAPPED_HASH}`));
    assert.equal(pins.get(TARGET), HASH, "a warn does not move the pin");
  });

  it("blocks instead when the owner chose block", async () => {
    await checkContract(TARGET, config);
    fake.accounts.set(TARGET, { wasm: SWAPPED });
    const result = await checkContract(TARGET, { ...config, mutability: { pins, onCodeChange: "block" } });
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /code changed since you last approved it/);
  });

  it("needs no auditor: unaudited code that was approved once is held when it changes", async () => {
    fake.verdicts.clear();
    await pins.set(TARGET, HASH, undefined);
    fake.accounts.set(TARGET, { wasm: SWAPPED });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "warn");
    assert.match(result.reasons.join(), /no verdict in the registry/);
    assert.match(result.reasons.join(), /code changed since you last approved it/);
  });

  it("does not pin a warn, a block or an account with no code", async () => {
    fake.verdicts.clear();
    await checkContract(TARGET, config);
    fake.publish(TARGET, "Unsafe", ["PF001"]);
    await checkContract(TARGET, config);
    fake.accounts.set("plain.test.near", {});
    await checkContract("plain.test.near", config);
    assert.equal(pins.get(TARGET), undefined);
    assert.equal(pins.get("plain.test.near"), undefined);
  });

  it("blocks an allow whose pin cannot be saved", async () => {
    const unsaved = await unsavablePins();
    const result = await checkContract(TARGET, { ...config, mutability: { pins: unsaved } });
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /could not save the code pin/);
    assert.equal(unsaved.get(TARGET), undefined);
  });
});

describe("the pin file", () => {
  it("keeps pins across a restart, and a missing file is an empty store", async () => {
    const path = join(dir, "nested", "pins.json");
    const first = await openPins(path);
    assert.equal(first.get(TARGET), undefined);
    await first.set(TARGET, HASH, undefined);
    assert.deepEqual(JSON.parse(await readFile(path, "utf8")), { [TARGET]: HASH });
    first.close();
    assert.equal((await openPins(path)).get(TARGET), HASH);
  });

  it("serializes writes: concurrent pins all reach the file", async () => {
    const path = join(dir, "pins.json");
    const pins = await openPins(path);
    await Promise.all([pins.set("a.test.near", HASH, undefined), pins.set("b.test.near", SWAPPED_HASH, undefined), pins.set("c.test.near", HASH, undefined)]);
    assert.deepEqual(Object.keys(JSON.parse(await readFile(path, "utf8")) as object).sort(), ["a.test.near", "b.test.near", "c.test.near"]);
  });

  it("refuses to open a file that is not what it writes, rather than read it as empty", async () => {
    const path = join(dir, "pins.json");
    for (const text of ["not json", "[]", JSON.stringify({ [TARGET]: "short" }), JSON.stringify({ "Bad Id": HASH }), JSON.stringify({ [TARGET]: 7 })]) {
      await writeFile(path, text);
      await assert.rejects(openPins(path), /pin file/);
    }
  });

  it("only takes an account id and a code hash", async () => {
    const pins = await openPins();
    await assert.rejects(pins.set("Bad Id", HASH, undefined), TypeError);
    await assert.rejects(pins.set(TARGET, "short", undefined), TypeError);
  });
});

describe("readMutability", () => {
  it("returns the code hash and the full-access key count, and describes what it cannot show", async () => {
    fake.addKey(TARGET, KEY_A, "FullAccess");
    fake.addKey(TARGET, KEY_B, CALL_KEY);
    const facts = await readMutability(TARGET, config);
    assert.deepEqual(facts, { accountId: TARGET, codeHash: HASH, globalPublisher: null, fullAccessKeys: 1 });
    const text = describeMutability(facts!);
    assert.match(text, /^Code at this address can be replaced by a key holder at any time \(1 full-access key\)\./);
    assert.ok(text.endsWith(MUTABILITY_LIMITS));
    assert.match(MUTABILITY_LIMITS, /upgrade itself through one of its own methods/);
    assert.match(MUTABILITY_LIMITS, /when the code last changed/);
  });

  it("reports zero keys without claiming the code is fixed", async () => {
    const facts = await readMutability(TARGET, config);
    assert.equal(facts?.fullAccessKeys, 0);
    assert.match(describeMutability(facts!), /^No full-access key on this account, so no key holder can deploy new code to it\. Not established: whether the contract can upgrade itself/);
  });

  it("reads no code: only the account and its keys", async () => {
    await readMutability(TARGET, config);
    assert.deepEqual(fake.queries, ["view_account", "view_access_key_list"]);
  });

  it("returns null for an account that does not exist and throws for one the node cannot answer about", async () => {
    assert.equal(await readMutability("ghost.test.near", config), null);
    fake.faults.set("view_access_key_list", { kind: "http", status: 500 });
    await assert.rejects(readMutability(TARGET, config), /HTTP 500/);
  });

  it("reports the code hash a global contract resolves to", async () => {
    fake.accounts.set(TARGET, { wasm: WASM, globalCodeHash: HASH });
    assert.equal((await readMutability(TARGET, config))?.codeHash, HASH);
  });

  it("says a publisher-followed account names no hash, and still names the publisher", async () => {
    fake.accounts.set(TARGET, { wasm: WASM, globalPublisher: "publisher.test.near" });
    const facts = await readMutability(TARGET, config);
    assert.deepEqual(facts, { accountId: TARGET, codeHash: null, globalPublisher: "publisher.test.near", fullAccessKeys: 0 });
    const text = describeMutability(facts!);
    assert.match(text, /^Code at this address is the global contract published by publisher\.test\.near, who can replace it at any time; no full-access key on this account\. Not established/);
    assert.doesNotMatch(text, /no key holder/);
  });

  it("rejects an invalid account id before any request", async () => {
    await assert.rejects(readMutability("Bad Id", config), TypeError);
    assert.deepEqual(fake.queries, []);
  });
});

describe("GuardedAgent with mutability on", () => {
  let logPath: string;
  beforeEach(() => {
    logPath = join(dir, "decisions.jsonl");
  });

  async function agent(guard: GuardConfig, approve?: GuardedAgentOptions["approve"]): Promise<GuardedAgent> {
    const signer = new KeyPairSigner(KeyPair.fromRandom("ed25519"));
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), CALL_KEY);
    return new GuardedAgent({ accountId: AGENT, signer, guard, policy: { allowedContracts: [TARGET], maxDepositPerCall: 0n, maxTotalDeposit: 0n }, logPath, ...(approve !== undefined && { approve }) });
  }
  const call = { contractId: TARGET, method: "release", args: {}, deposit: 0n, gas: teraToGas("30") } as const;

  it("carries the key fact into the warn the approver sees, and logs it", async () => {
    fake.addKey(TARGET, KEY_A, "FullAccess");
    let shown: readonly string[] = [];
    const guarded = await agent(config, (_request, guard) => ((shown = guard.reasons), true));
    const result = await guarded.guardedCall(call);
    assert.equal(result.guard.decision, "warn");
    assert.match(shown.join(), KEY_FACT);
    assert.match(await readFile(logPath, "utf8"), /can be replaced by a key holder at any time/);
  });

  it("pins what it signs for: an approved warn pins the hash, and a later change is refused without an approver", async () => {
    const pins = await openPins();
    const guard = { ...config, mutability: { pins } };
    await (await agent(guard, () => true)).guardedCall(call);
    assert.equal(pins.get(TARGET), HASH);
    fake.accounts.set(TARGET, { wasm: SWAPPED });
    fake.publish(TARGET, "Safe");
    const sentBefore = fake.sent.length;
    const error = await (await agent(guard)).guardedCall(call).then(() => undefined, (e: unknown) => e);
    assert.ok(error instanceof RefusedError);
    assert.equal(error.entry.decision, "warn");
    assert.match(error.entry.reasons.join(), /code changed since you last approved it/);
    assert.equal(fake.sent.length, sentBefore);
  });

  it("re-pins the new code once the approver accepts the change", async () => {
    const pins = await openPins();
    await pins.set(TARGET, HASH, undefined);
    fake.accounts.set(TARGET, { wasm: SWAPPED });
    await (await agent({ ...config, mutability: { pins } }, () => true)).guardedCall(call);
    assert.equal(pins.get(TARGET), SWAPPED_HASH);
  });

  it("blocks without asking anyone when the owner chose block", async () => {
    const pins = await openPins();
    await pins.set(TARGET, HASH, undefined);
    fake.accounts.set(TARGET, { wasm: SWAPPED });
    let asked = false;
    const guarded = await agent({ ...config, mutability: { pins, onCodeChange: "block" } }, () => ((asked = true), true));
    const error = await guarded.guardedCall(call).then(() => undefined, (e: unknown) => e);
    assert.ok(error instanceof RefusedError);
    assert.equal(error.entry.decision, "block");
    assert.equal(asked, false);
  });

  it("signs nothing when the pin moved between the read and the approval", async () => {
    const pins = await openPins();
    const original = pins.set.bind(pins);
    mock.method(pins, "set", async (id: string, hash: string, expected: string | undefined) => {
      await original(id, SWAPPED_HASH, undefined);
      return original(id, hash, expected);
    });
    const error = await (await agent({ ...config, mutability: { pins } }, () => true)).guardedCall(call).then(() => undefined, (e: unknown) => e);
    assert.ok(error instanceof RefusedError);
    assert.match(error.message, /changed while it was being checked/);
    assert.equal(fake.sent.length, 0);
  });

  it("signs nothing when the pin cannot be saved", async () => {
    const pins = await unsavablePins();
    const stderr = mock.method(console, "error", () => undefined);
    const error = await (await agent({ ...config, mutability: { pins } }, () => true)).guardedCall(call).then(() => undefined, (e: unknown) => e).finally(() => stderr.mock.restore());
    assert.ok(error instanceof RefusedError);
    assert.match(error.message, /the guard failed before signing: could not save the code pin for/);
    assert.ok(!error.message.includes(dir), "no path in what a caller reads");
    assert.equal(fake.sent.length, 0);
  });

  it("rejects a mutability setting it would misread, and keeps its own copy of the one it was given", async () => {
    const make = (mutability: unknown) => agent({ ...config, mutability: mutability as GuardConfig["mutability"] & object });
    await assert.rejects(make({ onCodeChange: "allow" }), /onCodeChange/);
    await assert.rejects(make({ pins: new Map() }), /CodePins/);
    await assert.rejects(make(null), /must be an object/);
    const pins = await openPins();
    await pins.set(TARGET, HASH, undefined);
    fake.accounts.set(TARGET, { wasm: SWAPPED });
    const mutability: { pins: CodePins; onCodeChange: "warn" | "block" } = { pins, onCodeChange: "block" };
    const guarded = await agent({ ...config, mutability });
    mutability.onCodeChange = "warn";
    const error = await guarded.guardedCall(call).then(() => undefined, (e: unknown) => e);
    assert.ok(error instanceof RefusedError);
    assert.equal(error.entry.decision, "block");
  });
});
