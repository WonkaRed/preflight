import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";
import { rpcQuery } from "../src/rpc.ts";
import { checkContract, codeHashOf, isValidAccountId, type GuardConfig } from "../src/index.ts";
import { FakeNear, fakeWasm } from "../testkit/fake-rpc.ts";

const REGISTRY = "registry.test.near";
const TARGET = "escrow.test.near";

// SHA-256 then base58, computed with an independent implementation (Python hashlib + a hand-written base58).
const HASH_OF_EMPTY = "GKot5hBsd81kMupNCXHaqbhv3huEbxAFMLnpcX2hniwn";
const WASM_A = fakeWasm("a");
const HASH_OF_WASM_A = "Bvocsc7xBZmcjwLLNJbLBJpvV5SqcWKsT6fNZZGKySTj";
const OTHER_HASH = "AwLEfgaHQguPVVLGUV9Sf5QKGrMMMr2N6MVSjBj9dJAh"; // hash of the stand-in wasm with no label

let fake: FakeNear;
let config: GuardConfig;

beforeEach(async () => {
  fake = new FakeNear(REGISTRY);
  config = { rpcUrl: await fake.start(), registryId: REGISTRY, timeoutMs: 2_000 };
});
afterEach(async () => {
  await fake.stop();
});

const BLOCK = "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW";

/** Makes the registry answer `get_verdict` with exactly this JSON, whatever the fake chain knows. */
function serveRegistryAnswer(answer: unknown): void {
  fake.faults.set("call_function", { kind: "json", body: { jsonrpc: "2.0", result: { block_height: 1, block_hash: BLOCK, logs: [], result: [...Buffer.from(JSON.stringify(answer))] }, id: "dontcare" } });
}

const validVerdict = (codeHash: string): Record<string, unknown> => ({
  code_hash: codeHash,
  status: "Unsafe",
  rule_ids: ["PF001", "PF004"],
  report_url: "https://preflight.invalid/reports/a.json",
  report_sha256: "ab".repeat(32),
  auditor: "auditor.test.near",
  published_at_ms: "1762790400000",
});

describe("hashing", () => {
  it("hashes bytes to base58 SHA-256, the form RPC reports as code_hash", () => {
    assert.equal(codeHashOf(new Uint8Array()), HASH_OF_EMPTY);
    assert.equal(codeHashOf(WASM_A), HASH_OF_WASM_A);
  });
});

describe("decision table", () => {
  it("allows code with a Safe verdict", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.publish(TARGET, "Safe");
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "allow");
    assert.equal(result.codeHash, HASH_OF_WASM_A);
    assert.equal(result.verdict?.status, "Safe");
    assert.match(result.reasons.join(), /Safe/);
  });

  it("blocks code with an Unsafe verdict and names the rules", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.publish(TARGET, "Unsafe", ["PF004"]);
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.deepEqual(result.verdict?.rule_ids, ["PF004"]);
    assert.match(result.reasons.join(), /Unsafe \(PF004\)/);
  });

  it("warns on a Warn verdict", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.publish(TARGET, "Warn", ["PF003"]);
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "warn");
    assert.equal(result.verdict?.status, "Warn");
  });

  it("warns when the registry has no verdict for the code (registry returns null)", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "warn");
    assert.equal(result.verdict, null);
    assert.equal(result.codeHash, HASH_OF_WASM_A);
    assert.match(result.reasons.join(), /no verdict/);
  });

  it("warns when the code was swapped after its audit: the audited hash no longer matches", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    const audited = fake.publish(TARGET, "Safe");
    assert.equal((await checkContract(TARGET, config)).decision, "allow");

    fake.accounts.set(TARGET, { wasm: fakeWasm("a, redeployed with a backdoor") });
    const after = await checkContract(TARGET, config);
    assert.equal(after.decision, "warn");
    assert.notEqual(after.codeHash, audited);
    assert.equal(after.verdict, null);
  });

  it("allows an account without contract code and never asks the registry", async () => {
    fake.accounts.set("wallet.test.near", {});
    const result = await checkContract("wallet.test.near", config);
    assert.equal(result.decision, "allow");
    assert.equal(result.codeHash, null);
    assert.deepEqual(fake.queries, ["view_account", "view_code"]);
  });

  it("allows an account that does not exist (nothing to audit)", async () => {
    const result = await checkContract("nobody.test.near", config);
    assert.equal(result.decision, "allow");
    assert.equal(result.codeHash, null);
  });
});

describe("global contracts", () => {
  it("resolves a global contract by code hash and checks the wasm view_code returns", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A, globalCodeHash: HASH_OF_WASM_A });
    fake.publish(TARGET, "Unsafe", ["PF001"]);
    // A generous timeout: this test must fail on the decision, never on a slow CI box.
    const result = await checkContract(TARGET, { ...config, timeoutMs: 10_000 });
    assert.equal(result.decision, "block");
    assert.equal(result.codeHash, HASH_OF_WASM_A);
    assert.equal(result.verdict?.status, "Unsafe");
    assert.match(result.reasons.join(), /registry verdict Unsafe \(PF001\)/);
    assert.deepEqual(fake.queries, ["view_account", "view_code", "call_function"]);
  });

  it("blocks an account that reports both a real local code_hash and a global contract", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.publish(TARGET, "Safe");
    fake.faults.set("view_account", { kind: "json", body: { jsonrpc: "2.0", result: { amount: "1", block_height: 1, block_hash: BLOCK, code_hash: HASH_OF_WASM_A, locked: "0", storage_usage: 1, global_contract_account_id: "publisher.test.near" }, id: "dontcare" } });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /both a local code_hash and a global contract/);
  });

  it("blocks when view_code serves bytes that do not match the account's global_contract_hash", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A, globalCodeHash: OTHER_HASH });
    fake.publish(TARGET, "Safe");
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /account's code hash/);
  });

  it("resolves a global contract by publisher account, whose view_account code_hash is the all-zero hash", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A, globalPublisher: "publisher.test.near" });
    fake.publish(TARGET, "Safe");
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "allow");
    assert.equal(result.codeHash, HASH_OF_WASM_A);
  });
});

describe("what view_account says about global contracts never decides that there is no code", () => {
  const ZERO = "11111111111111111111111111111111";
  const viewAccount = (extra: Record<string, unknown>) => ({
    kind: "json" as const,
    body: { jsonrpc: "2.0", result: { amount: "1", block_hash: "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW", block_height: 187440904, code_hash: ZERO, locked: "0", storage_usage: 410, ...extra }, id: "dontcare" },
  });

  it("blocks a global_contract_hash that is not a string, even with the all-zero code_hash", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    for (const bad of [123, { hash: "x" }, true]) {
      fake.faults.set("view_account", viewAccount({ global_contract_hash: bad }));
      const result = await checkContract(TARGET, config);
      assert.equal(result.decision, "block", JSON.stringify(bad));
      assert.match(result.reasons.join(), /global_contract_hash/);
    }
  });

  it("blocks a global_contract_account_id that is not a string", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    for (const bad of [7, ["a.test.near"], {}]) {
      fake.faults.set("view_account", viewAccount({ global_contract_account_id: bad }));
      const result = await checkContract(TARGET, config);
      assert.equal(result.decision, "block", JSON.stringify(bad));
      assert.match(result.reasons.join(), /global_contract_account_id/);
    }
  });

  it("reads the code and applies the registry when view_account has the zero hash and no global fields (older node, typed proxy)", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.faults.set("view_account", viewAccount({}));
    const unaudited = await checkContract(TARGET, config);
    assert.equal(unaudited.decision, "warn");
    assert.equal(unaudited.codeHash, HASH_OF_WASM_A);
    fake.publish(TARGET, "Unsafe", ["PF001"]);
    assert.equal((await checkContract(TARGET, config)).decision, "block");
    assert.ok(fake.queries.includes("view_code"));
  });

  it("accepts explicit nulls for the global fields", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.publish(TARGET, "Safe");
    fake.faults.set("view_account", viewAccount({ global_contract_hash: null, global_contract_account_id: null, code_hash: HASH_OF_WASM_A }));
    assert.equal((await checkContract(TARGET, config)).decision, "allow");
  });
});

describe("fails closed", () => {
  it("blocks when the RPC is unreachable", async () => {
    // The connection is dropped on a port this test still holds: a stopped server's port could be handed to a parallel test's server.
    fake.faults.set("view_account", { kind: "drop" });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.equal(result.codeHash, null);
    assert.match(result.reasons[0] ?? "", /could not verify/);
  });

  it("blocks on an RPC timeout", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.faults.set("view_code", { kind: "hang" });
    const result = await checkContract(TARGET, { ...config, timeoutMs: 150 });
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /no answer within 150 ms/);
  });

  it("blocks on an HTTP error status", async () => {
    fake.faults.set("view_account", { kind: "http", status: 502 });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /HTTP 502/);
  });

  it("backs off and retries a query the node rate limits with HTTP 429, then answers from the chain", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.publish(TARGET, "Safe");
    fake.faults.set("view_account", { kind: "http", status: 429, times: 2 });
    const started = Date.now();
    const result = await checkContract(TARGET, { ...config, rateLimitBackoffMs: [40, 80] });
    assert.equal(result.decision, "allow");
    assert.equal(fake.queries.filter((type) => type === "view_account").length, 3, "two throttled attempts and the one that answered");
    assert.ok(Date.now() - started >= 100, "it waited 40 ms and 80 ms between the attempts, not a retry storm");
  });

  it("blocks when the node is still rate limiting after the last backoff, and says so", async () => {
    fake.faults.set("view_account", { kind: "http", status: 429 });
    const result = await checkContract(TARGET, { ...config, rateLimitBackoffMs: [5, 5, 5] });
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /HTTP 429 \(rate limited, still after 3 retries\)/);
    assert.equal(fake.queries.filter((type) => type === "view_account").length, 4);
  });

  it("does not retry other HTTP errors, and a backoff of [] turns the retry off", async () => {
    for (const status of [500, 502, 503]) {
      fake.queries.length = 0;
      fake.faults.set("view_account", { kind: "http", status });
      assert.equal((await checkContract(TARGET, config)).decision, "block", String(status));
      assert.equal(fake.queries.filter((type) => type === "view_account").length, 1, `HTTP ${status} is not retried`);
    }
    fake.queries.length = 0;
    fake.faults.set("view_account", { kind: "http", status: 429 });
    assert.equal((await checkContract(TARGET, { ...config, rateLimitBackoffMs: [] })).decision, "block");
    assert.equal(fake.queries.filter((type) => type === "view_account").length, 1);
  });

  it("holds the whole query, retries and waits included, to timeoutMs", async () => {
    // One quick retry, then a wait of a minute: the query ends at its 1 s deadline only if the deadline covers the wait.
    // Nothing here depends on the speed of the machine: a missing deadline would not end for 60 s, far past the bound.
    fake.faults.set("view_account", { kind: "http", status: 429 });
    const started = Date.now();
    const result = await checkContract(TARGET, { ...config, timeoutMs: 1_000, rateLimitBackoffMs: [5, 60_000, 60_000, 60_000] });
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /no answer within 1000 ms/);
    assert.ok(Date.now() - started < 30_000, "the deadline covers the waits between the retries");
    assert.equal(fake.queries.length, 2, "it retried once, and the minute-long wait was cut at the deadline");
  });

  it("uses the backoff list as it was when the query started, not as the caller edits it later", async () => {
    fake.faults.set("view_account", { kind: "http", status: 429 });
    const list = [5, 5];
    const query = rpcQuery(config.rpcUrl, { request_type: "view_account", finality: "final", account_id: TARGET }, 2_000, list);
    list.length = 0;
    list.push(...new Array<number>(10).fill(1));
    await assert.rejects(query, /still after 2 retries/);
    assert.equal(fake.queries.length, 3);
  });

  it("uses a list that answers differently the second time as it answered the first", async () => {
    fake.faults.set("view_account", { kind: "http", status: 429 });
    // Honest until the first request has gone out, then a million delays of 1 ms.
    const shifty = new Proxy([5, 5], {
      get(target, key, receiver) {
        if (fake.queries.length === 0) return Reflect.get(target, key, receiver) as unknown;
        return key === "length" ? 1_000_000 : 1;
      },
    });
    await assert.rejects(rpcQuery(config.rpcUrl, { request_type: "view_account", finality: "final", account_id: TARGET }, 300, shifty), /RPC view_account request failed/);
    assert.ok(fake.queries.length <= 3, `${fake.queries.length} requests for a list validated as [5, 5]`);
  });

  it("is not hung or exhausted by a list that is a Proxy with an endless iterator or a huge length", async () => {
    const endless = new Proxy([5, 5], {
      get(target, key, receiver) {
        if (key === Symbol.iterator) return function* () { for (;;) yield 1; };
        return Reflect.get(target, key, receiver) as unknown;
      },
    });
    const huge = new Proxy([5], { get: (target, key, receiver) => (key === "length" ? 2 ** 31 : (Reflect.get(target, key, receiver) as unknown)) });
    const throwing = new Proxy([5], { get: (target, key, receiver) => { if (key === "0") throw new Error("boom"); return Reflect.get(target, key, receiver) as unknown; } });
    fake.faults.set("view_account", { kind: "http", status: 429 });
    const params = { request_type: "view_account", finality: "final", account_id: TARGET };
    // The endless iterator is never used (entries are read by index), so the copy is the honest [5, 5].
    await assert.rejects(rpcQuery(config.rpcUrl, params, 2_000, endless), /still after 2 retries/);
    assert.equal(fake.queries.length, 3);
    fake.queries.length = 0;
    for (const bad of [huge, throwing]) await assert.rejects(rpcQuery(config.rpcUrl, params, 2_000, bad), /rateLimitBackoffMs must be a list/);
    assert.equal(fake.queries.length, 0);
  });

  it("blocks on a backoff list that is not a list of timer delays", async () => {
    for (const bad of [[0], [-1], [1.5], ["5"], new Array<number>(11).fill(5), 5, null]) {
      const result = await checkContract(TARGET, { ...config, rateLimitBackoffMs: bad as unknown as number[] });
      assert.equal(result.decision, "block", JSON.stringify(bad));
      assert.match(result.reasons.join(), /rateLimitBackoffMs/);
    }
    assert.deepEqual(fake.queries, []);
  });

  it("blocks on malformed JSON from the RPC", async () => {
    fake.faults.set("view_account", { kind: "body", text: '{"jsonrpc":"2.0","result":{"amount":' });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /not valid JSON/);
  });

  it("blocks on a well-formed but unexpected view_account body", async () => {
    fake.faults.set("view_account", { kind: "json", body: { jsonrpc: "2.0", result: { amount: "1" }, id: "dontcare" } });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
  });

  it("blocks when the account claims code but view_code says there is none", async () => {
    fake.accounts.set(TARGET, { globalCodeHash: OTHER_HASH });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /NO_CONTRACT_CODE/);
  });

  it("blocks when view_code returns bytes that do not hash to the hash it reports", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.publish(TARGET, "Safe");
    const forged = Buffer.from(fakeWasm("forged")).toString("base64");
    fake.faults.set("view_code", { kind: "json", body: { jsonrpc: "2.0", result: { block_hash: "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW", block_height: 187440904, code_base64: forged, hash: HASH_OF_WASM_A }, id: "dontcare" } });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /RPC reports/);
  });

  it("blocks when the served code is not the code the account's code_hash names", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    const other = fakeWasm("other");
    fake.faults.set("view_code", { kind: "json", body: { jsonrpc: "2.0", result: { block_hash: "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW", block_height: 187440904, code_base64: Buffer.from(other).toString("base64"), hash: codeHashOf(other) }, id: "dontcare" } });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /account's code hash/);
  });

  it("blocks when code_base64 is not valid base64", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.faults.set("view_code", { kind: "json", body: { jsonrpc: "2.0", result: { block_hash: "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW", block_height: 187440904, code_base64: "AGFz*bQEAAAA=", hash: HASH_OF_WASM_A }, id: "dontcare" } });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /base64/);
  });

  it("blocks when the registry call fails (wrong registry id)", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    const result = await checkContract(TARGET, { ...config, registryId: "not-a-registry.test.near" });
    assert.equal(result.decision, "block");
    assert.equal(result.codeHash, HASH_OF_WASM_A);
    assert.match(result.reasons.join(), /MethodNotFound/);
  });

  it("blocks when the registry answers with a malformed verdict", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    const verdict = { code_hash: HASH_OF_WASM_A, status: "Maybe", rule_ids: [], report_url: "", report_sha256: "", auditor: "a.test.near", published_at_ms: "1" };
    fake.faults.set("call_function", { kind: "json", body: { jsonrpc: "2.0", result: { block_height: 1, block_hash: "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW", logs: [], result: [...Buffer.from(JSON.stringify(verdict))] }, id: "dontcare" } });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /malformed verdict/);
  });

  it("blocks when the registry answers for a different code hash", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    serveRegistryAnswer({ ...validVerdict(OTHER_HASH), status: "Safe", rule_ids: [] });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /different code hash than the one requested/);
  });

  it("blocks when the registry result is not JSON", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.faults.set("call_function", { kind: "json", body: { jsonrpc: "2.0", result: { block_height: 1, block_hash: "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW", logs: [], result: [60, 104, 62] }, id: "dontcare" } });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /invalid JSON/);
  });
});

describe("answers that must not read as a quiet result", () => {
  it("blocks a registry answer that carries an error object next to a usable-looking result", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    // The bytes spell "null", which on its own is the registry's "no verdict" and gives warn.
    fake.faults.set("call_function", { kind: "json", body: { jsonrpc: "2.0", result: { block_height: 1, block_hash: "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW", logs: [], result: [110, 117, 108, 108], error: { kind: "HostError" } }, id: "dontcare" } });
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.match(result.reasons.join(), /failed/);
  });

  it("reads the code, the account and the registry at the optimistic head, not the lagging final block", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.publish(TARGET, "Safe");
    assert.equal((await checkContract(TARGET, config)).decision, "allow");
    assert.deepEqual(fake.queries, ["view_account", "view_code", "call_function"]);
    assert.deepEqual(fake.queryParams.map((params) => params["finality"]), ["optimistic", "optimistic", "optimistic"]);
  });

  it("accepts a verdict whose every field has the registry's shape", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    serveRegistryAnswer(validVerdict(HASH_OF_WASM_A));
    const result = await checkContract(TARGET, config);
    assert.equal(result.decision, "block");
    assert.deepEqual(result.verdict, validVerdict(HASH_OF_WASM_A));
  });

  const HOSTILE = "PF004\n2026-11-14 FORGED: outcome allowed\u202e";
  const malformed: Array<[string, Record<string, unknown>]> = [
    ["a rule id with a newline and a bidi control", { rule_ids: [HOSTILE] }],
    ["a rule id that is not PFnnn", { rule_ids: ["PF1"] }],
    ["a rule id given twice", { rule_ids: ["PF001", "PF001"] }],
    ["more than 32 rule ids", { rule_ids: Array.from({ length: 33 }, (_, i) => `PF${String(i).padStart(3, "0")}`) }],
    ["rule ids that are not strings", { rule_ids: [1] }],
    ["an Unsafe verdict with no rule ids", { rule_ids: [] }],
    ["a Safe verdict that lists rule ids", { status: "Safe" }],
    ["an unknown status", { status: "Fine" }],
    ["a report_url that is not http(s)", { report_url: "javascript:alert(1)" }],
    ["a report_url with a newline", { report_url: "https://x.io/a\nforged" }],
    ["a report_url with a space", { report_url: "https://x.io/a b" }],
    ["a report_url with non-ASCII text", { report_url: "https://x.io/\u202e" }],
    ["a report_url over 256 bytes", { report_url: `https://x.io/${"a".repeat(260)}` }],
    ["an upper-case report_sha256", { report_sha256: "AB".repeat(32) }],
    ["a short report_sha256", { report_sha256: "ab".repeat(31) }],
    ["an auditor that is not an account id", { auditor: "evil\nauditor.near" }],
    ["a non-numeric published_at_ms", { published_at_ms: "1\u202e2" }],
    ["a published_at_ms above u64", { published_at_ms: "18446744073709551616" }],
    ["a numeric published_at_ms", { published_at_ms: 1762790400000 }],
  ];
  for (const [name, change] of malformed) {
    it(`blocks a verdict with ${name}, and the reason carries none of its text`, async () => {
      fake.accounts.set(TARGET, { wasm: WASM_A });
      serveRegistryAnswer({ ...validVerdict(HASH_OF_WASM_A), ...change });
      const result = await checkContract(TARGET, config);
      assert.equal(result.decision, "block");
      assert.equal(result.verdict, null);
      assert.match(result.reasons.join(), /malformed verdict: bad /);
      assert.doesNotMatch(result.reasons.join(), /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202e]|FORGED/);
    });
  }
});

describe("the registry's result must be a byte array, byte for byte", () => {
  /** The bytes of a valid Safe verdict, with one byte replaced by a number outside 0..255 that Buffer.from would wrap to the original. */
  const serveBytes = (replace: (bytes: number[]) => void): void => {
    const bytes = [...Buffer.from(JSON.stringify({ ...validVerdict(HASH_OF_WASM_A), status: "Safe", rule_ids: [] }))];
    replace(bytes);
    fake.faults.set("call_function", { kind: "json", body: { jsonrpc: "2.0", result: { block_height: 1, block_hash: BLOCK, logs: [], result: bytes }, id: "dontcare" } });
  };

  it("allows the unmodified bytes, so the cases below fail for the wrapped byte alone", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    serveBytes(() => undefined);
    assert.equal((await checkContract(TARGET, config)).decision, "allow");
  });

  for (const [name, wrap] of [["256 and above", (b: number) => b + 256], ["a negative number", (b: number) => b - 256], ["a fraction", (b: number) => b + 0.5], ["a string", (b: number) => String(b)]] as const) {
    it(`blocks a result holding ${name}, though Buffer.from would wrap it into a Safe verdict`, async () => {
      fake.accounts.set(TARGET, { wasm: WASM_A });
      serveBytes((bytes) => { bytes[10] = wrap(bytes[10] ?? 0) as number; });
      const result = await checkContract(TARGET, config);
      assert.equal(result.decision, "block");
      assert.match(result.reasons.join(), /not a byte array/);
    });
  }
});

describe("timeoutMs", () => {
  it("blocks, fail closed, on a timeout Node's timer would overflow or that is not whole", async () => {
    fake.accounts.set(TARGET, { wasm: WASM_A });
    fake.publish(TARGET, "Safe");
    for (const bad of [0, 1.5, 2 ** 31, Number.NaN]) {
      const result = await checkContract(TARGET, { ...config, timeoutMs: bad });
      assert.equal(result.decision, "block", String(bad));
      assert.match(result.reasons.join(), /timeoutMs/);
    }
    assert.deepEqual(fake.queries, []);
  });
});

describe("contract id validation", () => {
  it("throws for an invalid contract id, and only for that", async () => {
    for (const bad of ["", "a", "UPPER.near", "a..near", ".a.near", "a.near.", "has space.near", "a".repeat(65), "a.near/../x"]) {
      await assert.rejects(checkContract(bad, config), TypeError, `expected ${JSON.stringify(bad)} to throw`);
    }
    assert.deepEqual(fake.queries, []);
  });

  it("accepts the NEAR account id forms", () => {
    for (const good of ["a1", "escrow.test.near", "my-contract_v2.near", "0".repeat(64), "a".repeat(64)]) {
      assert.equal(isValidAccountId(good), true, good);
    }
  });
});
