import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";
import { codeHashOf } from "../../src/check.ts";
import { fakeWasm } from "../../testkit/fake-rpc.ts";
import { AUDITED, UNAUDITED, UNSAFE, setReportUrl, startHarness, type Harness } from "./harness.ts";

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

const check = (args: Record<string, unknown>) => h.call("preflight_check_contract", args);

describe("preflight_check_contract", () => {
  it("allows code the registry marks Safe, and says whose verdict it is", async () => {
    const reply = await check({ account_id: AUDITED });
    assert.equal(reply.isError, false);
    assert.deepEqual(reply.data, {
      decision: "allow",
      account_id: AUDITED,
      network: "testnet",
      registry_id: "registry.preflight-guard.testnet",
      code_hash: codeHashOf(fakeWasm(AUDITED)),
      verdict: { status: "Safe", auditor: "auditor.test.near", report_url: `https://preflight.invalid/reports/${codeHashOf(fakeWasm(AUDITED)).slice(0, 8)}.json`, published_at_ms: "1762790400000" },
      rule_ids: [],
      reasons: [`registry verdict Safe: published by auditor.test.near, report https://preflight.invalid/reports/${codeHashOf(fakeWasm(AUDITED)).slice(0, 8)}.json`],
    });
    assert.deepEqual(JSON.parse(reply.text), reply.data, "the text block carries the same answer as the structured one");
  });

  it("blocks code the registry marks Unsafe and names the rule ids", async () => {
    const reply = await check({ account_id: UNSAFE });
    assert.equal(reply.data?.["decision"], "block");
    assert.deepEqual(reply.data?.["rule_ids"], ["PF001"]);
    assert.match(String((reply.data?.["reasons"] as string[])[0]), /Unsafe \(PF001\)/);
  });

  it("warns on code with no verdict: the code hash is shown, the verdict is null", async () => {
    const reply = await check({ account_id: UNAUDITED });
    assert.equal(reply.data?.["decision"], "warn");
    assert.equal(reply.data?.["code_hash"], codeHashOf(fakeWasm(UNAUDITED)));
    assert.equal(reply.data?.["verdict"], null);
    assert.deepEqual(reply.data?.["rule_ids"], []);
  });

  it("warns on a Warn verdict and keeps its rule ids", async () => {
    h.testnet.publish(UNAUDITED, "Warn", ["PF003"]);
    const reply = await check({ account_id: UNAUDITED });
    assert.equal(reply.data?.["decision"], "warn");
    assert.deepEqual(reply.data?.["rule_ids"], ["PF003"]);
    assert.equal((reply.data?.["verdict"] as { status: string }).status, "Warn");
  });

  it("blocks when the chain cannot be read: fail closed, a tool result and not an error", async () => {
    h.testnet.faults.set("view_code", { kind: "http", status: 500 });
    const reply = await check({ account_id: AUDITED });
    assert.equal(reply.isError, false);
    assert.equal(reply.data?.["decision"], "block");
    assert.equal(reply.data?.["code_hash"], null);
    assert.match(String((reply.data?.["reasons"] as string[])[0]), /could not verify/);
  });

  it("allows an account with no contract, with a null code hash", async () => {
    const reply = await check({ account_id: "nobody.preflight-guard.testnet" });
    assert.equal(reply.data?.["decision"], "allow");
    assert.equal(reply.data?.["code_hash"], null);
  });

  it("asks the operator's registry by default when the policy names one", async () => {
    await h.close();
    h = await startHarness({ keys: true, policy: { registryId: "mine.preflight-guard.testnet" } });
    const reply = await check({ account_id: AUDITED });
    assert.equal(reply.data?.["registry_id"], "mine.preflight-guard.testnet");
    assert.equal(reply.data?.["decision"], "block", "the fake chain has no registry there");
  });

  it("takes the RPC url out of a reason: an endpoint can carry an API key", async () => {
    setReportUrl(h.testnet, AUDITED, `${h.testnetUrl}/report.json`);
    const reply = await check({ account_id: AUDITED });
    assert.equal(reply.data?.["decision"], "allow");
    assert.match(String((reply.data?.["reasons"] as string[])[0]), /report \[rpc url\]\/report\.json$/);
    assert.ok(h.testnetUrl.startsWith("http://127.0.0.1:"));
    assert.equal(reply.text.includes(h.testnetUrl), false, "neither the structured answer nor its text block repeats the endpoint");
  });

  it("refuses mainnet unless the operator configured a registry for it", async () => {
    h.mainnet.accounts.set("token.near", { wasm: fakeWasm("token") });
    h.mainnet.publish("token.near", "Safe");
    const reply = await check({ account_id: "token.near", network: "mainnet" });
    assert.equal(reply.isError, true);
    assert.match(reply.text, /no registry for mainnet/);
    assert.equal(h.mainnet.queries.length, 0);
  });

  it("reads mainnet from the mainnet endpoint, against the operator's mainnet registry", async () => {
    await h.close();
    h = await startHarness({ mainnetRegistry: "registry.near" });
    h.mainnet.accounts.set("token.near", { wasm: fakeWasm("token") });
    h.mainnet.publish("token.near", "Safe");
    const reply = await check({ account_id: "token.near", network: "mainnet" });
    assert.equal(reply.data?.["decision"], "allow");
    assert.equal(reply.data?.["network"], "mainnet");
    assert.equal(reply.data?.["registry_id"], "registry.near");
    assert.equal(h.testnet.queries.length, 0, "nothing was asked of the testnet endpoint");
  });

  it("never asks a registry the caller names, even one that would say allow", async () => {
    const rogue = "rogue.preflight-guard.testnet";
    const reply = await check({ account_id: UNSAFE, registry_id: rogue });
    assert.equal(reply.isError, true);
    assert.match(reply.text, /^Input validation error/);
    assert.equal(h.testnet.queries.length, 0);
  });
});

describe("preflight_check_contract input", () => {
  const bad: Array<[string, Record<string, unknown>]> = [
    ["an empty account id", { account_id: "" }],
    ["a one character account id", { account_id: "a" }],
    ["an upper case account id", { account_id: "Shop.testnet" }],
    ["an account id with a space", { account_id: "shop patched.testnet" }],
    ["a path as the account id", { account_id: "../../etc/passwd" }],
    ["an account id over 64 characters", { account_id: `${"a".repeat(60)}.testnet` }],
    ["a number as the account id", { account_id: 7 }],
    ["no account id", {}],
    ["an unknown network", { account_id: AUDITED, network: "devnet" }],
    ["a registry id: the registry is the operator's to choose", { account_id: AUDITED, registry_id: "registry.preflight-guard.testnet" }],
    ["a field the tool does not have", { account_id: AUDITED, rpc_url: "http://127.0.0.1:1" }],
  ];
  for (const [name, args] of bad) {
    it(`refuses ${name} as a plain tool error, before any RPC call`, async () => {
      const reply = await check(args);
      assert.equal(reply.isError, true);
      assert.match(reply.text, /^Input validation error/);
      assert.doesNotMatch(reply.text, /\n\s+at /, "no stack trace");
      assert.equal(h.testnet.queries.length, 0);
    });
  }
});

describe("preflight_check_contract with the chain-fact checks on", () => {
  let on: Harness;
  beforeEach(async () => {
    on = await startHarness({ env: { PREFLIGHT_MCP_MUTABILITY: "pin-warn" } });
  });
  afterEach(async () => {
    await on.close();
  });

  it("tells the host the truth about itself: it keeps a local record, so it is not read-only, and the description says so", async () => {
    const tool = (await on.client.listTools()).tools.find((candidate) => candidate.name === "preflight_check_contract");
    assert.equal(tool?.annotations?.readOnlyHint, false);
    assert.match(tool?.description ?? "", /records the code hash in the operator's pin store/);
    assert.doesNotMatch(tool?.description ?? "", /^Read-only/);
    const keysOnly = await startHarness({ env: { PREFLIGHT_MCP_MUTABILITY: "keys" } });
    try {
      const plain = (await keysOnly.client.listTools()).tools.find((candidate) => candidate.name === "preflight_check_contract");
      assert.equal(plain?.annotations?.readOnlyHint, true, "keys mode records nothing");
      assert.match(plain?.description ?? "", /^Read-only, needs no key\./);
    } finally {
      await keysOnly.close();
    }
    const off = (await h.client.listTools()).tools.find((candidate) => candidate.name === "preflight_check_contract");
    assert.equal(off?.annotations?.readOnlyHint, true);
    assert.match(off?.description ?? "", /^Read-only, needs no key\./);
  });

  it("says a key holder can replace unaudited code, on the same decision and output shape", async () => {
    on.testnet.addKey(UNAUDITED, "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp", "FullAccess");
    const reply = await on.call("preflight_check_contract", { account_id: UNAUDITED });
    assert.equal(reply.data?.["decision"], "warn");
    assert.match((reply.data?.["reasons"] as string[]).join(), /code at this address can be replaced by a key holder at any time \(1 full-access key\)/);
  });

  it("pins audited code at the first allow and warns when it changes, on testnet only", async () => {
    assert.equal((await on.call("preflight_check_contract", { account_id: AUDITED })).data?.["decision"], "allow");
    on.testnet.accounts.set(AUDITED, { wasm: fakeWasm("replacement") });
    on.testnet.publish(AUDITED, "Safe");
    const changed = await on.call("preflight_check_contract", { account_id: AUDITED });
    assert.equal(changed.data?.["decision"], "warn");
    assert.match((changed.data?.["reasons"] as string[]).join(), /code changed since you last approved it/);
  });
});
