import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { teraToGas } from "near-api-js";
import { AGENT, AUDITED, UNAUDITED, UNSAFE, setReportUrl, startHarness, type Harness } from "./harness.ts";

let h: Harness;
beforeEach(async () => {
  h = await startHarness({ keys: true });
});
afterEach(async () => {
  await h.close();
});

const send = (args: Record<string, unknown>) => h.call("preflight_guarded_call", args);

async function logged(): Promise<Array<{ outcome: string; decision: string; contract: string }>> {
  const text = await readFile(join(h.dir, "decisions.jsonl"), "utf8").catch(() => "");
  return text.split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

describe("preflight_guarded_call", () => {
  it("signs and sends a call to audited code, and logs the decision before and at the send", async () => {
    const reply = await send({ contract_id: AUDITED, method: "release", args: { id: 3 } });
    assert.equal(reply.isError, false);
    assert.equal(reply.data?.["decision"], "allow");
    assert.equal(reply.data?.["execution"], "success");
    assert.equal(typeof reply.data?.["transaction_hash"], "string");
    assert.equal(h.testnet.sent.length, 1);
    const [sent] = h.testnet.sent;
    assert.equal(sent?.signerId, AGENT);
    assert.equal(sent?.receiverId, AUDITED);
    assert.equal(sent?.methodName, "release");
    assert.equal(sent?.args, '{"id":3}');
    assert.equal(sent?.deposit, 0n);
    assert.equal(sent?.gas, teraToGas("30"));
    assert.deepEqual((await logged()).map((entry) => entry.outcome), ["approved", "sent"]);
  });

  it("sends empty arguments when none are given", async () => {
    await send({ contract_id: AUDITED, method: "release" });
    assert.equal(h.testnet.sent[0]?.args, "{}");
  });

  it("refuses code the registry marks Unsafe: nothing is sent, the refusal is logged with the rule", async () => {
    const reply = await send({ contract_id: UNSAFE, method: "release", args: { id: 1 } });
    assert.equal(reply.isError, true);
    assert.match(reply.text, /PF001/);
    assert.equal(h.testnet.sent.length, 0);
    assert.deepEqual((await logged()).map((entry) => [entry.outcome, entry.decision]), [["refused", "block"]]);
  });

  it("takes the RPC url out of a refusal: an endpoint can carry an API key", async () => {
    setReportUrl(h.testnet, UNSAFE, `${h.testnetUrl}/report.json`);
    const reply = await send({ contract_id: UNSAFE, method: "release" });
    assert.equal(reply.isError, true);
    assert.match(reply.text, /PF001/);
    assert.match(reply.text, /\[rpc url\]\/report\.json/);
    assert.equal(reply.text.includes(h.testnetUrl), false);
  });

  it("refuses code with no verdict, because no human is there to approve a warn", async () => {
    const reply = await send({ contract_id: UNAUDITED, method: "release" });
    assert.equal(reply.isError, true);
    assert.match(reply.text, /no approval callback/);
    assert.equal(h.testnet.sent.length, 0);
  });

  it("refuses a contract that is not on the allow list before any RPC call", async () => {
    const reply = await send({ contract_id: "drain.preflight-guard.testnet", method: "release" });
    assert.equal(reply.isError, true);
    assert.match(reply.text, /not in the allowed contracts/);
    assert.equal(h.testnet.queries.length, 0);
    assert.equal(h.testnet.sent.length, 0);
  });

  it("refuses a deposit above the policy's cap", async () => {
    const reply = await send({ contract_id: AUDITED, method: "release", deposit: "1" });
    assert.equal(reply.isError, true);
    assert.match(reply.text, /exceeds the per-call cap/);
    assert.equal(h.testnet.sent.length, 0);
  });

  it("refuses to send when the endpoint is not testnet, and never prints the endpoint", async () => {
    h.testnet.chainId = "mainnet";
    const reply = await send({ contract_id: AUDITED, method: "release" });
    assert.equal(reply.isError, true);
    assert.match(reply.text, /did not confirm chain_id testnet/);
    assert.match(reply.text, /\[rpc url\]/);
    assert.doesNotMatch(reply.text, /127\.0\.0\.1/);
    assert.equal(h.testnet.queries.length, 0);
    assert.equal(h.testnet.sent.length, 0);
  });

  it("has no way to name another network: the field is refused, not ignored", async () => {
    const reply = await send({ contract_id: AUDITED, method: "release", network: "mainnet" });
    assert.equal(reply.isError, true);
    assert.match(reply.text, /^Input validation error/);
    assert.equal(h.testnet.sent.length, 0);
  });
});

describe("preflight_guarded_call input", () => {
  const big = { note: "x".repeat(16 * 1024) };
  const bad: Array<[string, Record<string, unknown>]> = [
    ["an invalid contract id", { contract_id: "Not A Contract", method: "release" }],
    ["a method name with a dash", { contract_id: AUDITED, method: "bad-method" }],
    ["a method name that starts with a digit", { contract_id: AUDITED, method: "1release" }],
    ["an empty method name", { contract_id: AUDITED, method: "" }],
    ["a method name over 256 characters", { contract_id: AUDITED, method: "a".repeat(257) }],
    ["arguments that are a list", { contract_id: AUDITED, method: "release", args: [1] }],
    ["arguments over 16 KiB", { contract_id: AUDITED, method: "release", args: big }],
    ["a deposit with a decimal point", { contract_id: AUDITED, method: "release", deposit: "1.5" }],
    ["a negative deposit", { contract_id: AUDITED, method: "release", deposit: "-1" }],
    ["a deposit in exponent form", { contract_id: AUDITED, method: "release", deposit: "1e3" }],
    ["a deposit with a leading zero", { contract_id: AUDITED, method: "release", deposit: "01" }],
    ["a deposit as a number", { contract_id: AUDITED, method: "release", deposit: 1 }],
    ["a deposit of 2^128", { contract_id: AUDITED, method: "release", deposit: "340282366920938463463374607431768211456" }],
    ["a deposit of 5000 digits", { contract_id: AUDITED, method: "release", deposit: "9".repeat(5000) }],
  ];
  for (const [name, args] of bad) {
    it(`refuses ${name} as a plain tool error, before any RPC call`, async () => {
      const reply = await send(args);
      assert.equal(reply.isError, true);
      assert.match(reply.text, /^Input validation error/);
      assert.doesNotMatch(reply.text, /\n\s+at /, "no stack trace");
      assert.equal(h.testnet.queries.length, 0);
      assert.equal(h.testnet.sent.length, 0);
    });
  }

  it("accepts arguments of exactly 16 KiB of JSON", async () => {
    const note = "x".repeat(16 * 1024 - '{"note":""}'.length);
    const reply = await send({ contract_id: AUDITED, method: "release", args: { note } });
    assert.equal(reply.isError, false);
    assert.equal(h.testnet.sent[0]?.argsBytes.length, 16 * 1024);
  });
});

describe("what the model can see", () => {
  it("never receives key material, in any tool result or in the tool list", async () => {
    await send({ contract_id: AUDITED, method: "release" });
    await send({ contract_id: UNSAFE, method: "release" });
    await send({ contract_id: "drain.preflight-guard.testnet", method: "release" });
    await h.call("preflight_check_contract", { account_id: AUDITED });
    await h.call("preflight_decision_log", { limit: 100 });
    h.transcript.push(JSON.stringify(await h.client.listTools()));

    assert.equal(h.secrets.length, 3);
    const seen = h.transcript.join("\n");
    for (const secret of h.secrets) assert.ok(!seen.includes(secret.slice("ed25519:".length)), "a secret key reached the client");
    assert.ok(!seen.includes("keys/"), "no key file path reached the client");
  });
});
