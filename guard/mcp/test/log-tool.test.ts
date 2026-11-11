import assert from "node:assert/strict";
import { appendFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { AUDITED, UNSAFE, setReportUrl, startHarness, type Harness } from "./harness.ts";

let h: Harness;
beforeEach(async () => {
  h = await startHarness({ keys: true });
});
afterEach(async () => {
  await h.close();
});

const entries = async (limit?: number) => {
  const reply = await h.call("preflight_decision_log", limit === undefined ? {} : { limit });
  return { reply, entries: (reply.data?.["entries"] ?? []) as Array<{ timestamp: string; outcome: string; contract: string; decision: string }> };
};

describe("preflight_decision_log", () => {
  it("is empty before any call", async () => {
    assert.deepEqual((await entries()).entries, []);
  });

  it("returns what the guard logged, oldest first", async () => {
    await h.call("preflight_guarded_call", { contract_id: UNSAFE, method: "release" });
    await h.call("preflight_guarded_call", { contract_id: AUDITED, method: "release" });
    const { entries: all } = await entries();
    assert.deepEqual(all.map((entry) => [entry.contract, entry.outcome, entry.decision]), [[UNSAFE, "refused", "block"], [AUDITED, "approved", "allow"], [AUDITED, "sent", "allow"]]);
  });

  it("takes the RPC url out of the reasons it returns, even when the log file holds it", async () => {
    setReportUrl(h.testnet, UNSAFE, `${h.testnetUrl}/report.json`);
    await h.call("preflight_guarded_call", { contract_id: UNSAFE, method: "release" });
    const { reply, entries: all } = await entries();
    assert.match(String((all[0] as { reasons?: string[] }).reasons?.[0]), /report \[rpc url\]\/report\.json$/);
    assert.equal(reply.text.includes(h.testnetUrl), false);
  });

  it("returns only the last N", async () => {
    await h.call("preflight_guarded_call", { contract_id: UNSAFE, method: "release" });
    await h.call("preflight_guarded_call", { contract_id: AUDITED, method: "release" });
    assert.deepEqual((await entries(2)).entries.map((entry) => entry.outcome), ["approved", "sent"]);
    assert.deepEqual((await entries(1)).entries.map((entry) => entry.outcome), ["sent"]);
  });

  it("reads the end of a log far larger than the window it needs", async () => {
    const line = (n: number) => JSON.stringify({ timestamp: `t${n}`, contract: AUDITED, method: "release", deposit: "0", codeHash: null, decision: "block", outcome: "refused", reasons: ["r".repeat(1_000)] });
    await writeFile(join(h.dir, "decisions.jsonl"), Array.from({ length: 60 }, (_, n) => `${line(n)}\n`).join(""));
    assert.deepEqual((await entries(1)).entries.map((entry) => entry.timestamp), ["t59"]);
    assert.deepEqual((await entries(3)).entries.map((entry) => entry.timestamp), ["t57", "t58", "t59"]);
  });

  it("refuses to guess at a log line that is not a decision entry", async () => {
    await appendFile(join(h.dir, "decisions.jsonl"), "not json\n");
    const { reply } = await entries();
    assert.equal(reply.isError, true);
    assert.match(reply.text, /not a decision entry/);
  });

  for (const limit of [0, 101, 1.5, "5", -1]) {
    it(`refuses a limit of ${JSON.stringify(limit)}`, async () => {
      const reply = await h.call("preflight_decision_log", { limit });
      assert.equal(reply.isError, true);
      assert.match(reply.text, /^Input validation error/);
    });
  }
});
