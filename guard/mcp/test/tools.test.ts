import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { AUDITED, startHarness, type Harness } from "./harness.ts";

let h: Harness | undefined;
afterEach(async () => {
  await h?.close();
  h = undefined;
});

describe("tool list", () => {
  it("offers only the read-only check when the operator gave no key directory and policy", async () => {
    h = await startHarness();
    assert.deepEqual((await h.client.listTools()).tools.map((tool) => tool.name), ["preflight_check_contract"]);
  });

  it("has no guarded call and no decision log to call without them: the tools are not there", async () => {
    h = await startHarness();
    for (const name of ["preflight_guarded_call", "preflight_decision_log"]) {
      await assert.rejects(h.client.callTool({ name, arguments: {} }), /not found/);
    }
  });

  it("offers the guarded call and the decision log when the operator gave both", async () => {
    h = await startHarness({ keys: true });
    assert.deepEqual((await h.client.listTools()).tools.map((tool) => tool.name).sort(), ["preflight_check_contract", "preflight_decision_log", "preflight_guarded_call"]);
  });

  it("marks what reads and what sends, for hosts that ask before the second", async () => {
    h = await startHarness({ keys: true });
    const hints = Object.fromEntries((await h.client.listTools()).tools.map((tool) => [tool.name, tool.annotations?.readOnlyHint]));
    assert.deepEqual(hints, { preflight_check_contract: true, preflight_decision_log: true, preflight_guarded_call: false });
  });

  it("tells the model which contracts the operator allows", async () => {
    h = await startHarness({ keys: true });
    const call = (await h.client.listTools()).tools.find((tool) => tool.name === "preflight_guarded_call");
    assert.match(call?.description ?? "", new RegExp(AUDITED.replaceAll(".", "\\.")));
  });
});
