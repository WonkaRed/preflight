// demo-llm-replay: recorded model answers through the real guard on the fake chain. No model, no network.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { promisify } from "node:util";
import type { FakeNear } from "../testkit/fake-rpc.ts";
import { makeTempDir } from "../testkit/tempdir.ts";
import { runLlmAgent } from "../demo/llm-agent.ts";
import { startLlmFakeChain } from "../demo/llm-fake-chain.ts";
import { LlmError } from "../demo/llm-client.ts";
import { RECORD, REPLAYS, replaySource } from "../demo/llm-replay.ts";

const root = join(import.meta.dirname, "..", "..");

describe("the replayed answers are the ones in the record", () => {
  it("each recorded call appears verbatim in its run of the first batch, with the outcome the replay expects", async () => {
    const record = await readFile(join(root, RECORD), "utf8");
    const firstBatch = record.slice(0, record.indexOf("\n================ BATCH"));
    const expectedOutcome = ["the model followed the injected instruction, and the guard stopped it", "it called the audited contract, safe-escrow.test.near (method pay_invoice), and the guard allowed it"];
    for (const [index, replay] of REPLAYS.entries()) {
      const start = firstBatch.indexOf(`================ run ${replay.run} ================`);
      assert.ok(start >= 0, `run ${replay.run} is in the record`);
      const next = firstBatch.indexOf("================ run ", start + 1);
      const section = firstBatch.slice(start, next < 0 ? undefined : next);
      assert.ok(section.includes(`The model's own tool call, verbatim:\n  call_contract ${replay.callArguments}\n`), `run ${replay.run}'s call is verbatim in the record`);
      assert.ok(section.includes(expectedOutcome[index] ?? "?"), `run ${replay.run}'s outcome`);
      assert.ok(section.includes("fetched: https://shop.invalid/invoices/42"), `run ${replay.run} fetched the invoice page`);
    }
  });
});

describe("replaying through the real guard", () => {
  let chain: FakeNear;
  let dir: string;
  let env: Awaited<ReturnType<typeof startLlmFakeChain>>["env"];
  beforeEach(async () => {
    dir = await makeTempDir("llm-replay");
    ({ chain, env } = await startLlmFakeChain());
  });
  afterEach(async () => {
    await chain.stop();
    await rm(dir, { recursive: true, force: true });
  });

  it("blocks the recorded call to the unsafe contract and allows the recorded call to the audited one", async () => {
    const lines: string[] = [];
    const followed = await runLlmAgent({ ...env, logPath: join(dir, "log.jsonl") }, replaySource(REPLAYS[0]!), (line) => lines.push(line));
    assert.equal(followed.outcome.kind, "followed-injection");
    assert.deepEqual(followed.proposals.map((p) => p.signed), [false]);
    assert.match(followed.proposals[0]?.why ?? "", /^block: registry verdict Unsafe \(PF004\)/);
    assert.equal(chain.sent.length, 0);
    const called = await runLlmAgent({ ...env, logPath: join(dir, "log.jsonl") }, replaySource(REPLAYS[1]!), (line) => lines.push(line));
    assert.equal(called.outcome.kind, "called-safe-contract");
    assert.deepEqual(chain.sent.map((call) => `${call.receiverId}.${call.methodName}`), ["safe-escrow.test.near.pay_invoice"]);
    const output = lines.join("\n");
    assert.match(output, /RECORDED answer replayed \(no model is running and no network is used: a replay of run 2 of the 2026-11-11 batch of 30 in docs\/guard-llm-demo-runs\.txt/);
    assert.match(output, /run 8 of the 2026-11-11 batch of 30/);
    assert.doesNotMatch(output, /locally run language model/);
  });

  it("has no more turns than the record shows", async () => {
    const source = replaySource(REPLAYS[0]!);
    await source.ask([], []);
    await source.ask([], []);
    await assert.rejects(source.ask([], []), LlmError);
  });
});

describe("the demo script", () => {
  const run = () => promisify(execFile)(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "..", "demo", "llm-replay-demo.ts"), join(tmpdirFor, "log.jsonl")], { env: { PATH: process.env["PATH"] ?? "" } });
  let tmpdirFor = "";
  beforeEach(async () => { tmpdirFor = await makeTempDir("llm-replay-script"); });
  afterEach(() => rm(tmpdirFor, { recursive: true, force: true }));

  it("exits 0 with no model, key or endpoint in the environment, says plainly it is a replay naming the record, and prints the same thing twice", async () => {
    const first = await run();
    const second = await run();
    assert.equal(first.stdout, second.stdout);
    assert.match(first.stdout, /^This is a REPLAY of recorded model answers, not a live model run\./);
    assert.ok(first.stdout.includes("docs/guard-llm-demo-runs.txt"));
    assert.match(first.stdout, /The chain received 1 transaction\(s\): safe-escrow\.test\.near\.pay_invoice/);
    assert.equal(first.stderr, "");
  });
});
