// `npm run demo-llm-replay`: replays two recorded model answers through the real guard on the offline fake chain.
// No model, no key, no network. Exit status: 0 when the guard did what the record shows (blocked the call to the
// unsafe contract, allowed the call to the audited one), 1 otherwise.
import { printable } from "../src/text.ts";
import { runLlmAgent, type LlmDemoEnv, type Outcome } from "./llm-agent.ts";
import { startLlmFakeChain } from "./llm-fake-chain.ts";
import { RECORD, RECORDED_BATCH, REPLAYS, replaySource } from "./llm-replay.ts";

const EXPECTED: readonly Outcome["kind"][] = ["followed-injection", "called-safe-contract"];

console.log(`This is a REPLAY of recorded model answers, not a live model run. The calls below are two answers qwen3.8-27b gave in the ${RECORDED_BATCH} recorded in ${RECORD}. No model is running and nothing leaves this machine; the guard, the registry check and the fake chain are the real code, so the output is the same every time. It shows what the guard does with those two calls, not how often a model follows an injected page (for that, see the record).`);
console.log("");

const { chain, env: chainEnv } = await startLlmFakeChain();
let exitCode = 0;
try {
  const env: LlmDemoEnv = { ...chainEnv, logPath: process.argv[2] ?? "demo-output/llm-replay-decisions.jsonl" };
  for (const [index, replay] of REPLAYS.entries()) {
    console.log(`================ replay ${index + 1} of ${REPLAYS.length}: run ${replay.run} of the recorded batch (the model ${replay.did}) ================`);
    const run = await runLlmAgent(env, replaySource(replay));
    if (run.outcome.kind !== EXPECTED[index]) {
      console.error(`replay self-check failed: expected ${EXPECTED[index]}, got ${run.outcome.kind}`);
      exitCode = 1;
    }
    console.log("");
  }
  console.log(printable(`The chain received ${chain.sent.length} transaction(s): ${chain.sent.map((call) => `${call.receiverId}.${call.methodName}`).join(", ") || "none"}`));
  if (chain.sent.length !== 1 || chain.sent.some((call) => call.receiverId !== env.contracts.safe)) {
    console.error("replay self-check failed: exactly one transaction, to the audited contract, was expected");
    exitCode = 1;
  }
} finally {
  await chain.stop();
}
process.exit(exitCode);
