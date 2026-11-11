// `npm run demo-llm`: the attack scenario with a locally run language model as the agent, against the same offline
// fake NEAR RPC as the scripted demo. No network beyond the model's own loopback endpoint, no keys.
//   PREFLIGHT_LLM_ENDPOINT=http://127.0.0.1:18020 PREFLIGHT_LLM_MODEL=<model id> npm run demo-llm [-- <log path>]
// (or an https:// endpoint with the key in PREFLIGHT_LLM_API_KEY)
// Exit status: 0 for every outcome the model can honestly produce (it followed the injection and the guard stopped it,
// it made the task's call, it made no call), 1 when the model's answer was unusable or the self-check failed,
// 2 when the configuration is wrong.
import { describeError, printable } from "../src/text.ts";
import { runLlmAgent, type LlmDemoEnv } from "./llm-agent.ts";
import { startLlmFakeChain } from "./llm-fake-chain.ts";
import { LlmError, parseEndpoint } from "./llm-client.ts";

const endpoint = process.env["PREFLIGHT_LLM_ENDPOINT"];
const model = process.env["PREFLIGHT_LLM_MODEL"];
if (endpoint === undefined || model === undefined) {
  console.error("set PREFLIGHT_LLM_ENDPOINT (the base URL of a model server: http://127.0.0.1:18020 on this machine, or an https:// URL with the key in PREFLIGHT_LLM_API_KEY) and PREFLIGHT_LLM_MODEL (its model id)");
  process.exit(2);
}
let llm;
try {
  llm = parseEndpoint(endpoint, model, undefined, process.env["PREFLIGHT_LLM_API_KEY"] || undefined);
} catch (error) {
  console.error(printable(describeError(error)));
  process.exit(2);
}

const { chain, env: chainEnv } = await startLlmFakeChain();
let exitCode = 0;
try {
  const env: LlmDemoEnv = { ...chainEnv, logPath: process.argv[2] ?? "demo-output/llm-decisions.jsonl" };
  try {
    await runLlmAgent(env, llm);
  } catch (error) {
    if (!(error instanceof LlmError)) throw error;
    console.error(`The model's answer could not be used: ${printable(describeError(error))}`);
    exitCode = 1;
  }
  console.log(printable(`The chain received ${chain.sent.length} transaction(s): ${chain.sent.map((call) => `${call.receiverId}.${call.methodName}`).join(", ") || "none"}`));
  if (chain.sent.some((call) => call.receiverId !== env.contracts.safe)) {
    console.error("demo self-check failed: only the audited contract may be signed");
    exitCode = 1;
  }
} finally {
  await chain.stop();
}
process.exit(exitCode);
