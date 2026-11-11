// `npm run testnet-demo-llm`: the attack scenario with a real, locally run language model as the agent, against the
// deployed testnet contracts, with the agent's real function-call keys and real transactions. The model reads a page that
// carries an injected instruction; its calls go through the guard, which decides from the registry on testnet.
//   PREFLIGHT_AGENT_KEYS=<dir with agent-key-for-<shop>.key files> PREFLIGHT_LLM_ENDPOINT=http://127.0.0.1:18020 PREFLIGHT_LLM_MODEL=<model id> \
//     npm run testnet-demo-llm -- [--rpc <url>] [--deployment <file>] [--log <file>]
// Exit status: 0 for every outcome the model can honestly produce (it followed the injection and was blocked, it went
// straight to the task, it made no call), 1 when the model's answer was unusable or the self-check failed (something
// other than the task's release was signed), 2 for bad options, 3 when the chain could not be read.
import { parseArgs } from "node:util";
import { describeError, printable } from "../src/text.ts";
import { runLlmTestnetAgent, type LlmTestnetEnv } from "./llm-testnet-agent.ts";
import { parseEndpoint, type LlmConfig } from "./llm-client.ts";
import { DEFAULT_DEPLOYMENT, DEFAULT_TESTNET_RPC, agentSigners, assertTestnetChain, explorerTxUrl, firstFundedOrder, loadDeployment, orderStatus, shopAccount, waitForStatus } from "./testnet-deployment.ts";

const USAGE = "usage: PREFLIGHT_AGENT_KEYS=<dir> PREFLIGHT_LLM_ENDPOINT=<url> PREFLIGHT_LLM_MODEL=<id> testnet-demo-llm [--rpc <url>] [--deployment <file>] [--log <file>]";

function options() {
  try {
    const { values } = parseArgs({ options: { rpc: { type: "string" }, deployment: { type: "string" }, log: { type: "string" } }, strict: true });
    const keysDir = process.env["PREFLIGHT_AGENT_KEYS"];
    if (!keysDir) throw new Error("PREFLIGHT_AGENT_KEYS must name the directory with the agent's key files");
    const endpoint = process.env["PREFLIGHT_LLM_ENDPOINT"];
    const model = process.env["PREFLIGHT_LLM_MODEL"];
    if (endpoint === undefined || model === undefined) throw new Error("set PREFLIGHT_LLM_ENDPOINT (the base URL of a model server: http://127.0.0.1:18020 on this machine, or an https:// URL with the key in PREFLIGHT_LLM_API_KEY) and PREFLIGHT_LLM_MODEL (its model id)");
    const llm: LlmConfig = parseEndpoint(endpoint, model, undefined, process.env["PREFLIGHT_LLM_API_KEY"] || undefined);
    return {
      keysDir,
      llm,
      rpc: values.rpc ?? process.env["PREFLIGHT_TESTNET_RPC"] ?? DEFAULT_TESTNET_RPC,
      deployment: values.deployment ?? DEFAULT_DEPLOYMENT,
      log: values.log ?? "demo-output/testnet-llm-decisions.jsonl",
    };
  } catch (error) {
    console.error(`${printable(describeError(error))}\n${USAGE}`);
    process.exit(2);
  }
}
const { keysDir, llm, rpc, deployment: deploymentPath, log } = options();

try {
  await assertTestnetChain(rpc);
  const deployment = await loadDeployment(deploymentPath);
  const shops = { patched: shopAccount(deployment, "patched"), vulnerable: shopAccount(deployment, "vulnerable"), swapped: shopAccount(deployment, "swapped") };
  const order = await firstFundedOrder(rpc, deployment);
  const injectedOrder = deployment.orders.vulnerable[0];
  if (injectedOrder === undefined) throw new Error(`${deploymentPath} records no order on ${shops.vulnerable}`);
  const signers = await agentSigners(deployment, keysDir);

  const env: LlmTestnetEnv = {
    guard: { rpcUrl: rpc, registryId: deployment.accounts["registry"] ?? "", timeoutMs: 20_000 },
    agentId: deployment.accounts["agent"] ?? "",
    shops,
    order,
    injectedOrder,
    signerFor: (contractId) => {
      const signer = signers.get(contractId);
      if (signer === undefined) throw new Error(`the agent holds no key for ${contractId}`);
      return signer;
    },
    rpcDescription: `NEAR testnet, ${rpc} (real transactions, throwaway accounts under ${deployment.parent})`,
    logPath: log,
    explorerTxUrl,
  };
  const run = await runLlmTestnetAgent(env, llm);

  const signed = run.calls.filter((call) => call.status === "signed");
  const taskSigned = signed.filter((call) => call.contractId === shops.patched && call.method === "release");
  const patchedState = taskSigned.length > 0 ? await waitForStatus(rpc, shops.patched, order, "Released") : await orderStatus(rpc, shops.patched, order);
  const vulnerableState = await orderStatus(rpc, shops.vulnerable, injectedOrder);
  console.log("");
  console.log(printable(`Escrow state read back from the chain: ${shops.patched} order ${order} is ${patchedState}; ${shops.vulnerable} order ${injectedOrder} is ${vulnerableState}.`));
  console.log(printable(`The model's run: ${run.outcome}; transactions sent: ${signed.length === 0 ? "none" : signed.map((call) => `${call.contractId}.${call.method} ${call.transactionHash}`).join(", ")}.`));
  const sound = signed.length === taskSigned.length && vulnerableState === "Funded" && (taskSigned.length === 0 ? patchedState === "Funded" : patchedState === "Released" && taskSigned.every((call) => call.executionFailed === false));
  console.log(sound ? "Self-check passed: nothing was signed except the task's release of the patched shop." : "Self-check FAILED: read the decision log.");
  process.exit(sound && run.outcome !== "unusable" ? 0 : 1);
} catch (error) {
  console.error(`testnet-demo-llm failed: ${printable(describeError(error))}`);
  process.exit(3);
}
