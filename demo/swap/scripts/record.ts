// Sends four flips with the public flip key and writes demo/swap/recorded.json: for each flip the transaction, its
// block, and the code hash, registry verdict and guard decision before and after. The web page replays the file when
// the RPC is down. Every number in it is read from the chain.
//   npm run record -- --key <flip key file> [--rpc <url>] [--flips 4]
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { DEFAULT_TESTNET_RPC, assertTestnetChain, chainCodeHash, explorerTxUrl, guardDecision, loadSwapDeployment, sendFlip, switchStatus, type SwapDeployment } from "./lib.ts";

const { values } = parseArgs({ options: { key: { type: "string" }, rpc: { type: "string" }, flips: { type: "string" } }, strict: true });
if (!values.key) {
  console.error("usage: record --key <file> [--rpc <url>] [--flips <n>]");
  process.exit(2);
}
const rpc = values.rpc ?? DEFAULT_TESTNET_RPC;
const count = Number(values.flips ?? "4");
if (!Number.isInteger(count) || count < 1 || count > 20) throw new Error("--flips must be a whole number from 1 to 20");
const secretKey = (await readFile(values.key, "utf8")).trim() as `ed25519:${string}`;
if (!secretKey.startsWith("ed25519:")) throw new Error(`${values.key} does not hold an ed25519 secret key`);

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** The chameleon as the chain and the registry show it at one moment. */
async function snapshot(rpc: string, deployment: SwapDeployment) {
  const [live, codeHash, guard] = await Promise.all([switchStatus(rpc, deployment).then((status) => status.live), chainCodeHash(rpc, deployment.chameleon), guardDecision(rpc, deployment)]);
  if (guard.codeHash !== codeHash) throw new Error(`the guard read ${guard.codeHash} but the chain reports ${codeHash}: the code changed mid-read, run again`);
  return { live, codeHash, decision: guard.decision, verdict: guard.verdict };
}

await assertTestnetChain(rpc);
const deployment = await loadSwapDeployment();
const flips = [];
let before = await snapshot(rpc, deployment);
for (let n = 1; n <= count; n++) {
  const { hash, blockHash, blockHeight } = await sendFlip(rpc, deployment.switch, secretKey);
  const after = await snapshot(rpc, deployment);
  flips.push({ n, txHash: hash, explorerUrl: explorerTxUrl(hash), blockHeight, blockHash, signer: `${deployment.switch} (flip key ${deployment.flipKey?.publicKey ?? "unknown"})`, before, after });
  console.log(`flip ${n}: ${before.live} -> ${after.live}  ${before.decision.toUpperCase()} -> ${after.decision.toUpperCase()}  ${explorerTxUrl(hash)}`);
  before = after;
  // The switch refuses a flip inside its minimum interval; wait it out (plus a block of slack).
  if (n < count) await sleep((await switchStatus(rpc, deployment)).min_interval_ms + 2_000);
}
const recorded = { network: deployment.network, rpc, chameleon: deployment.chameleon, switch: deployment.switch, registry: deployment.registry, recordedAt: new Date().toISOString(), flips };
await writeFile(join(import.meta.dirname, "..", "recorded.json"), `${JSON.stringify(recorded, null, 2)}\n`);
console.log(`wrote recorded.json with ${flips.length} flips`);
