// Flips the chameleon once, signing with the public flip key: what a visitor's browser does.
//   npm run flip -- --key <file with the flip key's secret> [--rpc <url>]
// Needs no other key. Prints the transaction and what the guard decides about the chameleon before and after.
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { DEFAULT_TESTNET_RPC, assertTestnetChain, explorerTxUrl, guardDecision, loadSwapDeployment, sendFlip, switchStatus } from "./lib.ts";

const { values } = parseArgs({ options: { key: { type: "string" }, rpc: { type: "string" } }, strict: true });
if (!values.key) {
  console.error("usage: flip --key <file> [--rpc <url>]");
  process.exit(2);
}
const rpc = values.rpc ?? DEFAULT_TESTNET_RPC;
const secretKey = (await readFile(values.key, "utf8")).trim();
if (!secretKey.startsWith("ed25519:")) throw new Error(`${values.key} does not hold an ed25519 secret key`);

try {
  await assertTestnetChain(rpc);
  const deployment = await loadSwapDeployment();
  const before = await guardDecision(rpc, deployment);
  console.log(`before: the build live is ${(await switchStatus(rpc, deployment)).live}; the guard says ${before.decision.toUpperCase()} (${before.reason})`);
  const { hash } = await sendFlip(rpc, deployment.switch, secretKey as `ed25519:${string}`);
  console.log(`flip transaction ${hash}\n  ${explorerTxUrl(hash)}`);
  const after = await guardDecision(rpc, deployment);
  console.log(`after:  the build live is ${(await switchStatus(rpc, deployment)).live}; the guard says ${after.decision.toUpperCase()} (${after.reason})`);
} catch (error) {
  console.error(`flip failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
