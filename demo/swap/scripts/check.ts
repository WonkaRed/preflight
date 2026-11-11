// Read-only, no keys: what the switch says, what the chain says, and what two kinds of check decide about the chameleon.
//   npm run check [-- --rpc <url>]
// Exit status: 0 printed, 1 the chain disagrees with the switch, 3 the chain could not be read.
import { parseArgs } from "node:util";
import { DEFAULT_TESTNET_RPC, assertTestnetChain, chainCodeHash, guardDecision, loadSwapDeployment, switchStatus } from "./lib.ts";

const { values } = parseArgs({ options: { rpc: { type: "string" } }, strict: true });
const rpc = values.rpc ?? DEFAULT_TESTNET_RPC;

try {
  await assertTestnetChain(rpc);
  const deployment = await loadSwapDeployment();
  const status = await switchStatus(rpc, deployment);
  const onChain = await chainCodeHash(rpc, deployment.chameleon);
  const guard = await guardDecision(rpc, deployment);

  console.log(`switch    ${deployment.switch}   chameleon ${deployment.chameleon}`);
  const wait = Math.max(0, status.next_flip_ms - Date.now());
  console.log(`status()  live: ${status.live}   flips: ${status.flips}   next flip ${wait === 0 ? "allowed now" : `allowed in ${Math.ceil(wait / 1000)} s`}`);
  for (const build of ["vulnerable", "patched"] as const) {
    console.log(`  ${build.padEnd(10)} code hash ${status[build].code_hash}  hex ${status[build].code_hash_hex}  (${status[build].size_bytes} bytes)`);
  }
  const running = onChain === status.vulnerable.code_hash ? "vulnerable" : onChain === status.patched.code_hash ? "patched" : "neither build";
  console.log(`the chain reports the chameleon's code hash as ${onChain}: the ${running} build`);
  console.log();
  // A check keyed to the address: the chameleon is on the list of accounts someone once vetted, and stays on it.
  console.log(`A check that trusts the address (is ${deployment.chameleon} on the allowlist?):  ALLOW`);
  console.log(`Preflight (the verdict for this code hash in the registry):                    ${guard.decision.toUpperCase()}`);
  console.log(`  ${guard.reason}`);
  process.exit(running === status.live ? 0 : 1);
} catch (error) {
  console.error(`check failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(3);
}
