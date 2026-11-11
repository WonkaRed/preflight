// One status line for the Swap's money, and the repairs that keep it flipping. Run it on a timer.
//
//   PREFLIGHT_TESTNET_KEYS=<dir> npm run watchdog          (or: make -C demo/swap watchdog)
//
// It reads the spare balance (balance minus what the account's storage costs) of the switch and of the chameleon, and
// what is left of the flip key's gas allowance. Below a floor it repairs, when <dir> holds the key files it needs:
//   - switch spare < 5 NEAR, or chameleon spare < 0.3 NEAR: the parent account (<dir>/preflight-guard.testnet.key) tops
//     the account up to its target, as far as the parent's own spare allows;
//   - flip allowance < 1 NEAR: the switch (<dir>/switch.preflight-guard.testnet.key) replaces the flip key with the same
//     public key and a fresh allowance, in one transaction, so there is no moment without the key.
// Without PREFLIGHT_TESTNET_KEYS it only reads and reports. The line it prints ends in OK or FAIL; it exits 1 on FAIL (a floor that
// is still not met, a repair that could not be made, or a chain it could not read) and 2 on a usage error.
// TESTNET ONLY: the RPC must report chain_id "testnet".
import { parseArgs } from "node:util";
import { Account, JsonRpcProvider, KeyPairSigner, PublicKey, actions, nearToYocto } from "near-api-js";
import { DEFAULT_TESTNET_RPC, assertTestnetChain, keyPath, loadSwapDeployment, readSecretKey, switchStatus } from "./lib.ts";

/** Each floor, the level a repair brings the account back to, in NEAR. */
const SWITCH = { floor: "5", target: "10" };
const CHAMELEON = { floor: "0.3", target: "1" };
const ALLOWANCE = { floor: "1", target: "5" };
/** What the parent keeps for itself above its storage, so a top-up never leaves it unable to sign the next one. */
const PARENT_KEEPS = "0.2";
const STORAGE_BYTE_COST = 10n ** 19n;

let values;
try {
  ({ values } = parseArgs({ options: { rpc: { type: "string" } }, strict: true }));
} catch (error) {
  console.error(`${error instanceof Error ? error.message : String(error)}\nusage: [PREFLIGHT_TESTNET_KEYS=<dir>] watchdog [--rpc <url>]`);
  process.exit(2);
}
const rpc = values.rpc ?? DEFAULT_TESTNET_RPC;
const keysDir = process.env["PREFLIGHT_TESTNET_KEYS"];

const yocto = (near: string): bigint => nearToYocto(near as `${number}`);
const show = (amount: bigint): string => `${(Number(amount / 10n ** 18n) / 1e6).toFixed(3)}`;

const provider = new JsonRpcProvider({ url: rpc });
const deployment = await loadSwapDeployment();
const flipKey = deployment.flipKey;
if (flipKey === null) throw new Error("deployment.json records no flip key");
const accountFor = async (accountId: string): Promise<Account> => new Account(accountId, provider, KeyPairSigner.fromSecretKey(await readSecretKey(keyPath(keysDir ?? "", accountId))));

async function spare(accountId: string): Promise<bigint> {
  const account = await provider.viewAccount({ accountId, blockQuery: { finality: "final" } });
  const free = BigInt(String(account.amount)) - BigInt(account.storage_usage) * STORAGE_BYTE_COST;
  return free > 0n ? free : 0n;
}

/** What the flip key may still burn; null when the key has no limit (or is no function-call key at all). */
async function allowance(): Promise<bigint | null> {
  const key = await provider.viewAccessKey({ accountId: deployment.switch, publicKey: flipKey!.publicKey, finalityQuery: { finality: "final" } });
  const permission = key.permission;
  if (typeof permission === "string" || !("FunctionCall" in permission) || permission.FunctionCall.allowance == null) return null;
  return BigInt(String(permission.FunctionCall.allowance));
}

const read = async () => ({ switchSpare: await spare(deployment.switch), chameleonSpare: await spare(deployment.chameleon), allowance: await allowance() });

const repairs: string[] = [];
const problems: string[] = [];
let state = await read();

async function topUp(name: string, accountId: string, level: { floor: string; target: string }, current: bigint): Promise<void> {
  if (current >= yocto(level.floor) || keysDir === undefined) return;
  try {
    const parent = await accountFor(deployment.parent);
    const room = (await spare(deployment.parent)) - yocto(PARENT_KEEPS);
    const amount = [yocto(level.target) - current, room].reduce((a, b) => (a < b ? a : b));
    if (amount <= 0n) return void problems.push(`${deployment.parent} has nothing to give ${name}`);
    await parent.signAndSendTransaction({ receiverId: accountId, actions: [actions.transfer(amount)], waitUntil: "FINAL", throwOnFailure: true });
    repairs.push(`${name} +${show(amount)}`);
  } catch (error) {
    problems.push(`${name} top-up failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function renewAllowance(current: bigint | null): Promise<void> {
  if (current === null || current >= yocto(ALLOWANCE.floor) || keysDir === undefined) return;
  try {
    const owner = await accountFor(deployment.switch);
    const key = PublicKey.from(flipKey!.publicKey);
    await owner.signAndSendTransaction({
      receiverId: deployment.switch,
      actions: [actions.deleteKey(key), actions.addFunctionCallAccessKey(key, deployment.switch, ["flip"], yocto(ALLOWANCE.target))],
      waitUntil: "FINAL",
      throwOnFailure: true,
    });
    repairs.push(`allowance renewed to ${ALLOWANCE.target}`);
  } catch (error) {
    problems.push(`allowance renewal failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

await assertTestnetChain(rpc);
await topUp("switch", deployment.switch, SWITCH, state.switchSpare);
await topUp("chameleon", deployment.chameleon, CHAMELEON, state.chameleonSpare);
await renewAllowance(state.allowance);
if (repairs.length > 0) state = await read();

// Judged on what the chain says after the repairs, whatever the repairs reported.
if (state.switchSpare < yocto(SWITCH.floor)) problems.push(`switch spare ${show(state.switchSpare)} is still below ${SWITCH.floor}`);
if (state.chameleonSpare < yocto(CHAMELEON.floor)) problems.push(`chameleon spare ${show(state.chameleonSpare)} is still below ${CHAMELEON.floor}`);
if (state.allowance !== null && state.allowance < yocto(ALLOWANCE.floor)) problems.push(`flip allowance ${show(state.allowance)} is still below ${ALLOWANCE.floor}`);

const status = await switchStatus(rpc, deployment);
const healthy = problems.length === 0;
console.log(
  [
    `swap-watchdog ${new Date().toISOString()} ${healthy ? "OK" : "FAIL"}${keysDir === undefined ? " (read-only: PREFLIGHT_TESTNET_KEYS not set)" : ""}`,
    `switch_spare=${show(state.switchSpare)} chameleon_spare=${show(state.chameleonSpare)} flip_allowance=${state.allowance === null ? "unlimited" : show(state.allowance)}`,
    `live=${status.live} flips=${status.flips}`,
    repairs.length > 0 ? `repaired: ${repairs.join(", ")}` : "",
    problems.length > 0 ? `problems: ${problems.join("; ")}` : "",
  ]
    .filter(Boolean)
    .join(" | "),
);
process.exit(healthy ? 0 : 1);
