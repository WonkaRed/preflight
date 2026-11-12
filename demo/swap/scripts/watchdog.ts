// One status line for the Swap's money, and the repairs that keep it flipping. Run it on a timer.
//
//   PREFLIGHT_TESTNET_KEYS=<dir> npm run watchdog          (or: make -C demo/swap watchdog)
//
// It reads the spare balance (balance minus what the account's storage costs) of the switch, the chameleon and the
// "Rob it" robber account, and what is left of the flip key's and the robber key's gas allowance. Below a floor it
// repairs, when <dir> holds the key files it needs:
//   - switch spare < 5 NEAR, chameleon spare < 0.3 NEAR, or robber spare < 0.1 NEAR: the parent account
//     (<dir>/preflight-guard.testnet.key) tops the account up to its target, as far as the parent's own spare allows;
//   - flip allowance < 1 NEAR: the switch (<dir>/switch.preflight-guard.testnet.key) replaces the flip key with the same
//     public key and a fresh allowance, in one transaction, so there is no moment without the key;
//   - robber allowance < 0.03 NEAR: the robber account (<dir>/robber.preflight-guard.testnet.key) replaces its own
//     scoped key the same way. Both keys attach no deposit (a function-call key never can), so a renewal can never
//     spend more than gas.
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
const ROBBER = { floor: "0.1", target: "0.2" };
const ROBBER_ALLOWANCE = { floor: "0.03", target: "0.1" };
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
// The robber account and its scoped key are optional: a deployment that has not run deploy-robber.ts yet is still watched for the switch and the chameleon.
const robberKey = deployment.robberKey ?? null;
const accountFor = async (accountId: string): Promise<Account> => new Account(accountId, provider, KeyPairSigner.fromSecretKey(await readSecretKey(keyPath(keysDir ?? "", accountId))));

async function spare(accountId: string): Promise<bigint> {
  const account = await provider.viewAccount({ accountId, blockQuery: { finality: "final" } });
  const free = BigInt(String(account.amount)) - BigInt(account.storage_usage) * STORAGE_BYTE_COST;
  return free > 0n ? free : 0n;
}

/** What a function-call key may still burn; null when the key has no limit (or is no function-call key at all). Shared by the flip key and the robber key. */
async function allowanceOf(accountId: string, publicKey: string): Promise<bigint | null> {
  const key = await provider.viewAccessKey({ accountId, publicKey, finalityQuery: { finality: "final" } });
  const permission = key.permission;
  if (typeof permission === "string" || !("FunctionCall" in permission) || permission.FunctionCall.allowance == null) return null;
  return BigInt(String(permission.FunctionCall.allowance));
}

const read = async () => ({
  switchSpare: await spare(deployment.switch),
  chameleonSpare: await spare(deployment.chameleon),
  robberSpare: deployment.robber === undefined ? null : await spare(deployment.robber),
  allowance: await allowanceOf(deployment.switch, flipKey!.publicKey),
  robberAllowance: robberKey === null || deployment.robber === undefined ? null : await allowanceOf(deployment.robber, robberKey.publicKey),
});

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

/** Deletes and re-adds `publicKey` on `accountId` with the same methods and a fresh allowance, in one transaction, so there is no moment without the key. Shared by the flip key and the robber key. */
async function renewAllowance(name: string, accountId: string, publicKey: string, methods: string[], target: string, current: bigint | null, floor: string): Promise<void> {
  if (current === null || current >= yocto(floor) || keysDir === undefined) return;
  try {
    const owner = await accountFor(accountId);
    const key = PublicKey.from(publicKey);
    await owner.signAndSendTransaction({
      receiverId: accountId,
      actions: [actions.deleteKey(key), actions.addFunctionCallAccessKey(key, accountId, methods, yocto(target))],
      waitUntil: "FINAL",
      throwOnFailure: true,
    });
    repairs.push(`${name} allowance renewed to ${target}`);
  } catch (error) {
    problems.push(`${name} allowance renewal failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

await assertTestnetChain(rpc);
await topUp("switch", deployment.switch, SWITCH, state.switchSpare);
await topUp("chameleon", deployment.chameleon, CHAMELEON, state.chameleonSpare);
await renewAllowance("flip", deployment.switch, flipKey!.publicKey, ["flip"], ALLOWANCE.target, state.allowance, ALLOWANCE.floor);
if (deployment.robber !== undefined && robberKey !== null) {
  await topUp("robber", deployment.robber, ROBBER, state.robberSpare ?? 0n);
  await renewAllowance("robber", deployment.robber, robberKey.publicKey, ["on_deposit"], ROBBER_ALLOWANCE.target, state.robberAllowance, ROBBER_ALLOWANCE.floor);
}
if (repairs.length > 0) state = await read();

// Judged on what the chain says after the repairs, whatever the repairs reported.
if (state.switchSpare < yocto(SWITCH.floor)) problems.push(`switch spare ${show(state.switchSpare)} is still below ${SWITCH.floor}`);
if (state.chameleonSpare < yocto(CHAMELEON.floor)) problems.push(`chameleon spare ${show(state.chameleonSpare)} is still below ${CHAMELEON.floor}`);
if (state.allowance !== null && state.allowance < yocto(ALLOWANCE.floor)) problems.push(`flip allowance ${show(state.allowance)} is still below ${ALLOWANCE.floor}`);
if (state.robberSpare !== null && state.robberSpare < yocto(ROBBER.floor)) problems.push(`robber spare ${show(state.robberSpare)} is still below ${ROBBER.floor}`);
if (state.robberAllowance !== null && state.robberAllowance < yocto(ROBBER_ALLOWANCE.floor)) problems.push(`robber allowance ${show(state.robberAllowance)} is still below ${ROBBER_ALLOWANCE.floor}`);

const status = await switchStatus(rpc, deployment);
const healthy = problems.length === 0;
console.log(
  [
    `swap-watchdog ${new Date().toISOString()} ${healthy ? "OK" : "FAIL"}${keysDir === undefined ? " (read-only: PREFLIGHT_TESTNET_KEYS not set)" : ""}`,
    `switch_spare=${show(state.switchSpare)} chameleon_spare=${show(state.chameleonSpare)} flip_allowance=${state.allowance === null ? "unlimited" : show(state.allowance)}`,
    state.robberSpare === null ? "robber=not deployed" : `robber_spare=${show(state.robberSpare)} robber_allowance=${state.robberAllowance === null ? "unlimited" : show(state.robberAllowance)}`,
    `live=${status.live} flips=${status.flips}`,
    repairs.length > 0 ? `repaired: ${repairs.join(", ")}` : "",
    problems.length > 0 ? `problems: ${problems.join("; ")}` : "",
  ]
    .filter(Boolean)
    .join(" | "),
);
process.exit(healthy ? 0 : 1);
