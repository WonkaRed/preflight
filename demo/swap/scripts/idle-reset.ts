// Puts the chameleon back on the patched build when it has sat on the vulnerable build for more than 10 minutes with no
// swap in that time, so the next visitor to the web page arrives to a contract that is fine (ALLOW from both checks) and
// watches the swap to the vulnerable build turn Preflight to BLOCK while the address check keeps saying ALLOW, and not on a
// state a previous visitor left. Run it on a timer (systemd/preflight-swap-idle-reset.timer).
//
//   PREFLIGHT_TESTNET_KEYS=<dir> npm run idle-reset [-- --idle-minutes 10] [--dry-run]       (or: make -C demo/swap idle-reset)
//
// It signs with the same public flip key the web page uses (<dir>/swap-flip-public.key), so the gas comes from that key's
// allowance, which the watchdog renews. It sends at most one transaction per run, and it reads the switch and the chain
// again right before sending: a visitor who swapped in the meantime leaves it nothing to do. A flip this script sends
// while a visitor's flip is a few seconds old is refused by the switch's own 20 s interval and changes nothing, so the
// two can never undo each other.
// It prints one line, `swap-idle-reset <time> <ACTION> | ...`, and exits 0 for every outcome except a failure (an unreadable
// chain, a missing key, a flip that failed for a reason other than a visitor swapping first): 1, and 2 on a usage error.
// TESTNET ONLY: the RPC must report chain_id "testnet".
import { parseArgs } from "node:util";
import { JsonRpcProvider } from "near-api-js";
import { DEFAULT_TESTNET_RPC, assertTestnetChain, chainCodeHash, explorerTxUrl, keyPath, loadSwapDeployment, readSecretKey, sendFlip, switchStatus } from "./lib.ts";
import type { SwapDeployment } from "./lib.ts";

const DEFAULT_IDLE_MINUTES = 10;
const FLIP_KEY_FILE = "swap-flip-public";

let values;
try {
  ({ values } = parseArgs({ options: { rpc: { type: "string" }, "idle-minutes": { type: "string" }, "dry-run": { type: "boolean" } }, strict: true }));
} catch (error) {
  console.error(`${error instanceof Error ? error.message : String(error)}\nusage: PREFLIGHT_TESTNET_KEYS=<dir> idle-reset [--rpc <url>] [--idle-minutes <n>] [--dry-run]`);
  process.exit(2);
}
const rpc = values.rpc ?? DEFAULT_TESTNET_RPC;
const idleMinutes = values["idle-minutes"] === undefined ? DEFAULT_IDLE_MINUTES : Number(values["idle-minutes"]);
if (!Number.isFinite(idleMinutes) || idleMinutes < 1) {
  console.error(`--idle-minutes must be a number of at least 1, not ${values["idle-minutes"]}`);
  process.exit(2);
}
const dryRun = values["dry-run"] === true;
const keysDir = process.env["PREFLIGHT_TESTNET_KEYS"];
if (keysDir === undefined && !dryRun) {
  console.error("PREFLIGHT_TESTNET_KEYS is not set: it names the directory that holds swap-flip-public.key (use --dry-run to only read)");
  process.exit(2);
}

const provider = new JsonRpcProvider({ url: rpc });

interface Snapshot {
  /** What the chain runs, by code hash: the truth, where the switch's `live` is a record kept one receipt later. */
  onChain: "vulnerable" | "patched" | "unknown";
  /** What the switch records as live. */
  recorded: "vulnerable" | "patched";
  /** Milliseconds, on chain time, since the switch last accepted a flip (it stamps the flip before the upgrade runs). */
  idleMs: number;
  flips: number;
}

/** Everything the decision rests on, read at optimistic finality so a swap that has only just landed is seen. */
async function snapshot(deployment: SwapDeployment): Promise<Snapshot> {
  const [status, hash, block] = await Promise.all([
    switchStatus(rpc, deployment, "optimistic"),
    chainCodeHash(rpc, deployment.chameleon, "optimistic"),
    provider.viewBlock({ finality: "optimistic" }),
  ]);
  const nowMs = Number(BigInt(String(block.header.timestamp_nanosec)) / 1_000_000n);
  const onChain = hash === deployment.codeHashes.vulnerable ? "vulnerable" : hash === deployment.codeHashes.patched ? "patched" : "unknown";
  return { onChain, recorded: status.live, idleMs: nowMs - status.last_flip_ms, flips: status.flips };
}

/** Why there is nothing to do, or null when the chameleon should be put back: vulnerable, recorded as vulnerable, and quiet for long enough. */
function reasonToWait(state: Snapshot): string | null {
  if (state.onChain === "unknown") return "the chain runs a build this script does not know";
  if (state.onChain === "patched") return "the patched build is live";
  if (state.recorded !== "vulnerable") return "a swap is still landing";
  if (state.idleMs <= idleMinutes * 60_000) return `a swap ran ${Math.round(state.idleMs / 1000)} s ago, inside the ${idleMinutes} minutes`;
  return null;
}

const describe = (state: Snapshot): string => `chain=${state.onChain} recorded=${state.recorded} last_swap_s_ago=${Math.round(state.idleMs / 1000)} flips=${state.flips}`;
const line = (action: string, ...rest: string[]): string => [`swap-idle-reset ${new Date().toISOString()} ${action}`, ...rest].join(" | ");

try {
  await assertTestnetChain(rpc);
  const deployment = await loadSwapDeployment();
  const first = await snapshot(deployment);
  const wait = reasonToWait(first);
  if (wait !== null) {
    console.log(line("OK nothing to do", describe(first), wait));
    process.exit(0);
  }
  // A visitor may have swapped while this run was starting: decide again on a fresh read, and send nothing if it changed.
  const second = await snapshot(deployment);
  const waitNow = reasonToWait(second);
  if (waitNow !== null) {
    console.log(line("OK skipped", describe(second), `changed since the first read: ${waitNow}`));
    process.exit(0);
  }
  if (dryRun) {
    console.log(line("DRY RUN would reset", describe(second)));
    process.exit(0);
  }
  const secretKey = await readSecretKey(keyPath(keysDir ?? "", FLIP_KEY_FILE));
  try {
    const { hash } = await sendFlip(rpc, deployment.switch, secretKey);
    const after = await snapshot(deployment);
    console.log(line("RESET to the patched build", describe(second), `tx=${hash} ${explorerTxUrl(hash)}`, `now: ${describe(after)}`));
    process.exit(after.onChain === "patched" ? 0 : 1);
  } catch (error) {
    // A visitor's swap that landed first makes the switch refuse this one as too soon: the goal is met, and nothing was sent twice.
    const message = error instanceof Error ? error.message : String(error);
    const after = await snapshot(deployment);
    if (/too soon/.test(message) && after.onChain === "patched") {
      console.log(line("OK skipped", describe(after), "a visitor swapped first; this flip was refused as too soon"));
      process.exit(0);
    }
    throw error;
  }
} catch (error) {
  console.error(line("FAIL", error instanceof Error ? error.message : String(error)));
  process.exit(1);
}
