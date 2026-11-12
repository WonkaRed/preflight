// One-time setup of the "Rob it" throwaway attacker account on testnet, under the same parent as deploy.ts.
//
//   PREFLIGHT_TESTNET_KEYS=<dir> npm run deploy-robber -- --parent <you>.testnet [--near 1.5] [--allowance 1]
//
// It creates robber.<parent> with its own full-access key (so the watchdog can renew its scoped key's allowance the
// same way it renews the switch's flip key), then adds a function-call key limited to `on_deposit` on the chameleon:
// no deposit (a function-call key can never attach one), a small gas allowance. That key's secret is PUBLIC ON
// PURPOSE: it is embedded in the page, same model as the flip key.
// It also sends one real, tiny `deposit()` from the robber's own full-access key: `on_deposit` only ever updates an
// existing balance entry (`LookupMap::get_mut`), so without this one-time deposit the forged credit the page's key
// sends would land on no entry and do nothing. This is the only NEAR the robber account ever spends on a deposit;
// every later "Rob it" click forges a credit on top of it with no deposit of its own.
// Private keys go to <dir>/robber.<parent>.key and <dir>/swap-robber-public.key (mode 0600) and are never printed.
// Every transaction is recorded in demo/swap/deployment.json as it happens, and a rerun skips the recorded steps.
// TESTNET ONLY: the RPC must report chain_id "testnet".
import { writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { join } from "node:path";
import { parseArgs, promisify } from "node:util";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, PublicKey, actions, nearToYocto, teraToGas } from "near-api-js";
import { DEFAULT_TESTNET_RPC, DEPLOYMENT_FILE, assertTestnetChain, explorerTxUrl, keyPath, loadSwapDeployment, readSecretKey } from "./lib.ts";

const USAGE = "usage: PREFLIGHT_TESTNET_KEYS=<dir> deploy-robber --parent <account>.testnet [--rpc <url>] [--near <n>] [--allowance <n>]";
const ROB_METHOD = "on_deposit";
// Enough to clear the 1% fee and the storage of one new balance entry with room to spare; the rest is the robber's
// own real, counted balance (not part of any forged credit).
const SEED_DEPOSIT_NEAR = "0.05";
const SEED_DEPOSIT_GAS = teraToGas("50");

function options() {
  try {
    const { values } = parseArgs({ options: { parent: { type: "string" }, rpc: { type: "string" }, near: { type: "string" }, allowance: { type: "string" } }, strict: true });
    const keysDir = process.env["PREFLIGHT_TESTNET_KEYS"];
    if (!keysDir || !values.parent?.endsWith(".testnet")) throw new Error("PREFLIGHT_TESTNET_KEYS and --parent (a .testnet account) are required");
    const amount = (name: string, fallback: string): `${number}` => {
      const text = values[name as "near"] ?? fallback;
      if (!/^\d+(\.\d{1,24})?$/.test(text)) throw new Error(`--${name} must be a plain decimal amount of NEAR, got ${JSON.stringify(text)}`);
      return text as `${number}`;
    };
    return { keysDir, parent: values.parent, rpc: values.rpc ?? DEFAULT_TESTNET_RPC, near: amount("near", "1.5"), allowance: amount("allowance", "1") };
  } catch (error) {
    console.error(`${error instanceof Error ? error.message : String(error)}\n${USAGE}`);
    process.exit(2);
  }
}
const { keysDir, parent, rpc, near, allowance } = options();

const robberId = `robber.${parent}`;
const provider = new JsonRpcProvider({ url: rpc });

/** The public key of an account's key file; a missing file is a new key, written there (never overwritten, never printed). */
async function ensureKey(accountId: string): Promise<string> {
  const path = keyPath(keysDir, accountId);
  try {
    return KeyPair.fromString(await readSecretKey(path)).getPublicKey().toString();
  } catch (error) {
    if (!String(error).includes("cannot read the key file")) throw error;
  }
  const key = KeyPair.fromRandom("ed25519");
  await writeFile(path, `${key.toString()}\n`, { flag: "wx", mode: 0o600 });
  return key.getPublicKey().toString();
}

const deployment = await loadSwapDeployment();
if (deployment.parent !== parent) throw new Error(`${DEPLOYMENT_FILE} belongs to parent ${deployment.parent}, not ${parent}`);
const save = (): Promise<void> => writeFile(DEPLOYMENT_FILE, `${JSON.stringify(deployment, null, 2)}\n`);
const done = (step: string): boolean => deployment.transactions.some((tx) => tx.step === step);

async function send(step: string, signer: Account, receiver: string, txActions: Parameters<Account["signAndSendTransaction"]>[0]["actions"], what: string): Promise<void> {
  if (done(step)) return console.log(`skip ${step} (already recorded)`);
  const outcome = await signer.signAndSendTransaction({ receiverId: receiver, actions: txActions, waitUntil: "FINAL", throwOnFailure: true });
  const hash = outcome.transaction.hash;
  deployment.transactions.push({ step, signer: signer.accountId, receiver, hash, what });
  await save();
  console.log(`${step}: ${what}\n    ${explorerTxUrl(hash)}`);
}

async function main(): Promise<void> {
  await assertTestnetChain(rpc);
  const parentAccount = new Account(parent, provider, KeyPairSigner.fromSecretKey(await readSecretKey(keyPath(keysDir, parent))));

  // 1. The throwaway account, with its own full-access key, so its scoped key can be renewed later the way the switch renews the flip key.
  const robberKey = await ensureKey(robberId);
  await send("create-robber", parentAccount, robberId, [actions.createAccount(), actions.transfer(nearToYocto(near)), actions.addFullAccessKey(PublicKey.from(robberKey))], `create ${robberId} with ${near} NEAR (full-access key ${robberKey})`);

  // 2. The scoped key the page embeds: made by the guard's scope-key script, `on_deposit` on the chameleon only, no deposit, a gas allowance.
  const robberScopedFile = keyPath(keysDir, "swap-robber-public");
  if (!done("scope-robber-key")) {
    const { stdout } = await promisify(execFile)(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "..", "..", "..", "guard", "scripts", "scope-key.ts"), "--rpc", rpc, "--account", robberId, "--contract", deployment.chameleon, "--methods", ROB_METHOD, "--allowance", allowance, "--out", robberScopedFile], {
      env: { ...process.env, NEAR_OWNER_KEY: await readSecretKey(keyPath(keysDir, robberId)) },
    });
    const publicKey = /^added (ed25519:\S+) to /m.exec(stdout)?.[1];
    const hash = /^transaction (\S+)$/m.exec(stdout)?.[1];
    if (publicKey === undefined || hash === undefined) throw new Error("scope-key printed no key or transaction hash");
    deployment.robber = robberId;
    deployment.robberKey = { publicKey, allowanceNear: allowance };
    deployment.transactions.push({ step: "scope-robber-key", signer: robberId, receiver: robberId, hash, what: `add a function-call key (${publicKey}) to ${robberId}: may call ${ROB_METHOD} on ${deployment.chameleon} only, gas allowance ${allowance} NEAR, no deposit` });
    await save();
    console.log(`scope-robber-key: ${publicKey}\n    ${explorerTxUrl(hash)}`);
  }

  // 3. One real, tiny deposit so the robber account has a balance entry for `on_deposit` to forge a credit onto.
  const robberAccount = new Account(robberId, provider, KeyPairSigner.fromSecretKey(await readSecretKey(keyPath(keysDir, robberId))));
  await send("seed-robber-deposit", robberAccount, deployment.chameleon, [actions.functionCall("deposit", {}, SEED_DEPOSIT_GAS, nearToYocto(SEED_DEPOSIT_NEAR))], `${robberId} deposits ${SEED_DEPOSIT_NEAR} NEAR into ${deployment.chameleon} for real, creating the balance entry "Rob it" forges a credit onto`);
  await save();
  console.log(`done: ${deployment.transactions.length} transactions recorded in ${DEPLOYMENT_FILE}`);
}

main().catch((error: unknown) => {
  console.error(`deploy-robber failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
