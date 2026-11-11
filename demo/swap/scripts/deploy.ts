// One-time setup of the Swap on testnet under a parent account you control.
//
//   PREFLIGHT_TESTNET_KEYS=<dir> npm run deploy -- --parent <you>.testnet --wasm-dir <dir> --reports <dir> [--chameleon-near 1.7] [--switch-near 6] [--allowance 3] [--seal]
//
// It creates chameleon.<parent> and switch.<parent>, deploys the vulnerable build on the chameleon and the switch
// (which stores both builds), has the registry's auditor publish the scanner's verdict for each build, and adds the
// flip key to the switch: a function-call key that may call `flip` on the switch and nothing else. With --seal it
// also deletes the chameleon's own full-access key, so that only the switch can ever change its code.
// Private keys go to <dir>/<account>.key and <dir>/swap-flip-public.key (mode 0600) and are never printed. Every
// transaction is recorded in demo/swap/deployment.json as it happens, and a rerun skips the recorded steps.
// TESTNET ONLY: the RPC must report chain_id "testnet".
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs, promisify } from "node:util";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, PublicKey, actions, baseEncode, nearToYocto, teraToGas } from "near-api-js";
import type { Action } from "near-api-js";
import { DEFAULT_TESTNET_RPC, DEPLOYMENT_FILE, assertTestnetChain, chainCodeHash, explorerTxUrl, keyPath, loadSwapDeployment, readSecretKey, type SwapDeployment, viewJson } from "./lib.ts";

const USAGE = "usage: PREFLIGHT_TESTNET_KEYS=<dir> deploy --parent <account>.testnet --wasm-dir <dir> --reports <dir> [--rpc <url>] [--chameleon-near <n>] [--switch-near <n>] [--allowance <n>] [--seal]";
const REPORT_BASE = "https://github.com/WonkaRed/preflight/blob/main/demo/swap/reports";
/** The switch refuses a flip sooner than this after the last one, so a script looping on the page's key cannot thrash the chameleon. */
const MIN_INTERVAL_MS = 10_000;
const PUBLISH_DEPOSIT = "0.01"; // attached to publish_verdict; the registry refunds what the storage does not need
const PACE_MS = 700; // between transactions, so a public RPC is not hit in a burst
/** Index of each build in the switch's Borsh `Build` enum. */
const BUILD_VULNERABLE = 0;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function options() {
  try {
    const { values } = parseArgs({
      options: { parent: { type: "string" }, "wasm-dir": { type: "string" }, reports: { type: "string" }, rpc: { type: "string" }, "chameleon-near": { type: "string" }, "switch-near": { type: "string" }, allowance: { type: "string" }, seal: { type: "boolean" } },
      strict: true,
    });
    const keysDir = process.env["PREFLIGHT_TESTNET_KEYS"];
    if (!keysDir || !values.parent?.endsWith(".testnet") || !values["wasm-dir"] || !values.reports) throw new Error("PREFLIGHT_TESTNET_KEYS, --parent (a .testnet account), --wasm-dir and --reports are required");
    const amount = (name: string, fallback: string): `${number}` => {
      const text = values[name as "allowance"] ?? fallback;
      if (!/^\d+(\.\d{1,24})?$/.test(text)) throw new Error(`--${name} must be a plain decimal amount of NEAR, got ${JSON.stringify(text)}`);
      return text as `${number}`;
    };
    return { keysDir, parent: values.parent, wasmDir: values["wasm-dir"], reports: values.reports, rpc: values.rpc ?? DEFAULT_TESTNET_RPC, chameleonNear: amount("chameleon-near", "1.7"), switchNear: amount("switch-near", "6"), allowance: amount("allowance", "3"), seal: values.seal === true };
  } catch (error) {
    console.error(`${error instanceof Error ? error.message : String(error)}\n${USAGE}`);
    process.exit(2);
  }
}
const { keysDir, parent, wasmDir, reports, rpc, chameleonNear, switchNear, allowance, seal } = options();

const registryId = `registry.${parent}`;
const auditorId = `auditor.${parent}`;
const chameleonId = `chameleon.${parent}`;
const switchId = `switch.${parent}`;
const provider = new JsonRpcProvider({ url: rpc });
const accountFor = async (accountId: string): Promise<Account> => new Account(accountId, provider, KeyPairSigner.fromSecretKey(await readSecretKey(keyPath(keysDir, accountId))));

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

async function loadOrStart(): Promise<SwapDeployment> {
  try {
    const existing = await loadSwapDeployment();
    if (existing.parent !== parent) throw new Error(`${DEPLOYMENT_FILE} belongs to parent ${existing.parent}, not ${parent}`);
    return existing;
  } catch (error) {
    // Only a missing file starts a new record; one that exists but is not a testnet record is never overwritten.
    if ((error as { code?: unknown }).code !== "ENOENT") throw error;
    return { network: "testnet", parent, registry: registryId, auditor: auditorId, chameleon: chameleonId, switch: switchId, codeHashes: { vulnerable: "", patched: "" }, flipKey: null, transactions: [] };
  }
}
const deployment = await loadOrStart();
const save = (): Promise<void> => writeFile(DEPLOYMENT_FILE, `${JSON.stringify(deployment, null, 2)}\n`);
const done = (step: string): boolean => deployment.transactions.some((tx) => tx.step === step);

/** Signs and sends one transaction, waits for it to be final, and records it. */
async function send(step: string, signer: Account, receiver: string, txActions: Action[], what: string): Promise<void> {
  if (done(step)) return console.log(`skip ${step} (already recorded)`);
  const outcome = await signer.signAndSendTransaction({ receiverId: receiver, actions: txActions, waitUntil: "FINAL", throwOnFailure: true });
  const hash = outcome.transaction.hash;
  deployment.transactions.push({ step, signer: signer.accountId, receiver, hash, what });
  await save();
  console.log(`${step}: ${what}\n    ${explorerTxUrl(hash)}`);
  await sleep(PACE_MS);
}

const wasm = async (name: string): Promise<Uint8Array> => new Uint8Array(await readFile(join(wasmDir, `${name}.wasm`)));
const codeHashOf = (code: Uint8Array): string => baseEncode(createHash("sha256").update(code).digest());

// Borsh, by hand: the switch's `new` takes (AccountId, Build, u64, Vec<u8>, Vec<u8>) and nothing else is needed.
const u32 = (n: number): Buffer => {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(n);
  return buffer;
};
const borshBytes = (bytes: Uint8Array): Buffer => Buffer.concat([u32(bytes.length), bytes]);
const borshString = (text: string): Buffer => borshBytes(Buffer.from(text, "utf8"));
const borshU64 = (n: number): Buffer => {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(n));
  return buffer;
};

async function main(): Promise<void> {
  await assertTestnetChain(rpc);
  const parentAccount = await accountFor(parent);
  const vulnerable = await wasm("chameleon_vulnerable");
  const patched = await wasm("chameleon_patched");
  deployment.codeHashes = { vulnerable: codeHashOf(vulnerable), patched: codeHashOf(patched) };

  // 1. The two accounts, each with its own full-access key.
  for (const [accountId, near] of [[chameleonId, chameleonNear], [switchId, switchNear]] as const) {
    const publicKey = await ensureKey(accountId);
    await send(`create-${accountId.split(".")[0]}`, parentAccount, accountId, [actions.createAccount(), actions.transfer(nearToYocto(near)), actions.addFullAccessKey(PublicKey.from(publicKey))], `create ${accountId} with ${near} NEAR (full-access key ${publicKey})`);
  }

  // 2. The chameleon runs the vulnerable build; only the switch may upgrade it. Deploy and `new` in one transaction.
  const chameleon = await accountFor(chameleonId);
  await send("deploy-chameleon", chameleon, chameleonId, [actions.deployContract(vulnerable), actions.functionCall("new", { switch: switchId, treasury: parent }, teraToGas("30"), 0n)], `deploy chameleon_vulnerable on ${chameleonId} and call new({switch, treasury: ${parent}}) in the same transaction`);

  // 3. The switch stores both builds for good and says the vulnerable one is live. Deploy and `new` in one transaction.
  const switchAccount = await accountFor(switchId);
  const init = Buffer.concat([borshString(chameleonId), Buffer.from([BUILD_VULNERABLE]), borshU64(MIN_INTERVAL_MS), borshBytes(vulnerable), borshBytes(patched)]);
  await send("deploy-switch", switchAccount, switchId, [actions.deployContract(await wasm("swap_switch")), actions.functionCall("new", init, teraToGas("300"), 0n)], `deploy swap_switch on ${switchId} and call new(${chameleonId}, vulnerable, ${MIN_INTERVAL_MS} ms, both builds) in the same transaction`);

  // 4. The auditor publishes the scanner's verdict for each build; rule ids come from the scanner's reports.
  const auditor = await accountFor(auditorId);
  for (const role of ["vulnerable", "patched"] as const) {
    const reportFile = `chameleon-${role}.json`;
    const reportBytes = await readFile(join(reports, reportFile));
    const report = JSON.parse(reportBytes.toString("utf8")) as { findings: { rule_id: string }[] };
    const ruleIds = [...new Set(report.findings.map((finding) => finding.rule_id))].sort();
    const verdict = { code_hash: deployment.codeHashes[role], status: ruleIds.length === 0 ? "Safe" : "Unsafe", rule_ids: ruleIds, report_url: `${REPORT_BASE}/${reportFile}`, report_sha256: createHash("sha256").update(reportBytes).digest("hex") };
    await send(`publish-${role}`, auditor, registryId, [actions.functionCall("publish_verdict", verdict, teraToGas("30"), nearToYocto(PUBLISH_DEPOSIT))], `publish ${verdict.status} ${verdict.rule_ids.join(",") || "(no rules)"} for the ${role} build's code hash ${verdict.code_hash}`);
  }

  // 5. The chain must hold exactly what was scanned, hashed and published, and the switch must say the same.
  const onChain = await chainCodeHash(rpc, chameleonId, "optimistic");
  if (onChain !== deployment.codeHashes.vulnerable && onChain !== deployment.codeHashes.patched) throw new Error(`${chameleonId} holds ${onChain}, neither of the builds that were deployed`);
  for (const role of ["vulnerable", "patched"] as const) {
    const verdict = (await viewJson(rpc, registryId, "get_verdict", { code_hash: deployment.codeHashes[role] }, "optimistic")) as { status?: string } | null;
    if (verdict === null) throw new Error(`the registry has no verdict for the ${role} build`);
    console.log(`registry verdict for the ${role} build: ${verdict.status}`);
  }

  // 6. The flip key: made by the guard's scope-key script, `flip` on the switch only, no deposit, a gas allowance.
  const flipKeyFile = keyPath(keysDir, "swap-flip-public");
  if (!done("scope-flip-key")) {
    const { stdout } = await promisify(execFile)(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "..", "..", "..", "guard", "scripts", "scope-key.ts"), "--rpc", rpc, "--account", switchId, "--contract", switchId, "--methods", "flip", "--allowance", allowance, "--out", flipKeyFile], {
      env: { ...process.env, NEAR_OWNER_KEY: await readSecretKey(keyPath(keysDir, switchId)) },
    });
    const publicKey = /^added (ed25519:\S+) to /m.exec(stdout)?.[1];
    const hash = /^transaction (\S+)$/m.exec(stdout)?.[1];
    if (publicKey === undefined || hash === undefined) throw new Error("scope-key printed no key or transaction hash");
    deployment.flipKey = { publicKey, allowanceNear: allowance };
    deployment.transactions.push({ step: "scope-flip-key", signer: switchId, receiver: switchId, hash, what: `add a function-call key (${publicKey}) to ${switchId}: may call flip on ${switchId} only, gas allowance ${allowance} NEAR, no deposit` });
    await save();
    console.log(`scope-flip-key: ${publicKey}\n    ${explorerTxUrl(hash)}`);
  }

  // 7. Only after a flip has been seen to work: nobody, the deployer included, may change the chameleon but the switch.
  if (seal && !done("seal-chameleon")) {
    const keys = (await provider.viewAccessKeyList({ accountId: chameleonId, finalityQuery: { finality: "final" } })).keys;
    const publicKeys = keys.map((key) => key.public_key);
    await send("seal-chameleon", chameleon, chameleonId, publicKeys.map((publicKey) => actions.deleteKey(PublicKey.from(publicKey))), `delete the chameleon's access key(s) ${publicKeys.join(", ")}: only the switch can change its code`);
  }
  await save();
  console.log(`done: ${deployment.transactions.length} transactions recorded in ${DEPLOYMENT_FILE}`);
}

main().catch((error: unknown) => {
  console.error(`deploy failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
