// One-time setup of the Preflight testnet deployment under a parent testnet account you control.
//
//   PREFLIGHT_TESTNET_KEYS=<dir> npm run testnet-deploy -- --parent <you>.testnet --wasm-dir <dir with the four wasm files>
//
// It creates the sub-accounts, deploys and initialises the registry, deploys the three shops, has the auditor publish
// a verdict for each audited build, scopes the agent's function-call keys with the repo's scope-key script, funds
// escrow orders, and finally deletes the registry's access keys. Every private key goes to <dir>/<account>.key (mode
// 0600) and is never printed. Every transaction is written to --out (default docs/testnet-deployment.json) as it
// happens, and a rerun skips the steps already recorded there. TESTNET ONLY: the RPC must report chain_id "testnet".
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { parseArgs, promisify } from "node:util";
import { Account, JsonRpcProvider, KeyPair, KeyPairSigner, PublicKey, actions, nearToYocto, teraToGas, type Action } from "near-api-js";
import { codeHashOf } from "../src/check.ts";
import { rpcQuery } from "../src/rpc.ts";
import { describeError, printable } from "../src/text.ts";
import { isValidAccountId } from "../src/validate.ts";
import {
  DEFAULT_DEPLOYMENT,
  DEFAULT_TESTNET_RPC,
  SHOP_ROLES,
  assertTestnetChain,
  sendSigned,
  chainCodeHash,
  loadDeployment,
  explorerTxUrl,
  keyPath,
  readSecretKey,
  viewJson,
  type Deployment,
  type ShopRole,
} from "../demo/testnet-deployment.ts";

const USAGE = "usage: PREFLIGHT_TESTNET_KEYS=<dir> testnet-deploy --parent <account>.testnet --wasm-dir <dir> [--rpc <url>] [--out <file>] [--reports <dir>] [--report-base <https url>] [--more-orders <n>]";

interface Options {
  keysDir: string;
  parent: string;
  wasmDir: string;
  rpc: string;
  out: string;
  reports: string;
  reportBase: string;
  moreOrders: number;
}

function options(): Options {
  try {
    const { values } = parseArgs({
      options: {
        parent: { type: "string" },
        "wasm-dir": { type: "string" },
        rpc: { type: "string" },
        out: { type: "string" },
        reports: { type: "string" },
        "report-base": { type: "string" },
        "more-orders": { type: "string" },
      },
      strict: true,
    });
    const keysDir = process.env["PREFLIGHT_TESTNET_KEYS"];
    const parent = values.parent;
    const wasmDir = values["wasm-dir"];
    if (!keysDir || !parent?.endsWith(".testnet") || !isValidAccountId(parent) || !wasmDir) throw new Error("PREFLIGHT_TESTNET_KEYS, --parent (a .testnet account) and --wasm-dir are required");
    const moreOrders = values["more-orders"] === undefined ? 0 : Number(values["more-orders"]);
    if (!Number.isInteger(moreOrders) || moreOrders < 0 || moreOrders > 40) throw new Error("--more-orders must be a whole number from 0 to 40");
    return {
      keysDir,
      parent,
      wasmDir,
      rpc: values.rpc ?? process.env["PREFLIGHT_TESTNET_RPC"] ?? DEFAULT_TESTNET_RPC,
      out: values.out ?? DEFAULT_DEPLOYMENT,
      reports: values.reports ?? join(import.meta.dirname, "..", "..", "docs", "testnet-reports"),
      reportBase: values["report-base"] ?? "https://github.com/WonkaRed/preflight/blob/main/docs/testnet-reports",
      moreOrders,
    };
  } catch (error) {
    console.error(`${printable(describeError(error))}\n${USAGE}`);
    process.exit(2);
  }
}
const { keysDir, parent, wasmDir, rpc, out, reports, reportBase, moreOrders } = options();

// Sizes, in NEAR. A contract account must hold its code's storage (1 NEAR per 100 KB) plus a margin for state and gas:
// the wasm files are about 140 KB, so 2 NEAR covers each with room. The agent pays for the escrow orders it funds.
const FUNDING: Record<string, `${number}`> = { registry: "2", auditor: "0.5", "shop-vulnerable": "2", "shop-patched": "2", "shop-swapped": "2", agent: "1.5", payee: "0.1" };
const ORDER_DEPOSIT = "0.05"; // per escrow order
const FIRST_ORDERS = 12; // funded on the patched shop; the demo uses one per run
const PUBLISH_DEPOSIT = "0.01"; // attached to publish_verdict; the registry refunds what the storage does not need
const PACE_MS = 700; // between transactions, so a public RPC is not hit in a burst
const RATE_LIMIT_WAITS_MS = [2_000, 4_000, 8_000, 16_000, 32_000]; // after an HTTP 429 on a send

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const id = (role: string): string => `${role}.${parent}`;
/** An account id of the record by role; a role the record lacks is a corrupt record, not a default. */
const acct = (role: string): string => {
  const accountId = deployment.accounts[role];
  if (accountId === undefined) throw new Error(`${out} has no account for ${role}`);
  return accountId;
};
const log = (text: string): void => {
  for (const line of text.split("\n")) console.log(printable(line));
};

const provider = new JsonRpcProvider({ url: rpc });
const accountFor = async (accountId: string): Promise<Account> => new Account(accountId, provider, KeyPairSigner.fromSecretKey(await readSecretKey(keyPath(keysDir, accountId))));

/** The key of an account: the one on disk, or a new one written there (never overwritten, never printed). */
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

async function loadOrStart(): Promise<Deployment> {
  try {
    return await loadDeployment(out);
  } catch (error) {
    // Only a missing file starts a new record; one that exists but is not a testnet record is never overwritten.
    if ((error as { code?: unknown }).code !== "ENOENT") throw error;
    return {
      network: "testnet",
      deployedAt: new Date().toISOString(),
      parent,
      accounts: { registry: id("registry"), auditor: id("auditor"), agent: id("agent"), payee: id("payee"), ...Object.fromEntries(SHOP_ROLES.map((role) => [role, id(`shop-${role}`)])) },
      codeHashes: {},
      agentKeys: { vulnerable: "", patched: "", swapped: "" },
      orders: { patched: [], vulnerable: [] },
      transactions: [],
    };
  }
}

const deployment = await loadOrStart();
if (deployment.parent !== parent) throw new Error(`${out} belongs to parent ${deployment.parent}, not ${parent}`);
const save = async (): Promise<void> => {
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, `${JSON.stringify(deployment, null, 2)}\n`);
};
const done = (step: string): boolean => deployment.transactions.some((tx) => tx.step === step);

/** Signs and sends one transaction (see `sendSigned`: a 429 resends the same signed bytes) and records it. */
async function send(step: string, signer: Account, receiver: string, txActions: Action[], what: string): Promise<void> {
  if (done(step)) return log(`skip ${step} (already recorded)`);
  const hash = await sendSigned(signer, receiver, txActions, RATE_LIMIT_WAITS_MS, (wait) => log(`rate limited (HTTP 429) on ${step}; waiting ${wait} ms, then sending the same signed transaction again`));
  deployment.transactions.push({ step, signer: signer.accountId, receiver, hash, what });
  await save();
  log(`${step}: ${what}\n    ${explorerTxUrl(hash)}`);
  await sleep(PACE_MS);
}

const wasm = async (name: string): Promise<Uint8Array> => new Uint8Array(await readFile(join(wasmDir, `${name}.wasm`)));

async function main(): Promise<void> {
  await assertTestnetChain(rpc);
  const parentAccount = await accountFor(parent);
  const balance = BigInt(String((await rpcQuery(rpc, { request_type: "view_account", finality: "final", account_id: parent }))["amount"]));
  const need = Object.values(FUNDING).reduce((sum, near) => sum + nearToYocto(near), 0n) + nearToYocto("1");
  if (!done("create-registry") && balance < need) throw new Error(`${parent} holds ${balance} yoctoNEAR; the setup needs about ${need}`);

  // 1. Sub-accounts, each with its own full-access key.
  for (const [name, near] of Object.entries(FUNDING)) {
    const accountId = id(name);
    const publicKey = await ensureKey(accountId);
    await send(`create-${name}`, parentAccount, accountId, [actions.createAccount(), actions.transfer(nearToYocto(near)), actions.addFullAccessKey(PublicKey.from(publicKey))], `create ${accountId} with ${near} NEAR (full-access key ${publicKey})`);
  }

  // 2. The registry: deploy and initialise in one transaction, so nobody can call `new` in between.
  const registryWasm = await wasm("registry");
  const registry = await accountFor(acct("registry"));
  deployment.codeHashes["registry"] = codeHashOf(registryWasm);
  await send("deploy-registry", registry, registry.accountId, [actions.deployContract(registryWasm), actions.functionCall("new", { auditors: [acct("auditor")] }, teraToGas("30"), 0n)], "deploy the registry and call new({auditors:[auditor]}) in the same transaction");

  // 3. The shops. shop-swapped first gets the patched build, the one that is audited.
  const builds: Record<ShopRole, string> = { vulnerable: "pf001_callback_vulnerable", patched: "pf001_callback_patched", swapped: "pf001_callback_patched" };
  for (const role of SHOP_ROLES) {
    const code = await wasm(builds[role]);
    const shop = await accountFor(acct(role));
    await send(`deploy-${role}`, shop, shop.accountId, [actions.deployContract(code), actions.functionCall("new", {}, teraToGas("30"), 0n)], `deploy ${builds[role]} on ${shop.accountId} and call new()`);
  }
  deployment.codeHashes["vulnerable"] = codeHashOf(await wasm("pf001_callback_vulnerable"));
  deployment.codeHashes["patched"] = codeHashOf(await wasm("pf001_callback_patched"));
  deployment.codeHashes["swappedAudited"] = deployment.codeHashes["patched"];
  await save();

  // 4. The auditor publishes a verdict per audited build; rule ids come from the scanner's reports.
  const auditor = await accountFor(acct("auditor"));
  for (const role of ["vulnerable", "patched"] as const) {
    const reportFile = `shop-${role}.json`;
    const reportBytes = await readFile(join(reports, reportFile));
    const report = JSON.parse(reportBytes.toString("utf8")) as { findings: { rule_id: string }[] };
    const ruleIds = [...new Set(report.findings.map((finding) => finding.rule_id))].sort();
    const verdict = { code_hash: deployment.codeHashes[role], status: ruleIds.length === 0 ? "Safe" : "Unsafe", rule_ids: ruleIds, report_url: `${reportBase}/${reportFile}`, report_sha256: createHash("sha256").update(reportBytes).digest("hex") };
    await send(`publish-${role}`, auditor, acct("registry"), [actions.functionCall("publish_verdict", verdict, teraToGas("30"), nearToYocto(PUBLISH_DEPOSIT))], `publish ${verdict.status} ${verdict.rule_ids.join(",") || "(no rules)"} for ${role}'s code hash ${verdict.code_hash}`);
  }

  // 5. The swap: the account that held the audited build is redeployed with other code, which has no verdict.
  const swapped = await accountFor(acct("swapped"));
  await send("swap-swapped", swapped, swapped.accountId, [actions.deployContract(await wasm("pf003_promise_result_patched"))], `redeploy ${swapped.accountId} with different code (pf003_promise_result_patched): the audited build is gone, the new one has no verdict`);
  deployment.codeHashes["swapped"] = codeHashOf(await wasm("pf003_promise_result_patched"));

  // 6. The agent's function-call keys, made by the repo's scope-key script: `release` on one shop each, no deposit.
  const agentId = acct("agent");
  for (const role of SHOP_ROLES) {
    const step = `scope-key-${role}`;
    const keyFile = keyPath(keysDir, `agent-key-for-${role}`);
    if (done(step)) {
      log(`skip ${step} (already recorded)`);
      continue;
    }
    const { stdout } = await promisify(execFile)(process.execPath, ["--disable-warning=ExperimentalWarning", join(import.meta.dirname, "scope-key.ts"), "--rpc", rpc, "--account", agentId, "--contract", acct(role), "--methods", "release", "--allowance", "0.25", "--out", keyFile], {
      env: { ...process.env, NEAR_OWNER_KEY: await readSecretKey(keyPath(keysDir, agentId)) },
    });
    const publicKey = /^added (ed25519:\S+) to /m.exec(stdout)?.[1];
    const hash = /^transaction (\S+)$/m.exec(stdout)?.[1];
    if (publicKey === undefined || hash === undefined) throw new Error(`scope-key printed no key or transaction hash for ${role}`);
    deployment.agentKeys[role] = publicKey;
    deployment.transactions.push({ step, signer: agentId, receiver: agentId, hash, what: `add a function-call key (${publicKey}) to ${agentId}: may call release on ${acct(role)} only, gas allowance 0.25 NEAR, no deposit` });
    await save();
    log(`${step}: ${publicKey}\n    ${explorerTxUrl(hash)}`);
    await sleep(PACE_MS);
  }

  // 7. Escrow orders, funded by the agent account (the buyer, the only account that may release them).
  const agent = await accountFor(agentId);
  const fund = async (role: "patched" | "vulnerable", ids: number[], step: string): Promise<void> => {
    await send(step, agent, acct(role), ids.map((order) => actions.functionCall("fund_order", { id: order, seller: acct("payee") }, teraToGas("10"), nearToYocto(ORDER_DEPOSIT))), `fund escrow order${ids.length > 1 ? "s" : ""} ${ids.join(",")} on ${acct(role)}, ${ORDER_DEPOSIT} NEAR each, payee ${acct("payee")}`);
    deployment.orders[role].push(...ids);
  };
  if (!done("fund-patched")) await fund("patched", Array.from({ length: FIRST_ORDERS }, (_, index) => index + 1), "fund-patched");
  if (!done("fund-vulnerable")) await fund("vulnerable", [1], "fund-vulnerable");
  if (moreOrders > 0) {
    const first = Math.max(0, ...deployment.orders.patched) + 1;
    await fund("patched", Array.from({ length: moreOrders }, (_, index) => first + index), `fund-patched-more-${first}`);
  }

  // 8. Check the chain against what was deployed, then seal the registry.
  for (const [name, accountId] of [["registry", "registry"], ["vulnerable", "vulnerable"], ["patched", "patched"], ["swapped", "swapped"]] as const) {
    const onChain = await chainCodeHash(rpc, acct(accountId), "optimistic");
    if (onChain !== deployment.codeHashes[name]) throw new Error(`${acct(accountId)} holds ${onChain}, not the ${deployment.codeHashes[name]} that was deployed`);
  }
  const registryId = acct("registry");
  for (const role of ["vulnerable", "patched"] as const) {
    const verdict = (await viewJson(rpc, registryId, "get_verdict", { code_hash: deployment.codeHashes[role] }, "optimistic")) as { status?: string } | null;
    if (verdict === null) throw new Error(`the registry has no verdict for ${role}`);
    log(`registry verdict for ${role}: ${verdict.status}`);
  }
  if (!done("seal-registry")) {
    const keys = await rpcQuery(rpc, { request_type: "view_access_key_list", finality: "optimistic", account_id: registryId });
    const publicKeys = (keys["keys"] as { public_key: string }[]).map((key) => key.public_key);
    await send("seal-registry", registry, registryId, publicKeys.map((publicKey) => actions.deleteKey(PublicKey.from(publicKey))), `delete the registry's access key(s) ${publicKeys.join(", ")}: nobody can redeploy or change it`);
  }
  await save();
  log(`done: ${deployment.transactions.length} transactions recorded in ${out}`);
}

main().catch((error: unknown) => {
  console.error(`testnet-deploy failed: ${printable(describeError(error))}`);
  process.exit(1);
});
