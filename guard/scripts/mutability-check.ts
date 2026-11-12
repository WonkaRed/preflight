// `npm run mutability-check`: read-only, no keys. For each account, who can replace its code (full-access keys), the code hash
// it runs, and the decision the guard gives with the chain-fact checks on. Default: the testnet demo contract
// chameleon.preflight-guard.testnet. Exit status 0 when every account was read, 2 for bad arguments, 3 when the chain could not be read.
//   npm run mutability-check -- [--rpc <url>] [--deployment <file>] [account ...]
import { parseArgs } from "node:util";
import { checkContract, describeMutability, readMutability } from "../src/index.ts";
import { describeError, printable } from "../src/text.ts";
import { DEFAULT_DEPLOYMENT, DEFAULT_TESTNET_RPC, assertTestnetChain, loadDeployment } from "../demo/testnet-deployment.ts";

const USAGE = "usage: mutability-check [--rpc <url>] [--deployment <file>] [account ...]";
const DEFAULT_ACCOUNTS = ["chameleon.preflight-guard.testnet"];

try {
  const { values, positionals } = (() => {
    try {
      return parseArgs({ options: { rpc: { type: "string" }, deployment: { type: "string" } }, allowPositionals: true, strict: true });
    } catch (error) {
      console.error(`${printable(describeError(error))}\n${USAGE}`);
      return process.exit(2);
    }
  })();
  const rpc = values.rpc ?? process.env["PREFLIGHT_TESTNET_RPC"] ?? DEFAULT_TESTNET_RPC;
  await assertTestnetChain(rpc);
  const registryId = (await loadDeployment(values.deployment ?? DEFAULT_DEPLOYMENT)).accounts["registry"] ?? "";
  const guard = { rpcUrl: rpc, registryId, timeoutMs: 20_000, mutability: {} };
  console.log(printable(`Preflight mutability check on testnet, read from ${rpc} (read-only: view_account and view_access_key_list)`));
  for (const accountId of positionals.length > 0 ? positionals : DEFAULT_ACCOUNTS) {
    const facts = await readMutability(accountId, guard);
    if (facts === null) {
      console.log(printable(`${accountId}: no such account`));
      continue;
    }
    const lines = [accountId, `  code hash   ${facts.codeHash ?? (facts.globalPublisher === null ? "none named (the account has no code)" : `none named (follows publisher ${facts.globalPublisher})`)}`, `  ${describeMutability(facts)}`];
    const result = await checkContract(accountId, guard);
    lines.push(`  guard decision (mutability on): ${result.decision}`, ...result.reasons.map((reason) => `    ${reason}`));
    for (const line of lines) console.log(printable(line));
  }
} catch (error) {
  console.error(`mutability-check failed: ${printable(describeError(error))}`);
  process.exit(3);
}
