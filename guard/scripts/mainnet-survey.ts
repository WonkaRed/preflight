// `npm run mainnet-survey`: read-only, no keys, no transactions. For each well-known NEAR mainnet contract, the hash of
// the code it runs and how many full-access keys the account holds, written as a table to docs/mainnet-survey.md. Facts only:
// the page says nothing about what any contract does. Exit status 0 when the page was written, 1 when an account did not exist or had no code
// (nothing is written), 2 for bad arguments, 3 when the chain could not be read.
//   npm run mainnet-survey -- [--rpc <url>] [--out <file>] [account ...]
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { MUTABILITY_LIMITS, readMutability } from "../src/index.ts";
import { describeError, printable } from "../src/text.ts";
import { isValidAccountId } from "../src/validate.ts";

const USAGE = "usage: mainnet-survey [--rpc <url>] [--out <file>] [account ...]";
/** Free, keyless public endpoint, the one the scanner and the MCP server default to. */
const DEFAULT_MAINNET_RPC = "https://free.rpc.fastnear.com";
const DEFAULT_OUT = join(import.meta.dirname, "..", "..", "docs", "mainnet-survey.md");
/** Widely used contracts, each checked to exist and hold code before it was listed here (burrow.near holds none; the Burrow contract is on contract.main.burrow.near). */
const ACCOUNTS = ["wrap.near", "v2.ref-finance.near", "aurora", "meta-pool.near", "linear-protocol.near", "usdt.tether-token.near", "intents.near", "contract.main.burrow.near", "token.sweat", "app.nearcrowd.near"];

async function assertMainnetChain(rpc: string): Promise<void> {
  const response = await fetch(rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "preflight", method: "status", params: [] }), signal: AbortSignal.timeout(15_000) });
  const body = (await response.json()) as { result?: { chain_id?: unknown } };
  if (body.result?.chain_id !== "mainnet") throw new Error(`${rpc} reports chain_id ${JSON.stringify(body.result?.chain_id)}, not "mainnet"`);
}

try {
  const { values, positionals } = (() => {
    try {
      return parseArgs({ options: { rpc: { type: "string" }, out: { type: "string" } }, allowPositionals: true, strict: true });
    } catch (error) {
      console.error(`${printable(describeError(error))}\n${USAGE}`);
      return process.exit(2);
    }
  })();
  const accounts = positionals.length > 0 ? positionals : ACCOUNTS;
  const bad = accounts.find((id) => !isValidAccountId(id));
  if (bad !== undefined) {
    console.error(`${printable(bad)} is not a valid account id\n${USAGE}`);
    process.exit(2);
  }
  const rpc = values.rpc ?? process.env["PREFLIGHT_MAINNET_RPC"] ?? DEFAULT_MAINNET_RPC;
  await assertMainnetChain(rpc);
  const date = new Date().toISOString().slice(0, 10);
  const rows: string[] = [];
  const unusable: string[] = [];
  for (const accountId of accounts) {
    const facts = await readMutability(accountId, { rpcUrl: rpc, registryId: "registry.invalid", timeoutMs: 20_000 });
    if (facts === null || (facts.codeHash === null && facts.globalPublisher === null)) {
      unusable.push(`${accountId} ${facts === null ? "does not exist" : "holds no code"}`);
      continue;
    }
    const code = facts.codeHash ?? `global contract published by ${facts.globalPublisher}`;
    rows.push(`| \`${accountId}\` | \`${code}\` | ${facts.fullAccessKeys} | ${date} |`);
    console.log(printable(`${accountId}  ${code}  ${facts.fullAccessKeys} full-access key(s)`));
  }
  if (unusable.length > 0) {
    console.error(printable(`not written: ${unusable.join("; ")}`));
    process.exit(1);
  }
  const page = `# Mainnet survey: can the code at a well-known address be replaced by a key?

Having a key that can replace code is a design choice, not a defect; this table only shows that an address alone does not pin the code.

Read on ${date} from NEAR mainnet through the RPC endpoint ${new URL(rpc).host}, with read-only calls (\`view_account\`, \`view_access_key_list\`): no keys, no transactions. The code hash is the base58 SHA-256 of the deployed wasm that the account reports. A full-access key can deploy new code to its account at any time; the count is the number of such keys the account holds on the date read.

| Account | Code hash | Full-access keys | Date read |
|---|---|---|---|
${rows.join("\n")}

${MUTABILITY_LIMITS} A count of 0 therefore shows only that the account holds no full-access key, not that nothing can replace its code.

Reproduce it with \`make -C guard mainnet-survey\`. The table is a snapshot: a later read can differ.
`;
  await writeFile(values.out ?? DEFAULT_OUT, page);
  console.log(printable(`wrote ${rows.length} rows to ${values.out ?? DEFAULT_OUT}`));
} catch (error) {
  console.error(`mainnet-survey failed: ${printable(describeError(error))}`);
  process.exit(3);
}
