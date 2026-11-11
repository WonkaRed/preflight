// Adds a function-call key, limited to one contract and named methods, to an account.
//   NEAR_OWNER_KEY=ed25519:... npm run scope-key -- --rpc <url> --account <id> --contract <id> --methods a,b --allowance <NEAR> --out <file>
// The owner key is read from the environment (never argv, which shows up in `ps`). The new secret key goes to
// --out (created with mode 0600, never overwritten) and is not printed.
import { stat, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { nearToYocto } from "near-api-js";
import { addScopedKey } from "../src/scope-key.ts";
import { describeError, printable } from "../src/text.ts";

const USAGE = "usage: NEAR_OWNER_KEY=ed25519:... scope-key --rpc <url> --account <id> --contract <id> --methods a,b --allowance <NEAR> --out <file>";

/** A bad option prints the escaped parser message and the usage, not a stack trace; argv is text the operator typed, but it is still printed through `printable`. */
function parse() {
  try {
    return parseArgs({
      options: {
        rpc: { type: "string" },
        account: { type: "string" },
        contract: { type: "string" },
        methods: { type: "string" },
        allowance: { type: "string" },
        out: { type: "string" },
      },
      strict: true,
    }).values;
  } catch (error) {
    console.error(`${printable(describeError(error))}\n${USAGE}`);
    process.exit(2);
  }
}

const values = parse();
const ownerKey = process.env["NEAR_OWNER_KEY"];
const { rpc, account, contract, methods, allowance, out } = values;
if (!ownerKey?.startsWith("ed25519:") || !rpc || !account || !contract || !methods || !allowance || !out) {
  console.error(USAGE);
  process.exit(2);
}

try {
  // nearToYocto reads "1,5" as 15 and accepts other shapes too: only plain decimals (at most 24 places) get through.
  if (!/^\d+(\.\d{1,24})?$/.test(allowance)) throw new TypeError(`--allowance must be a plain decimal amount of NEAR such as 0.25, got ${JSON.stringify(allowance)}`);
  // Checked before the key goes on chain: a secret that cannot be written would leave an orphaned key behind.
  if (await stat(out).then(() => true, () => false)) throw new Error(`${out} already exists; nothing was added`);
  const { publicKey, secretKey, transactionHash } = await addScopedKey({
    rpcUrl: rpc,
    accountId: account,
    ownerSecretKey: ownerKey as `ed25519:${string}`,
    contractId: contract,
    methodNames: methods.split(",").map((name) => name.trim()),
    allowance: nearToYocto(allowance as `${number}`),
  });
  await writeFile(out, `${secretKey}\n`, { flag: "wx", mode: 0o600 });
  console.log(printable(`added ${publicKey.toString()} to ${account}: may call ${methods} on ${contract} only, gas allowance ${allowance} NEAR, no deposit`));
  console.log(printable(`transaction ${transactionHash}`));
  console.log(printable(`secret key written to ${out}`));
} catch (error) {
  console.error(`scope-key failed: ${printable(describeError(error))}`);
  process.exit(1);
}
