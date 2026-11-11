// What the testnet scripts share: the shape of docs/testnet-deployment.json (the public record of a deployment:
// account ids, code hashes, transaction hashes, never a private key), the key-file layout, and two read-only RPC calls.
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { KeyPairSigner, type Account, type Action, type Signer } from "near-api-js";
import { rpcQuery } from "../src/rpc.ts";
import { failedSend, refusedByNode, requireSuccess, transactionHashOf, transactionSucceeded } from "../src/scope-key.ts";
import { isValidAccountId } from "../src/validate.ts";

// FastNear's free testnet endpoint (the one near-cli-rs lists as testnet-fastnear). rpc.testnet.near.org answers a burst of
// about two dozen requests with HTTP 429 for minutes, which the guard turns into a block.
export const DEFAULT_TESTNET_RPC = "https://test.rpc.fastnear.com";
export const DEFAULT_DEPLOYMENT = join(import.meta.dirname, "..", "..", "docs", "testnet-deployment.json");

/** The shops the agent has a key for: one function-call key each, named after the role in `agent-key-for-<role>.key`. */
export const SHOP_ROLES = ["vulnerable", "patched", "swapped"] as const;
export type ShopRole = (typeof SHOP_ROLES)[number];

export interface DeployedTransaction {
  /** Which step of the deploy script sent it (unique; a rerun skips steps that are recorded). */
  step: string;
  signer: string;
  receiver: string;
  hash: string;
  what: string;
}

export interface Deployment {
  network: "testnet";
  deployedAt: string;
  parent: string;
  /** The account id of every role: registry, auditor, agent, payee and one shop per `ShopRole`. */
  accounts: Record<string, string>;
  /** Base58 SHA-256 of the wasm each account holds now; `swappedAudited` is what `shop-swapped` held when it was audited. */
  codeHashes: Record<string, string>;
  /** Public keys of the agent's function-call keys, one per shop. */
  agentKeys: Record<ShopRole, string>;
  /** Order ids funded on the patched shop (the demo releases one per run) and on the vulnerable one. */
  orders: { patched: number[]; vulnerable: number[] };
  /** What happened before the deploy script ran: the faucet creating the parent account, and its top-up. Written by hand. */
  bootstrap?: DeployedTransaction[];
  transactions: DeployedTransaction[];
}

// near.rocks (FastNear's explorer) renders without a bot challenge; nearblocks.io, the explorer selector's recommended one, serves the same hashes.
export const explorerTxUrl = (hash: string): string => `https://testnet.near.rocks/tx/${hash}`;
export const explorerAccountUrl = (accountId: string): string => `https://testnet.near.rocks/account/${accountId}`;

/** Throws unless the RPC reports `chain_id` "testnet": no testnet script talks to any other network. */
export async function assertTestnetChain(rpcUrl: string): Promise<void> {
  const response = await fetch(rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "preflight", method: "status", params: [] }), signal: AbortSignal.timeout(15_000) });
  const body = (await response.json().catch(() => undefined)) as { result?: { chain_id?: unknown } } | undefined;
  const chainId = body?.result?.chain_id;
  if (chainId !== "testnet") throw new Error(`${rpcUrl} reports chain_id ${JSON.stringify(chainId)}, not "testnet"; this script is testnet only`);
}

export async function loadDeployment(path: string): Promise<Deployment> {
  const parsed: unknown = JSON.parse(await readFile(path, "utf8"));
  const deployment = parsed as Deployment;
  const ids = [deployment.parent, ...Object.values(deployment.accounts ?? {})];
  if (deployment.network !== "testnet" || ids.length < 2 || !ids.every((id) => typeof id === "string" && isValidAccountId(id) && id.endsWith(".testnet"))) {
    throw new Error(`${path} is not a testnet deployment record`);
  }
  return deployment;
}

/** Where a private key lives: `<dir>/<name>.key`, one line `ed25519:...`. */
export const keyPath = (dir: string, name: string): string => join(dir, `${name}.key`);

export async function readSecretKey(path: string): Promise<`ed25519:${string}`> {
  const text = (await readFile(path, "utf8").catch(() => {
    throw new Error(`cannot read the key file ${path}`);
  })).trim();
  if (!text.startsWith("ed25519:")) throw new Error(`${path} does not hold an ed25519 secret key`);
  return text as `ed25519:${string}`;
}

/** A registry or shop view call: `call_function` at the given finality, result decoded from its byte array to JSON. */
export async function viewJson(rpcUrl: string, contractId: string, method: string, args: Record<string, unknown>, finality: "final" | "optimistic" = "final"): Promise<unknown> {
  const call = await rpcQuery(rpcUrl, {
    request_type: "call_function",
    finality,
    account_id: contractId,
    method_name: method,
    args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
  });
  const bytes = call["result"];
  if (!Array.isArray(bytes)) throw new Error(`${contractId}.${method} returned no result`);
  return JSON.parse(Buffer.from(bytes as number[]).toString("utf8"));
}

/** The account of one shop in the record. */
export function shopAccount(deployment: Deployment, role: ShopRole): string {
  const accountId = deployment.accounts[role];
  if (accountId === undefined) throw new Error(`the deployment record has no ${role} shop`);
  return accountId;
}

/** The escrow state of an order on a shop, as the chain reports it now: `Funded`, `Released`, or `null` for no such order. */
export const orderStatus = async (rpcUrl: string, shop: string, order: number): Promise<string> => String(await viewJson(rpcUrl, shop, "get_status", { id: order }));

/** Escrow state after a release: `Released` once the payout and its callback ran, `Funded` when nothing happened. */
export async function waitForStatus(rpcUrl: string, shop: string, order: number, wanted: string): Promise<string> {
  let current = await orderStatus(rpcUrl, shop, order);
  for (let poll = 0; poll < 10 && current !== wanted; poll++) {
    await sleep(1_000);
    current = await orderStatus(rpcUrl, shop, order);
  }
  return current;
}

/** One funded order per run: the first of the patched shop's recorded orders that is still `Funded`. */
export async function firstFundedOrder(rpcUrl: string, deployment: Deployment): Promise<number> {
  const patched = shopAccount(deployment, "patched");
  for (const candidate of deployment.orders.patched) {
    if ((await orderStatus(rpcUrl, patched, candidate)) === "Funded") return candidate;
  }
  throw new Error(`every escrow order on ${patched} is already released. The recorded deployment's order stock is fixed (its agent holds no full-access key, so it cannot fund more); on a deployment of your own, fund more with: testnet-deploy --more-orders 5`);
}

/** The agent's function-call key for each shop, read from `<keysDir>/agent-key-for-<role>.key`, by shop account id. */
export async function agentSigners(deployment: Deployment, keysDir: string): Promise<Map<string, Signer>> {
  const signers = new Map<string, Signer>();
  for (const role of SHOP_ROLES) signers.set(shopAccount(deployment, role), KeyPairSigner.fromSecretKey(await readSecretKey(keyPath(keysDir, `agent-key-for-${role}`))));
  return signers;
}

/** The `code_hash` the chain reports for an account (the all-zero hash when it has no code). */
export async function chainCodeHash(rpcUrl: string, accountId: string, finality: "final" | "optimistic" = "final"): Promise<string> {
  const account = await rpcQuery(rpcUrl, { request_type: "view_account", finality, account_id: accountId });
  const hash = account["code_hash"];
  if (typeof hash !== "string") throw new Error(`view_account ${accountId} has no code_hash`);
  return hash;
}

/**
 * Signs a transaction once and sends it, returning its hash. When the node answers HTTP 429 the same signed bytes are
 * sent again after the next wait: the chain takes one transaction per signer key and nonce, so a resend can never run
 * a step twice. A transaction that failed throws (`sendTransaction` returns a failed outcome instead of throwing, so it
 * is checked). When a send throws and the node's own status of that transaction says it succeeded, the step is done;
 * anything else throws what `failedSend` makes of the error (it carries the hash), without waiting for a status when the node refused the transaction (see `refusedByNode`).
 */
export async function sendSigned(signer: Account, receiverId: string, actions: Action[], waitsMs: readonly number[], onRateLimit: (waitMs: number) => void): Promise<string> {
  const signed = await signer.createSignedTransaction({ receiverId, actions });
  const hash = transactionHashOf(signed);
  for (let attempt = 0; ; attempt++) {
    try {
      requireSuccess(await signer.provider.sendTransaction(signed), hash);
      return hash;
    } catch (error) {
      const wait = (error as { cause?: unknown }).cause === 429 ? waitsMs[attempt] : undefined;
      if (wait !== undefined) {
        onRateLimit(wait);
        await sleep(wait);
        continue;
      }
      if (!refusedByNode(error) && (await transactionSucceeded(signer.provider, signer.accountId, hash))) return hash;
      throw failedSend(error, hash);
    }
  }
}
