// Shared by the Swap scripts: the deployment record, reads of the chain, and the one flip every script sends.
// Everything here talks to testnet only (`assertTestnetChain`).
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { Account, JsonRpcProvider, KeyPairSigner, actions, teraToGas } from "near-api-js";
import { checkContract } from "../../../guard/src/index.ts";
import { assertTestnetChain, chainCodeHash, explorerTxUrl, viewJson } from "../../../guard/demo/testnet-deployment.ts";

export { assertTestnetChain, chainCodeHash, explorerTxUrl, viewJson };
export { DEFAULT_TESTNET_RPC, keyPath, readSecretKey } from "../../../guard/demo/testnet-deployment.ts";

export const DEPLOYMENT_FILE = join(import.meta.dirname, "..", "deployment.json");

/** The record `deploy.ts` writes and every other script reads: which accounts, which hashes, which transactions. */
export interface SwapDeployment {
  network: "testnet";
  parent: string;
  registry: string;
  auditor: string;
  chameleon: string;
  switch: string;
  /** Base58 SHA-256 of each build's wasm: what the chain reports and the registry keys. */
  codeHashes: { vulnerable: string; patched: string };
  /** The public key of the flip key: its private half is published on the web page. */
  flipKey: { publicKey: string; allowanceNear: string } | null;
  transactions: { step: string; signer: string; receiver: string; hash: string; what: string }[];
}

export async function loadSwapDeployment(path = DEPLOYMENT_FILE): Promise<SwapDeployment> {
  const parsed = JSON.parse(await readFile(path, "utf8")) as SwapDeployment;
  if (parsed.network !== "testnet") throw new Error(`${path} is not a testnet record`);
  return parsed;
}

/** The switch's `status()` view, in the shape the contract returns it (see demo/swap/README.md). */
export interface SwitchStatus {
  chameleon: string;
  live: "vulnerable" | "patched";
  vulnerable: { code_hash: string; code_hash_hex: string; size_bytes: number };
  patched: { code_hash: string; code_hash_hex: string; size_bytes: number };
  flips: number;
  last_flip_ms: number;
  min_interval_ms: number;
  next_flip_ms: number;
}

export const switchStatus = async (rpc: string, deployment: SwapDeployment, finality: "final" | "optimistic" = "final"): Promise<SwitchStatus> =>
  (await viewJson(rpc, deployment.switch, "status", {}, finality)) as SwitchStatus;

/** What the guard decides about the chameleon right now, from the chain only: the code hash and the registry's verdict for it. */
export async function guardDecision(rpc: string, deployment: SwapDeployment) {
  const result = await checkContract(deployment.chameleon, { rpcUrl: rpc, registryId: deployment.registry, timeoutMs: 20_000 });
  return { decision: result.decision, codeHash: result.codeHash, verdict: result.verdict === null ? null : { status: result.verdict.status, rule_ids: result.verdict.rule_ids, report_url: result.verdict.report_url }, reason: result.reasons[0] };
}

/** Gas a page attaches to `flip`: the switch asks for 100 Tgas at least and a flip burns about 28. The unspent part is refunded. */
export const FLIP_GAS = teraToGas("150");

/**
 * Signs `flip` on the switch with `secretKey` (the published function-call key) and waits until the transaction and
 * every receipt it caused are final. Throws unless the whole chain succeeded. Returns the transaction hash and the
 * block that included it.
 */
export async function sendFlip(rpc: string, switchId: string, secretKey: `ed25519:${string}`): Promise<{ hash: string; blockHash: string; blockHeight: number }> {
  const provider = new JsonRpcProvider({ url: rpc });
  const account = new Account(switchId, provider, KeyPairSigner.fromSecretKey(secretKey));
  const outcome = await account.signAndSendTransaction({ receiverId: switchId, actions: [actions.functionCall("flip", {}, FLIP_GAS, 0n)], waitUntil: "FINAL", throwOnFailure: true });
  const blockHash = outcome.transaction_outcome.block_hash;
  const block = await provider.viewBlock({ blockId: blockHash });
  return { hash: outcome.transaction.hash, blockHash, blockHeight: block.header.height };
}
