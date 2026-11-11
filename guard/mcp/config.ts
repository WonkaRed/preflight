// What the operator hands the server, read once at startup. The read-only tool needs nothing. The guarded call tool exists
// only when the operator names a key directory AND a policy file: either alone is a mistake, not a smaller grant.
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { KeyPairSigner, teraToGas, type Signer } from "near-api-js";
import * as z from "zod/v4";
import { DEFAULT_DEPLOYMENT, DEFAULT_TESTNET_RPC, keyPath, loadDeployment, readSecretKey } from "../demo/testnet-deployment.ts";
import { GuardedAgent } from "../src/index.ts";
import { describeError, printable } from "../src/text.ts";
import { accountId, testnetAccountId, yoctoNear, type Network } from "./schemas.ts";

/** Free, keyless public endpoint, the one the scanner defaults to. */
const DEFAULT_MAINNET_RPC = "https://free.rpc.fastnear.com";
const DEFAULT_LOG_NAME = "decisions.jsonl";
/** Gas attached to every guarded call; the model cannot raise it. */
export const CALL_GAS = teraToGas("30");
/** Allowed contracts per policy: one key file each, read at startup. */
const MAX_ALLOWED_CONTRACTS = 32;

export interface CallConfig {
  agent: GuardedAgent;
  allowedContracts: readonly string[];
  logPath: string;
}

export interface ServerConfig {
  rpc: Readonly<Record<Network, string>>;
  /** The only registry a testnet check asks: the caller of a tool never names one. */
  testnetRegistry: string;
  /** The only registry a mainnet check asks; absent unless the operator names one, and then mainnet checks are refused. */
  mainnetRegistry?: string;
  /** Present only when the operator enabled guarded calls. */
  call?: CallConfig;
}

const policyFile = z.strictObject({
  accountId: testnetAccountId,
  allowedContracts: z.array(testnetAccountId).min(1).max(MAX_ALLOWED_CONTRACTS),
  registryId: testnetAccountId.optional(),
  maxDepositPerCall: yoctoNear,
  maxTotalDeposit: yoctoNear,
  logPath: z.string().min(1).optional(),
});

function rpcUrl(env: NodeJS.ProcessEnv, name: string, fallback: string): string {
  const url = env[name] || fallback;
  let parsed: URL | undefined;
  try {
    parsed = new URL(url);
  } catch {
    parsed = undefined;
  }
  if (parsed?.protocol !== "http:" && parsed?.protocol !== "https:") throw new Error(`${name} must be an http or https URL`);
  if (parsed.username !== "" || parsed.password !== "") throw new Error(`${name} must not carry a user name or password in the URL`);
  return url;
}

function readMainnetRegistry(env: NodeJS.ProcessEnv): string | undefined {
  const id = env["PREFLIGHT_MAINNET_REGISTRY"];
  if (!id) return undefined;
  if (!accountId.safeParse(id).success) throw new Error("PREFLIGHT_MAINNET_REGISTRY must be a NEAR account id");
  return id;
}

type PolicyFile = z.infer<typeof policyFile>;

async function readPolicy(path: string): Promise<PolicyFile> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new Error(`cannot read the policy file ${path} as JSON: ${printable(describeError(error))}`);
  }
  const result = policyFile.safeParse(parsed);
  if (!result.success) {
    throw new Error(`the policy file ${path} is invalid: ${result.error.issues.map((issue) => `${issue.path.join(".") || "(file)"}: ${issue.message}`).join("; ")}`);
  }
  return result.data;
}

/** One `<contract id>.key` per allowed contract: a function-call key of the agent, scoped to that contract. */
async function readSigners(keysDir: string, contracts: readonly string[]): Promise<Map<string, Signer>> {
  const signers = new Map<string, Signer>();
  for (const contract of contracts) {
    const path = keyPath(keysDir, contract);
    const secret = await readSecretKey(path);
    try {
      signers.set(contract, KeyPairSigner.fromSecretKey(secret));
    } catch {
      // Say which file, never what it holds.
      throw new Error(`${path} does not hold a valid ed25519 secret key`);
    }
  }
  return signers;
}

function callConfig(policy: PolicyFile, signers: ReadonlyMap<string, Signer>, policyPath: string, rpc: string, registryId: string): CallConfig {
  const logPath = resolve(dirname(policyPath), policy.logPath ?? DEFAULT_LOG_NAME);
  const agent = new GuardedAgent({
    accountId: policy.accountId,
    signer: (contractId) => {
      const signer = signers.get(contractId);
      if (signer === undefined) throw new Error(`no key is loaded for ${contractId}`);
      return signer;
    },
    guard: { rpcUrl: rpc, registryId },
    policy: { allowedContracts: policy.allowedContracts, maxDepositPerCall: BigInt(policy.maxDepositPerCall), maxTotalDeposit: BigInt(policy.maxTotalDeposit) },
    logPath,
  });
  return { agent, allowedContracts: policy.allowedContracts, logPath };
}

/**
 * Reads the server's configuration from the environment: PREFLIGHT_TESTNET_RPC and PREFLIGHT_MAINNET_RPC (optional
 * endpoints, which must not carry a user name or password), PREFLIGHT_MAINNET_REGISTRY (optional: without it mainnet checks are
 * refused), and PREFLIGHT_MCP_KEYS plus PREFLIGHT_MCP_POLICY (both, or neither). The testnet registry is the policy's
 * `registryId` when it names one, otherwise the one in the testnet deployment record. Throws an Error with a plain
 * message for anything wrong; the process must not start half configured.
 */
export async function loadServerConfig(env: NodeJS.ProcessEnv): Promise<ServerConfig> {
  const rpc = { testnet: rpcUrl(env, "PREFLIGHT_TESTNET_RPC", DEFAULT_TESTNET_RPC), mainnet: rpcUrl(env, "PREFLIGHT_MAINNET_RPC", DEFAULT_MAINNET_RPC) };
  const mainnetRegistry = readMainnetRegistry(env);
  const keysDir = env["PREFLIGHT_MCP_KEYS"];
  const policyPath = env["PREFLIGHT_MCP_POLICY"];
  if (!keysDir !== !policyPath) throw new Error("set both PREFLIGHT_MCP_KEYS (key directory) and PREFLIGHT_MCP_POLICY (policy file) to enable guarded calls, or neither");

  const policy = policyPath ? await readPolicy(policyPath) : undefined;
  const testnetRegistry = policy?.registryId ?? (await loadDeployment(DEFAULT_DEPLOYMENT)).accounts["registry"];
  if (testnetRegistry === undefined) throw new Error("the testnet deployment record names no registry");
  if (policy === undefined || !keysDir || !policyPath) return { rpc, testnetRegistry, ...(mainnetRegistry && { mainnetRegistry }) };
  const signers = await readSigners(keysDir, policy.allowedContracts);
  return { rpc, testnetRegistry, ...(mainnetRegistry && { mainnetRegistry }), call: callConfig(policy, signers, policyPath, rpc.testnet, testnetRegistry) };
}
