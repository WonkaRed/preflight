// The offline fake NEAR chain the language-model demos run against: a registry that audited `safe-escrow` as Safe and
// `ghost-vault` as Unsafe (PF004), and one throwaway function-call key per contract. Shared by `demo-llm` and `demo-llm-replay`.
import { KeyPair, KeyPairSigner, type Signer } from "near-api-js";
import { FakeNear, fakeWasm } from "../testkit/fake-rpc.ts";
import type { LlmDemoEnv } from "./llm-agent.ts";

const REGISTRY = "registry.test.near";
const AGENT = "agent.test.near";

/** The chain is already started; the caller stops it. `env` lacks only the decision log path. */
export async function startLlmFakeChain(): Promise<{ chain: FakeNear; env: Omit<LlmDemoEnv, "logPath"> }> {
  const contracts = { safe: "safe-escrow.test.near", unsafe: "ghost-vault.test.near" };
  const chain = new FakeNear(REGISTRY);
  chain.accounts.set(contracts.safe, { wasm: fakeWasm("escrow v1, audited") });
  chain.publish(contracts.safe, "Safe");
  chain.accounts.set(contracts.unsafe, { wasm: fakeWasm("vault with the PF004 ghost balance bug") });
  chain.publish(contracts.unsafe, "Unsafe", ["PF004"]);

  const signers = new Map<string, Signer>();
  for (const contractId of Object.values(contracts)) {
    const signer = new KeyPairSigner(KeyPair.fromRandom("ed25519"));
    chain.addKey(AGENT, (await signer.getPublicKey()).toString(), { FunctionCall: { allowance: "250000000000000000000000", receiver_id: contractId, method_names: [] } });
    signers.set(contractId, signer);
  }
  const rpcUrl = await chain.start();
  return {
    chain,
    env: {
      guard: { rpcUrl, registryId: REGISTRY, timeoutMs: 5_000 },
      agentId: AGENT,
      contracts,
      signerFor: (contractId) => {
        const signer = signers.get(contractId);
        if (signer === undefined) throw new Error(`the agent holds no key for ${contractId}`);
        return signer;
      },
      rpcDescription: "fake NEAR JSON-RPC node on 127.0.0.1 (offline)",
    },
  };
}
