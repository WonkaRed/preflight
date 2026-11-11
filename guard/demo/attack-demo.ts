// `npm run demo`: the attack scenario against an offline fake NEAR RPC. No network, no keys, no LLM.
// Optional first argument: where to write the JSON-lines decision log (default demo-output/decisions.jsonl).
import { KeyPair, KeyPairSigner, type Signer } from "near-api-js";
import { FakeNear, fakeWasm } from "../testkit/fake-rpc.ts";
import { printable } from "../src/text.ts";
import { runScenario, type DemoEnv } from "./scenario.ts";

const REGISTRY = "registry.test.near";
const AGENT = "agent.test.near";
const contracts = { safe: "safe-escrow.test.near", unsafe: "ghost-vault.test.near", swapped: "swapped-escrow.test.near" };

const chain = new FakeNear(REGISTRY);
chain.accounts.set(contracts.safe, { wasm: fakeWasm("escrow v1, audited") });
chain.publish(contracts.safe, "Safe");
chain.accounts.set(contracts.unsafe, { wasm: fakeWasm("vault with the PF004 ghost balance bug") });
chain.publish(contracts.unsafe, "Unsafe", ["PF004"]);
chain.accounts.set(contracts.swapped, { wasm: fakeWasm("escrow v1, audited") });
const auditedHash = chain.publish(contracts.swapped, "Safe");
chain.accounts.set(contracts.swapped, { wasm: fakeWasm("escrow v2, swapped in after the audit") });

// One throwaway function-call key per contract, registered on the fake chain only.
const signers = new Map<string, Signer>();
for (const contractId of Object.values(contracts)) {
  const signer = new KeyPairSigner(KeyPair.fromRandom("ed25519"));
  chain.addKey(AGENT, (await signer.getPublicKey()).toString(), {
    FunctionCall: { allowance: "250000000000000000000000", receiver_id: contractId, method_names: [] },
  });
  signers.set(contractId, signer);
}

const rpcUrl = await chain.start();
let exitCode = 0;
try {
  const env: DemoEnv = {
    guard: { rpcUrl, registryId: REGISTRY, timeoutMs: 5_000 },
    agentId: AGENT,
    contracts,
    drainId: "drain.test.near",
    signerFor: (contractId) => {
      const signer = signers.get(contractId);
      if (signer === undefined) throw new Error(`the agent holds no key for ${contractId}`);
      return signer;
    },
    rpcDescription: "fake NEAR JSON-RPC node on 127.0.0.1 (offline)",
    auditedHashOfSwapped: auditedHash,
    logPath: process.argv[2] ?? "demo-output/decisions.jsonl",
  };
  const attempts = await runScenario(env);

  console.log("");
  console.log(printable(`The chain received ${chain.sent.length} transaction(s): ${chain.sent.map((call) => `${call.receiverId}.${call.methodName}`).join(", ") || "none"}`));
  const signed = attempts.filter((a) => a.outcome === "signed").map((a) => a.contractId);
  if (signed.length !== 1 || signed[0] !== contracts.safe || chain.sent.length !== 1) {
    console.error("demo self-check failed: only the audited contract may be signed");
    exitCode = 1;
  }
} finally {
  await chain.stop();
}
process.exit(exitCode);
