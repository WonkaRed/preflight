import { describeError, printable } from "./text.ts";
import { isValidAccountId } from "./validate.ts";

/** What the agent's owner allows, enforced locally before any RPC call. Amounts are yoctoNEAR (`nearToYocto("1")`). */
export interface Policy {
  /** The only contracts the agent may call. */
  allowedContracts: readonly string[];
  /** Largest deposit attached to one call. */
  maxDepositPerCall: bigint;
  /** Largest sum of deposits over the life of the agent object. Resets when the process restarts. */
  maxTotalDeposit: bigint;
}

/** Amounts arrive from agent code, so a string or a negative number is a bug to stop here, not to compare. */
export function assertAmount(value: unknown, what: string): asserts value is bigint {
  if (typeof value !== "bigint" || value < 0n) throw new TypeError(`${what} must be a non-negative bigint (yoctoNEAR), got ${typeof value === "bigint" ? value : `a ${typeof value}`}`);
}

export function assertValidPolicy(policy: Policy): void {
  assertAmount(policy.maxDepositPerCall, "policy.maxDepositPerCall");
  assertAmount(policy.maxTotalDeposit, "policy.maxTotalDeposit");
  if (!Array.isArray(policy.allowedContracts)) throw new TypeError("policy.allowedContracts must be an array of account ids");
  for (const contractId of policy.allowedContracts) {
    if (!isValidAccountId(contractId)) throw new TypeError(`policy.allowedContracts has an invalid account id: ${printable(describeError(contractId))}`);
  }
}

/** The first rule the call breaks, or null when the policy allows it. `spent` is the deposit total already committed. */
export function policyViolation(policy: Policy, contractId: string, deposit: bigint, spent: bigint): string | null {
  assertAmount(deposit, "deposit");
  if (!policy.allowedContracts.includes(contractId)) return `policy: ${contractId} is not in the allowed contracts`;
  if (deposit > policy.maxDepositPerCall) return `policy: deposit ${deposit} yoctoNEAR exceeds the per-call cap ${policy.maxDepositPerCall}`;
  if (spent + deposit > policy.maxTotalDeposit) {
    return `policy: deposit ${deposit} on top of ${spent} already committed exceeds the total cap ${policy.maxTotalDeposit}`;
  }
  return null;
}
