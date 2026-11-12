// Public surface of the guard (SPEC.md section 7). The types live in types.ts.

export type { Decision, GuardConfig, GuardResult, Verdict, VerdictStatus } from "./types.ts";
export { checkContract, codeHashOf, readMutability } from "./check.ts";
export { CodePins, describeMutability, MUTABILITY_LIMITS } from "./mutability.ts";
export type { Mutability, MutabilityConfig } from "./mutability.ts";
export { isValidAccountId, isValidMethodName, MAX_METHOD_NAME_LENGTH } from "./validate.ts";
export { GuardedAgent, RefusedError } from "./guarded.ts";
export type { ApprovalRequest, CallRequest, GuardedAgentOptions, GuardedCallResult } from "./guarded.ts";
export type { Policy } from "./policy.ts";
export type { LogEntry } from "./log.ts";
export { addScopedKey } from "./scope-key.ts";
