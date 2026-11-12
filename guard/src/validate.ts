// Grammars for the identifiers that cross the guard's boundary. Everything that reaches the policy, the log, an RPC
// request or a signature has passed one of these first, so those layers never see control characters or giants.
import { baseDecode } from "near-api-js";

// Account id grammar from the NEAR docs and the near-account-id crate: 2 to 64 characters, lowercase letters
// and digits, with single `.`, `-`, `_` separators that cannot start, end or repeat.
const ACCOUNT_ID = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

export function isValidAccountId(accountId: string): boolean {
  return typeof accountId === "string" && accountId.length >= 2 && accountId.length <= 64 && ACCOUNT_ID.test(accountId);
}

/**
 * The most bytes a method name may have: `max_length_method_name` is 256 in nearcore's runtime config (2.14.0,
 * core/parameters/res/runtime_configs/parameters.yaml, documented in core/parameters/src/vm.rs as "Max length of any
 * method name"), and a longer one fails with `FunctionCallMethodNameLengthExceeded`; an empty one with
 * `FunctionCallEmptyMethodName` (core/primitives/src/errors.rs).
 */
export const MAX_METHOD_NAME_LENGTH = 256;

// The chain accepts any non-empty UTF-8 name up to that limit. The guard is stricter on purpose: contracts written
// with the NEAR SDKs export identifiers, so the agent may only name a method that looks like one.
const METHOD_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function isValidMethodName(method: string): boolean {
  return typeof method === "string" && method.length <= MAX_METHOD_NAME_LENGTH && METHOD_NAME.test(method);
}

/**
 * The widest amounts a transaction can carry: a deposit is a u128 and gas a u64 in the borsh encoding. A larger
 * bigint does not fail to sign; it wraps around when serialized (a gas of 2^70 becomes 0, a deposit of 2^128 + 7
 * becomes 7), so what was checked and what is signed would differ.
 */
export const MAX_DEPOSIT = 2n ** 128n - 1n;
export const MAX_GAS = 2n ** 64n - 1n;

/** Whether `value` is a base58 string of 32 bytes: the form of every code hash NEAR RPC reports. */
export function isCryptoHash(value: string): boolean {
  try {
    return baseDecode(value).length === 32;
  } catch {
    return false;
  }
}
