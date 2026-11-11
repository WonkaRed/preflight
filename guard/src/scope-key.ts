import { createHash } from "node:crypto";
import { Account, KeyPair, JsonRpcProvider, KeyPairSigner, actions, baseEncode, encodeTransaction, type Provider, type PublicKey, type SignedTransaction } from "near-api-js";
import { InvalidNonceError, TransactionExecutionError } from "near-api-js/rpc-errors";
import { describeError, printable } from "./text.ts";
import { isValidAccountId, isValidMethodName } from "./validate.ts";

export interface ScopedKeyRequest {
  /** RPC endpoint. */
  rpcUrl: string;
  /** The account that gets the key. */
  accountId: string;
  /** A full-access key of that account: the only kind that can add keys. Used once, never stored. */
  ownerSecretKey: `ed25519:${string}`;
  /** The one contract the new key may call. */
  contractId: string;
  /** The methods it may call. Required and non-empty: an empty list would mean "every method". */
  methodNames: string[];
  /** Gas budget of the key in yoctoNEAR. Required: an omitted allowance means unlimited gas. */
  allowance: bigint;
}

/** The hash a node knows a transaction by: the base58 SHA-256 of the unsigned transaction. */
export const transactionHashOf = (signed: SignedTransaction): string => baseEncode(createHash("sha256").update(encodeTransaction(signed.transaction)).digest());

const isSuccess = (status: unknown): boolean => typeof status === "object" && status !== null && "SuccessValue" in status;

/** A transaction the node executed and reported as failed: the one send failure whose hash resolves on chain as a failure. */
class TransactionFailedError extends Error {}

/**
 * Throws unless the node reports the transaction as executed successfully. `provider.sendTransaction` returns a failed
 * transaction's outcome instead of throwing, so every caller of it has to ask.
 */
export function requireSuccess(outcome: { status?: unknown }, transactionHash: string): void {
  if (isSuccess(outcome.status)) return;
  const shown = typeof outcome.status === "object" && outcome.status !== null && "Failure" in outcome.status ? outcome.status.Failure : outcome.status;
  throw new TransactionFailedError(`transaction ${transactionHash} did not succeed: ${printable(JSON.stringify(shown) ?? String(shown)).slice(0, 300)}`);
}

/**
 * Whether a send's error is the node refusing the transaction at validation (not enough allowance, wrong method, no
 * balance, bad signature): it was never included, so asking for its status would only wait out the node's 30 s lookup
 * timeout, several times over. A nonce error is excluded: resending a transaction that landed answers that way.
 */
export const refusedByNode = (error: unknown): boolean => error instanceof TransactionExecutionError && !(error instanceof InvalidNonceError);

/**
 * What a send that did not succeed throws, so that no failure reaches the caller without the transaction's hash and
 * without saying whether the hash can be looked up: a failure the node executed already says so (`requireSuccess`); a
 * refusal never landed; any other error leaves the transaction's fate open. The node's own error stays as `cause`.
 */
export function failedSend(error: unknown, transactionHash: string): Error {
  if (error instanceof TransactionFailedError) return error;
  const reason = printable(describeError(error));
  if (refusedByNode(error)) return new Error(`the node refused transaction ${transactionHash}: it was not included in a block, so the hash does not resolve: ${reason}`, { cause: error });
  return new Error(`transaction ${transactionHash} was sent, but the node answered with an error and did not report it as succeeded; it may or may not have landed: ${reason}`, { cause: error });
}

/** Whether the node knows the transaction as executed successfully; any failure to find out counts as no. */
export async function transactionSucceeded(provider: Provider, accountId: string, txHash: string): Promise<boolean> {
  try {
    return isSuccess((await provider.viewTransactionStatus({ txHash, accountId, waitUntil: "EXECUTED_OPTIMISTIC" })).status);
  } catch {
    return false;
  }
}

/**
 * Adds a fresh function-call key, limited to one contract and the named methods, to the account and returns the
 * new key pair and the hash of the transaction that added it. The caller stores the secret key; this function never
 * writes or logs it. A transaction that fails, or whose fate cannot be confirmed after the send threw, throws (see `failedSend`,
 * the message carries its hash): no key is returned for it. (A send that threw but is found executed returns the key as normal.)
 */
export async function addScopedKey(request: ScopedKeyRequest): Promise<{ publicKey: PublicKey; secretKey: string; transactionHash: string }> {
  if (!isValidAccountId(request.accountId)) throw new TypeError(`invalid account id: ${printable(describeError(request.accountId))}`);
  if (!isValidAccountId(request.contractId)) throw new TypeError(`invalid contract id: ${printable(describeError(request.contractId))}`);
  if (request.methodNames.length === 0) throw new TypeError("methodNames must name at least one method; an empty list allows every method");
  const badMethod = request.methodNames.find((name) => !isValidMethodName(name));
  if (badMethod !== undefined) throw new TypeError(`invalid method name: ${printable(describeError(badMethod))}`);
  if (request.allowance <= 0n) throw new TypeError("allowance must be positive; zero makes the key unusable and omitting it means unlimited");

  const provider = new JsonRpcProvider({ url: request.rpcUrl });
  const owner = new Account(request.accountId, provider, KeyPairSigner.fromSecretKey(request.ownerSecretKey));
  const key = KeyPair.fromRandom("ed25519");
  const signed = await owner.createSignedTransaction({
    receiverId: request.accountId,
    actions: [actions.addFunctionCallAccessKey(key.getPublicKey(), request.contractId, request.methodNames, request.allowance)],
  });
  // Worked out here, so what the node answers cannot make it missing or wrong.
  const transactionHash = transactionHashOf(signed);
  const added = { publicKey: key.getPublicKey(), secretKey: key.toString(), transactionHash };
  try {
    requireSuccess(await provider.sendTransaction(signed), transactionHash);
  } catch (error) {
    // The node may have taken the transaction and then failed to answer: the key is on chain, and losing its secret would orphan it.
    if (refusedByNode(error) || !(await transactionSucceeded(provider, request.accountId, transactionHash))) throw failedSend(error, transactionHash);
  }
  return added;
}
