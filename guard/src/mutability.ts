// Who can replace the code behind an address, and has it changed since it was approved: two facts the chain itself
// answers, so they need no auditor. Everything here is read-only RPC.
import { randomUUID } from "node:crypto";
import { readFileSync, unlinkSync } from "node:fs";
import { mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { isObject, rpcQuery, RpcFailure } from "./rpc.ts";
import { describeError, printable } from "./text.ts";
import { isCryptoHash, isValidAccountId } from "./validate.ts";
import type { Decision, GuardConfig } from "./types.ts";

/** What the owner turns on with `GuardConfig.mutability`. An empty object turns on the key fact alone. */
export interface MutabilityConfig {
  /** Remembers the code hash of every contract that was approved, and compares against it on later checks. Pinning is off without it. */
  pins?: CodePins;
  /** What a code hash that differs from its pin does to the decision: `warn` (default) needs a human, `block` refuses. */
  onCodeChange?: Exclude<Decision, "allow">;
}

/** What the chain shows about who can replace the code at an account. */
export interface Mutability {
  accountId: string;
  /**
   * Hash of the code the account names: its own, or the global contract it points at by hash. Null when the account names
   * no hash: it has no code, or it follows a publisher (see `globalPublisher`), whose current code the account does not name.
   */
  codeHash: string | null;
  /** The account that published the global contract this account follows by publisher id, who can replace it; null otherwise. */
  globalPublisher: string | null;
  /** Number of full-access keys on this account: each can deploy new code to it at any time. 0 means this account holds none. */
  fullAccessKeys: number;
}

/** What `Mutability` cannot show, in the words the guard prints next to it. */
export const MUTABILITY_LIMITS = "Not established: whether the contract can upgrade itself through one of its own methods (a key count cannot show that, so zero full-access keys does not mean the code is fixed), and when the code last changed (RPC reports code changes one block at a time, so the guard cannot look back).";

/** The facts as a sentence, always ending with what they cannot show. */
export function describeMutability(mutability: Mutability): string {
  const statement = replaceability(mutability);
  return `${statement.charAt(0).toUpperCase()}${statement.slice(1)}. ${MUTABILITY_LIMITS}`;
}

/** The plain statement about who can replace the code, without a final period; `describeMutability` and the guard's reasons both use it. */
export function replaceability({ fullAccessKeys: keys, globalPublisher }: Pick<Mutability, "fullAccessKeys" | "globalPublisher">): string {
  const publisher = globalPublisher === null ? "" : `code at this address is the global contract published by ${globalPublisher}, who can replace it at any time; `;
  if (keys > 0) return `${publisher}code at this address can be replaced by a key holder at any time (${keys} full-access key${keys === 1 ? "" : "s"})`;
  return `${publisher}no full-access key on this account${globalPublisher === null ? ", so no key holder can deploy new code to it" : ""}`;
}

/** Counts the full-access keys of an account. An unknown kind of key is a failure, never a zero: it might be able to deploy. */
export async function countFullAccessKeys(accountId: string, config: GuardConfig): Promise<number> {
  const list = await rpcQuery(config.rpcUrl, { request_type: "view_access_key_list", finality: "optimistic", account_id: accountId }, config.timeoutMs, config.rateLimitBackoffMs);
  const keys = list["keys"];
  if (!Array.isArray(keys)) throw new RpcFailure("view_access_key_list result has no keys list");
  // nearcore adds `last_key` to a page it cut short; a count of a partial list could miss the full-access key.
  if (list["last_key"] !== undefined && list["last_key"] !== null) throw new RpcFailure("view_access_key_list answered with a partial list (last_key is set)");
  let full = 0;
  for (const key of keys) {
    const accessKey = isObject(key) ? key["access_key"] : undefined;
    const permission = isObject(accessKey) ? accessKey["permission"] : undefined;
    if (permission === "FullAccess") full += 1;
    else if (!isObject(permission) || !isObject(permission["FunctionCall"])) throw new RpcFailure("view_access_key_list holds a key with a permission this guard does not know");
  }
  return full;
}

/** Decisions from mildest to strictest. */
const SEVERITY: readonly Decision[] = ["allow", "warn", "block"];

/** The stricter of two decisions. A value that is not a decision throws: it can never be taken for the milder one. */
export function stricter(a: Decision, b: Decision): Decision {
  const [rankA, rankB] = [SEVERITY.indexOf(a), SEVERITY.indexOf(b)];
  if (rankA < 0 || rankB < 0) throw new TypeError(`not a decision: ${printable(describeError(rankA < 0 ? a : b))}`);
  return rankA >= rankB ? a : b;
}

/**
 * A copy of the `mutability` setting that cannot change under the guard (each property is read once), checked: it throws a
 * TypeError for a setting the guard would misread (an `onCodeChange` that is neither "warn" nor "block" must never mean "milder").
 * Undefined stays undefined: the checks are off.
 */
export function snapshotMutability(mutability: MutabilityConfig): MutabilityConfig;
export function snapshotMutability(mutability: MutabilityConfig | undefined): MutabilityConfig | undefined;
export function snapshotMutability(mutability: MutabilityConfig | undefined): MutabilityConfig | undefined {
  if (mutability === undefined) return undefined;
  if (typeof mutability !== "object" || mutability === null) throw new TypeError("guard.mutability must be an object");
  const { pins, onCodeChange } = mutability;
  if (pins !== undefined && !(pins instanceof CodePins)) throw new TypeError("guard.mutability.pins must be a CodePins");
  if (onCodeChange !== undefined && onCodeChange !== "warn" && onCodeChange !== "block") throw new TypeError('guard.mutability.onCodeChange must be "warn" or "block"');
  return { ...(pins !== undefined && { pins }), ...(onCodeChange !== undefined && { onCodeChange }) };
}

/** What `pins.get` found against the hash seen now: the reason, or null when there is no pin or it matches. */
export function pinChangeReason(pinned: string | undefined, codeHash: string): string | null {
  return pinned === undefined || pinned === codeHash ? null : `code changed since you last approved it: approved hash ${pinned}, hash now ${codeHash}`;
}

/** Why a store could not be read or opened: always printed to its operator at startup, so it may name the path. */
const unreadable = (path: string, why: string): Error => new Error(`the pin file ${path} ${why}`);

/**
 * The code hash approved for each contract, in memory and, when `open` gets a path, in a JSON file (account id to hash)
 * that survives a restart. One store belongs to one network (account ids can repeat across networks) and one process: a
 * file store holds a lock file next to it (`<path>.lock`, the owner's pid), taken by `open` and released by `close` or when the
 * process exits, and a second `open` of the same file refuses to start. An owner accepts a changed contract by approving it
 * (a `warn` that the approver allows pins the new hash), or with the process stopped by deleting its entry from the file.
 */
export class CodePins {
  readonly #hashes: Map<string, string>;
  readonly #path: string | undefined;
  readonly #release: (() => void) | undefined;
  #writing: Promise<void> = Promise.resolve();

  private constructor(hashes: Map<string, string>, path: string | undefined, release: (() => void) | undefined) {
    this.#hashes = hashes;
    this.#path = path;
    this.#release = release;
  }

  /**
   * Pins held in memory only, or loaded from `path` (a missing file is an empty store) under a lock. Throws when another
   * live process holds the lock, and for a file that is not what this class writes: a pin store that cannot be read must not
   * read as empty.
   */
  static async open(path?: string): Promise<CodePins> {
    const hashes = new Map<string, string>();
    if (path === undefined) return new CodePins(hashes, undefined, undefined);
    const release = await lock(`${path}.lock`);
    try {
      let text: string | undefined;
      try {
        text = await readFile(path, "utf8");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw unreadable(path, `cannot be read: ${printable(describeError(error))}`);
      }
      if (text !== undefined) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          throw unreadable(path, "is not valid JSON");
        }
        if (!isObject(parsed)) throw unreadable(path, "must hold one JSON object (account id to code hash)");
        for (const [id, hash] of Object.entries(parsed)) {
          if (!isValidAccountId(id) || typeof hash !== "string" || !isCryptoHash(hash)) throw unreadable(path, "holds an entry that is not an account id with a base58 32-byte code hash");
          hashes.set(id, hash);
        }
      }
    } catch (error) {
      release();
      throw error;
    }
    return new CodePins(hashes, path, release);
  }

  /** Releases the lock of a file store (also done when the process exits); the store must not be used afterwards. */
  close(): void {
    this.#release?.();
  }

  /** The hash approved for `contractId`, or undefined when none was. */
  get(contractId: string): string | undefined {
    return this.#hashes.get(contractId);
  }

  /**
   * Remembers `codeHash` for `contractId`, provided the pin is still `expectedPrevious` (what the caller read before it
   * decided; undefined for none): a pin that moved meanwhile throws instead of being overwritten. Pinning the hash already
   * pinned does nothing. The file, when there is one, is written before memory changes. A failed save throws a message without
   * the path (callers hand messages to a model); the detail goes to stderr.
   */
  async set(contractId: string, codeHash: string, expectedPrevious: string | undefined): Promise<void> {
    if (!isValidAccountId(contractId) || !isCryptoHash(codeHash)) throw new TypeError("a pin needs a valid account id and a base58 32-byte code hash");
    const run = this.#writing.then(() => this.#save(contractId, codeHash, expectedPrevious));
    this.#writing = run.catch(() => undefined);
    await run;
  }

  async #save(contractId: string, codeHash: string, expectedPrevious: string | undefined): Promise<void> {
    const current = this.#hashes.get(contractId);
    if (current === codeHash) return;
    if (current !== expectedPrevious) throw new Error(`the code pin for ${contractId} changed while it was being checked; check again`);
    if (this.#path !== undefined) {
      const temp = `${this.#path}.${process.pid}.${randomUUID()}.tmp`;
      try {
        await writeFile(temp, `${JSON.stringify(Object.fromEntries([...this.#hashes, [contractId, codeHash]]), null, 2)}\n`);
        await rename(temp, this.#path);
      } catch (error) {
        await rm(temp, { force: true }).catch(() => undefined);
        console.error(`preflight: could not save the code pin for ${contractId} to ${printable(this.#path)}: ${printable(describeError(error))}`);
        throw new Error(`could not save the code pin for ${contractId}`);
      }
    }
    this.#hashes.set(contractId, codeHash);
  }
}

/** True when a process with this pid exists (signal 0 only tests). EPERM means it exists and is someone else's. */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Takes the exclusive lock file `lockPath` (created with `wx`, holding this pid) and returns the function that releases it.
 * A lock whose pid is no longer running is stale and is replaced once; a live one refuses. The release also runs when the process
 * exits. The check-then-replace of a stale lock is not atomic: two processes that start at the same instant over one stale lock
 * can both win it; a lock that was left by a pid the machine has since reused is refused until it is deleted by hand.
 */
async function lock(lockPath: string): Promise<() => void> {
  await mkdir(dirname(lockPath), { recursive: true });
  for (let attempt = 0; ; attempt++) {
    try {
      const handle = await open(lockPath, "wx");
      await handle.writeFile(`${process.pid}\n`);
      await handle.close();
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const owner = Number.parseInt(await readFile(lockPath, "utf8").catch(() => ""), 10);
      if (attempt > 0 || !Number.isInteger(owner) || isAlive(owner)) {
        throw new Error(`the pin file lock ${lockPath} is held${Number.isInteger(owner) ? ` by process ${owner}` : ""}: one process per pin file (delete the lock file only if no process uses these pins)`);
      }
      await rm(lockPath, { force: true });
    }
  }
  const release = (): void => {
    process.removeListener("exit", release);
    try {
      if (Number.parseInt(readFileSync(lockPath, "utf8"), 10) === process.pid) unlinkSync(lockPath);
    } catch {
      // already gone
    }
  };
  process.once("exit", release);
  return release;
}
