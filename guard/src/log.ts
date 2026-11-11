import { appendFile } from "node:fs/promises";
import { resolve } from "node:path";
import { printable } from "./text.ts";
import type { Decision } from "./types.ts";

/**
 * One JSON line per event. A call that is accepted ends in a terminal line (`refused`, `sent` or `not_sent`) that tells
 * the truth about its last attempt; `approved` is the intermediate line written before anything is signed. There is one
 * `sent` line per attempt handed to the node, and a call has more than one attempt when near-api-js retries a stale nonce.
 */
export interface LogEntry {
  /** ISO 8601 time of the event. */
  timestamp: string;
  contract: string;
  method: string;
  /** Attached deposit in yoctoNEAR, as a decimal string. */
  deposit: string;
  /** Base58 SHA-256 of the deployed wasm; null when it was never read (policy refusal, RPC failure). */
  codeHash: string | null;
  /** The guard's decision, or `block` for a policy refusal. A `warn` that the approver accepts stays `warn`. */
  decision: Decision;
  /**
   * `refused`: nothing was signed (terminal). `approved`: the decision to sign was taken and logged; nothing is
   * signed yet. `sent`: written after signing, just before the transaction is handed to the network, once per
   * attempt, since near-api-js retries on a stale nonce (terminal; from here the money may be spent, so the deposit
   * stays committed). `not_sent`: the last attempt was not handed to the node: the call failed before any hand-off
   * (nothing left the process, the deposit was released), or the guard refused a retry whose signed transaction
   * differed from the checked request after an earlier attempt had been sent (terminal; best effort, like any write
   * after a failing disk, except for that refusal, which is built to be logged whatever happens).
   */
  outcome: "approved" | "sent" | "not_sent" | "refused";
  reasons: string[];
}

/** No log line is longer than this many bytes: one write per line, so a line is never split or torn. */
export const MAX_LOG_LINE_BYTES = 16 * 1024;
/** At most this many reasons are kept in one line. */
export const MAX_LOG_REASONS = 16;

/** Every string in the value, nested or not, is made printable; nothing else about the value's shape changes. */
function sanitizeStrings(value: unknown): unknown {
  if (typeof value === "string") return printable(value);
  if (Array.isArray(value)) return value.map(sanitizeStrings);
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([key, inner]) => [printable(key), sanitizeStrings(inner)]));
  }
  if (typeof value === "bigint") return value.toString();
  return value;
}

const lineOf = (entry: LogEntry): string => JSON.stringify(entry);
const bytesOf = (line: string): number => Buffer.byteLength(line, "utf8");

/**
 * The one place where text becomes a log line. `entry()` is the only way to make something `write()` accepts to
 * persist, and it walks every string field, so a field added to `LogEntry` later is escaped without anyone
 * remembering to. Writes go through one in-process queue per file, one `appendFile` per line, each line within
 * `MAX_LOG_LINE_BYTES`, so lines cannot interleave or tear.
 */
export class DecisionLog {
  readonly #path: string;
  #tail: Promise<void> = Promise.resolve();

  private constructor(path: string) {
    this.#path = path;
  }

  /** One log per file, shared by every agent in the process that writes to it, so their lines are queued together. */
  static for(path: string): DecisionLog {
    const key = resolve(path);
    let log = logs.get(key);
    if (log === undefined) {
      log = new DecisionLog(key);
      logs.set(key, log);
    }
    return log;
  }

  /** A sanitized, size-capped copy of the draft: exactly what `write` persists and `RefusedError.entry` carries. */
  entry(draft: LogEntry): LogEntry {
    const clean = sanitizeStrings(draft) as LogEntry;
    const kept = clean.reasons.slice(0, MAX_LOG_REASONS);
    const build = (): LogEntry => {
      const omitted = clean.reasons.length - kept.length;
      return { ...clean, reasons: omitted > 0 ? [...kept, `...[${omitted} more reasons omitted]`] : kept };
    };
    while (bytesOf(lineOf(build())) > MAX_LOG_LINE_BYTES && kept.length > 1) kept.pop();
    const entry = build();
    if (bytesOf(lineOf(entry)) > MAX_LOG_LINE_BYTES) throw new RangeError("a log entry exceeds the line cap even without reasons");
    return entry;
  }

  /** Appends the entry as one line. Calls are queued; a failed write rejects its own promise and nobody else's. */
  write(entry: LogEntry): Promise<void> {
    const line = `${lineOf(entry)}\n`;
    const done = this.#tail.then(() => appendFile(this.#path, line));
    this.#tail = done.catch(() => undefined);
    return done;
  }
}

const logs = new Map<string, DecisionLog>();
