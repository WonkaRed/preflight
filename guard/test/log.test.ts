import assert from "node:assert/strict";
import { mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { makeTempDir } from "../testkit/tempdir.ts";
import { afterEach, beforeEach, describe, it } from "node:test";
import { DecisionLog, MAX_LOG_LINE_BYTES, MAX_LOG_REASONS, type LogEntry } from "../src/log.ts";

let dir: string;
let path: string;

beforeEach(async () => {
  dir = await makeTempDir("log-test");
  path = join(dir, "decisions.jsonl");
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

/** Everything that can end a line, reorder text, hide in it or pass for an escape. */
const HOSTILE = "a\nb\rc\u2028d\u2029e\u0085f\u202eg\u2066h\u200bi\u2060j\ufeffk\u00adl\u{e0041}m\u001bn\u0000o\\u000ap";
const FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060\ufeff\u00ad]|[\u{e0000}-\u{e007f}]/u;

const entryOf = (overrides: Partial<LogEntry> = {}): LogEntry => ({
  timestamp: "2026-11-14T12:00:00.000Z",
  contract: "escrow.test.near",
  method: "release",
  deposit: "0",
  codeHash: null,
  decision: "allow",
  outcome: "approved",
  reasons: ["fine"],
  ...overrides,
});

async function rawLines(): Promise<string[]> {
  const raw = await readFile(path, "utf8");
  assert.ok(raw.endsWith("\n"), "every line ends in a newline");
  return raw.slice(0, -1).split("\n");
}

describe("the log writer", () => {
  it("escapes every string field of the entry, so one entry is one line of the raw file", async () => {
    const log = DecisionLog.for(path);
    const hostile = { ...entryOf(), timestamp: HOSTILE, contract: HOSTILE, method: HOSTILE, deposit: HOSTILE, codeHash: HOSTILE, decision: HOSTILE, outcome: HOSTILE, reasons: [HOSTILE, HOSTILE] } as unknown as LogEntry;
    const entry = log.entry(hostile);
    await log.write(entry);

    const lines = await rawLines();
    assert.equal(lines.length, 1);
    assert.doesNotMatch(lines[0] ?? "", FORBIDDEN, "no raw control, separator, bidi or invisible character reaches the file");
    const parsed = JSON.parse(lines[0] ?? "") as Record<string, unknown>;
    assert.deepEqual(parsed, entry, "RefusedError.entry is the object that was logged");
    const escaped = "a\\u000ab\\u000dc\\u2028d\\u2029e\\u0085f\\u202eg\\u2066h\\u200bi\\u2060j\\ufeffk\\u00adl\\u{e0041}m\\u001bn\\u0000o\\u005cu000ap";
    for (const field of ["timestamp", "contract", "method", "deposit", "codeHash", "decision", "outcome"]) assert.equal(parsed[field], escaped, field);
    assert.deepEqual(parsed["reasons"], [escaped, escaped]);
  });

  it("walks nested objects, arrays and keys, so a field added to the entry later is escaped too", async () => {
    const log = DecisionLog.for(path);
    const entry = log.entry({ ...entryOf(), future: { [`k${HOSTILE}`]: [HOSTILE, { deep: HOSTILE }] } } as unknown as LogEntry);
    await log.write(entry);
    const [line] = await rawLines();
    assert.doesNotMatch(line ?? "", FORBIDDEN);
    assert.match(line ?? "", /"future":\{"k/);
  });

  it("keeps a line within the byte cap, whatever the reasons add up to", async () => {
    const log = DecisionLog.for(path);
    const entry = log.entry(entryOf({ reasons: Array.from({ length: 100 }, () => `${"\u0001\\".repeat(300)}`) }));
    await log.write(entry);
    const [line] = await rawLines();
    assert.ok(Buffer.byteLength(line ?? "", "utf8") <= MAX_LOG_LINE_BYTES, String(Buffer.byteLength(line ?? "", "utf8")));
    const parsed = JSON.parse(line ?? "") as LogEntry;
    assert.ok(parsed.reasons.length <= MAX_LOG_REASONS + 1);
    assert.match(parsed.reasons.at(-1) ?? "", /more reasons omitted/);
    assert.equal(parsed.reasons[0], entry.reasons[0]);
  });

  it("counts bytes, not characters", async () => {
    const log = DecisionLog.for(path);
    const entry = log.entry(entryOf({ reasons: Array.from({ length: MAX_LOG_REASONS }, () => "\u65e5".repeat(480)) }));
    await log.write(entry);
    const [line] = await rawLines();
    assert.ok(Buffer.byteLength(line ?? "", "utf8") <= MAX_LOG_LINE_BYTES);
    assert.ok((line ?? "").length < MAX_LOG_LINE_BYTES / 2, "the test is only meaningful if bytes and characters differ");
  });

  it("keeps every line whole when many near-cap entries are written at once", async () => {
    const log = DecisionLog.for(path);
    const entries = Array.from({ length: 200 }, (_, i) => log.entry(entryOf({ method: `m${i}`, reasons: Array.from({ length: 12 }, () => "x".repeat(480)) })));
    await Promise.all(entries.map((entry) => log.write(entry)));
    const lines = await rawLines();
    assert.equal(lines.length, 200);
    const methods = lines.map((line) => (JSON.parse(line) as LogEntry).method);
    assert.deepEqual(methods, entries.map((entry) => entry.method), "written in the order they were queued");
  });

  it("shares one queue between every agent that writes to the same file", () => {
    assert.equal(DecisionLog.for(path), DecisionLog.for(join(dir, ".", "decisions.jsonl")));
    assert.notEqual(DecisionLog.for(path), DecisionLog.for(join(dir, "other.jsonl")));
  });

  it("rejects a failed write for its own caller only, and writes the next one", async () => {
    const missing = join(dir, "later", "log.jsonl");
    const log = DecisionLog.for(missing);
    await assert.rejects(log.write(log.entry(entryOf())), /ENOENT/);
    await mkdir(join(dir, "later"));
    await log.write(log.entry(entryOf({ method: "second" })));
    const lines = (await readFile(missing, "utf8")).trim().split("\n");
    assert.deepEqual(lines.map((line) => (JSON.parse(line) as LogEntry).method), ["second"]);
  });
});
