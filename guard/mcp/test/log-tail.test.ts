import assert from "node:assert/strict";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { MAX_LOG_LINE_BYTES } from "../../src/log.ts";
import { makeTempDir } from "../../testkit/tempdir.ts";
import { lastLines } from "../log-tail.ts";

let dir: string;
let path: string;
beforeEach(async () => {
  dir = await makeTempDir("mcp-tail");
  path = join(dir, "log");
});
afterEach(() => rm(dir, { recursive: true, force: true }));

describe("lastLines", () => {
  it("treats a missing file as an empty log", async () => {
    assert.deepEqual(await lastLines(path, 5), []);
  });

  it("returns every line of a short file, oldest first, when there are fewer than asked", async () => {
    await writeFile(path, "a\nb\n");
    assert.deepEqual(await lastLines(path, 5), ["a", "b"]);
  });

  it("returns the last N of more", async () => {
    await writeFile(path, "a\nb\nc\nd\n");
    assert.deepEqual(await lastLines(path, 2), ["c", "d"]);
  });

  it("returns whole lines when the read starts in the middle of one, even when every line is as long as a line may be", async () => {
    const lines = Array.from({ length: 6 }, (_, n) => `${n}`.padEnd(MAX_LOG_LINE_BYTES, "x"));
    await writeFile(path, lines.map((line) => `${line}\n`).join(""));
    assert.deepEqual(await lastLines(path, 2), lines.slice(-2));
    assert.deepEqual(await lastLines(path, 1), lines.slice(-1));
  });

  it("keeps multi-byte text whole", async () => {
    await writeFile(path, `${"é".repeat(MAX_LOG_LINE_BYTES / 2)}\nlast é\n`);
    assert.deepEqual(await lastLines(path, 1), ["last é"]);
  });
});
