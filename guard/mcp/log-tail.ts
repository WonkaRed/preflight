import { open } from "node:fs/promises";
import { MAX_LOG_LINE_BYTES } from "../src/log.ts";

/**
 * The last `count` lines of a file, oldest first, reading only the end of it: the decision log grows for as long as the
 * agent runs. The guard caps a line at MAX_LOG_LINE_BYTES, so `count + 1` lines' worth of bytes always holds `count`
 * whole lines even when the read starts in the middle of one (that first, partial line is dropped). A missing file is an
 * empty log.
 */
export async function lastLines(path: string, count: number): Promise<string[]> {
  let file;
  try {
    file = await open(path, "r");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  try {
    const { size } = await file.stat();
    const length = Math.min(size, (count + 1) * (MAX_LOG_LINE_BYTES + 1));
    const start = size - length;
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await file.read(buffer, 0, length, start);
    const lines = buffer.toString("utf8", 0, bytesRead).split("\n");
    if (start > 0) lines.shift();
    return lines.filter((line) => line !== "").slice(-count);
  } finally {
    await file.close();
  }
}
