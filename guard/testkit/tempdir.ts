// A fresh directory under the OS temp dir for one test; the test removes it afterwards.
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const makeTempDir = (prefix: string): Promise<string> => mkdtemp(join(tmpdir(), `${prefix}.`));
