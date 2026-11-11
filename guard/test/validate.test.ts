import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isValidAccountId, isValidMethodName, MAX_METHOD_NAME_LENGTH } from "../src/validate.ts";

describe("account ids", () => {
  it("accepts the NEAR forms", () => {
    for (const good of ["a1", "escrow.test.near", "my-contract_v2.near", "0".repeat(64), "a".repeat(64)]) assert.equal(isValidAccountId(good), true, good);
  });

  it("rejects everything else, including text that could reach a log line", () => {
    const bad = ["", "a", "UPPER.near", "a..near", ".a.near", "a.near.", "has space.near", "a".repeat(65), "a.near/../x", "a\u202e.near", "a\n.near", "a\u2028b", "a\u0085b", "a\u200bb", "a-.near", "a._b", "a.NEAR", "near.Near", "a.neaR", "a.b-C", "a.near.Z", "aB", "Ab", 5, null, undefined, {}];
    for (const id of bad) assert.equal(isValidAccountId(id as string), false, String(id));
  });
});

describe("method names", () => {
  it("accepts identifiers up to the limit nearcore enforces (max_length_method_name = 256)", () => {
    assert.equal(MAX_METHOD_NAME_LENGTH, 256);
    for (const good of ["release", "ft_transfer_call", "_private", "Release2", "a", "a".repeat(256)]) assert.equal(isValidMethodName(good), true, good);
  });

  it("rejects an empty name, one over the limit, a leading digit and anything that is not an identifier", () => {
    const bad = ["", "a".repeat(257), "a".repeat(8_000_000), "2fast", "has space", "a.b", "a-b", "a\n", "a\u202e", "a\u2028", "a\u0085", "a\u200b", "\u00e9", "a\u0000", 7, null, undefined];
    for (const name of bad) assert.equal(isValidMethodName(name as string), false, JSON.stringify(name)?.slice(0, 40));
  });
});
