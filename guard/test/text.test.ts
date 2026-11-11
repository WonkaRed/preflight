import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { describeError, MAX_TEXT_LENGTH, printable } from "../src/text.ts";

describe("printable", () => {
  const escaped = (char: string): string => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`;

  it("escapes C0 controls, DEL and every C1 control", () => {
    for (let code = 0; code <= 0x9f; code += 1) {
      if (code > 0x1f && code < 0x7f) continue;
      const char = String.fromCharCode(code);
      assert.equal(printable(`a${char}b`), `a${escaped(char)}b`, `U+${code.toString(16)}`);
    }
  });

  it("escapes the Unicode line and paragraph separators", () => {
    assert.equal(printable("a\u2028b\u2029c"), "a\\u2028b\\u2029c");
  });

  it("escapes the bidirectional controls that can reorder text on screen", () => {
    const bidi = ["\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"];
    for (const char of bidi) assert.equal(printable(`a${char}b`), `a${escaped(char)}b`, escaped(char));
  });

  it("escapes lone surrogates but keeps a valid pair and ordinary text", () => {
    assert.equal(printable("a\ud800b"), "a\\ud800b");
    assert.equal(printable("a\udc00b"), "a\\udc00b");
    assert.equal(printable("a\ud800"), "a\\ud800");
    assert.equal(printable("pair \u{1f600} é 日本"), "pair \u{1f600} é 日本");
  });

  it("cuts long text to the limit, never ends on half a surrogate pair, and says it cut", () => {
    const long = printable("x".repeat(10_000));
    assert.equal(long.length, MAX_TEXT_LENGTH);
    assert.match(long, /\.\.\.\[truncated\]$/);
    for (const filler of ["x", "\u{1f600}"]) {
      for (let pad = 0; pad < 3; pad += 1) {
        const cut = printable("y".repeat(pad) + filler.repeat(1_000));
        assert.ok(cut.length <= MAX_TEXT_LENGTH);
        assert.doesNotMatch(cut, /[\ud800-\udbff]\.\.\.\[truncated\]$/);
      }
    }
  });

  it("escapes a literal backslash, so text that spells an escape cannot pass for one", () => {
    assert.equal(printable("a\\u000ab"), "a\\u005cu000ab");
    assert.notEqual(printable("a\\u000ab"), printable("a\nb"));
    assert.equal(printable("a\nb"), "a\\u000ab");
    assert.equal(printable("C:\\dir"), "C:\\u005cdir");
  });

  it("escapes zero-width, soft-hyphen, word-joiner, BOM, tag and filler characters", () => {
    const invisible = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad", "\u034f", "\u115f", "\u1160", "\u3164", "\uffa0", "\u180e"];
    for (const char of invisible) assert.equal(printable(`a${char}b`), `a${escaped(char)}b`, escaped(char));
    for (const point of [0xe0000, 0xe0001, 0xe0020, 0xe007f]) {
      assert.equal(printable(`a${String.fromCodePoint(point)}b`), `a\\u{${point.toString(16)}}b`, point.toString(16));
    }
  });

  it("leaves ordinary international text alone", () => {
    for (const text of ["cafe\u0301 caf\u00e9", "\u65e5\u672c\u8a9e", "\u0645\u0631\u062d\u0628\u0627", "\u{1f600}\u{1f9d1}", "plain ascii 123 ~!@#"]) {
      assert.equal(printable(text), text);
    }
  });

  it("cuts a ten-million-character input before escaping it, so it costs no more than a short one", () => {
    // Counted, not timed: the escaping pass is String.prototype.replace, and it must only ever see the cut input.
    const replace = String.prototype.replace;
    const seen: number[] = [];
    String.prototype.replace = function (this: string, ...args: Parameters<typeof replace>): string {
      seen.push(this.length);
      return replace.apply(this, args);
    } as typeof replace;
    try {
      for (const filler of ["x", "\u0000", "\\", "\u{1f600}"]) {
        seen.length = 0;
        const out = printable(filler.repeat(10_000_000 / filler.length));
        assert.ok(out.length <= MAX_TEXT_LENGTH, `${out.length}`);
        assert.match(out, /\.\.\.\[truncated\]$/);
        assert.ok(seen.length > 0, "the escaping pass ran, and the spy saw it");
        assert.ok(seen.every((length) => length <= MAX_TEXT_LENGTH), `the input is cut before it is escaped (the escaping pass saw ${Math.max(...seen)} characters)`);
      }
    } finally {
      String.prototype.replace = replace;
    }
  });

  it("never ends in half an escape when it truncates", () => {
    for (let pad = 0; pad < 8; pad += 1) {
      const cut = printable("y".repeat(pad) + "\u0000".repeat(1_000));
      assert.ok(cut.length <= MAX_TEXT_LENGTH);
      assert.doesNotMatch(cut, /\\(?:u[0-9a-f]{0,3})?\.\.\.\[truncated\]$/);
    }
  });
});

describe("describeError", () => {
  const unprintable: Array<[string, unknown]> = [
    ["a null-prototype object", Object.create(null)],
    ["an object whose toString throws", { toString() { throw new Error("no"); } }],
    ["an Error whose message getter throws", Object.defineProperty(new Error("x"), "message", { get() { throw new Error("no"); } })],
    ["an Error whose name getter throws", Object.defineProperty(new Error("x"), "name", { get() { throw new Error("no"); } })],
    ["a revoked proxy", (() => { const { proxy, revoke } = Proxy.revocable({}, {}); revoke(); return proxy; })()],
    ["a proxy whose traps throw", new Proxy({}, { get() { throw new Error("no"); }, getPrototypeOf() { throw new Error("no"); } })],
    ["a symbol", Symbol("s")],
  ];
  for (const [name, value] of unprintable) {
    it(`returns text for ${name}`, () => {
      assert.equal(typeof describeError(value), "string");
      assert.ok(describeError(value).length > 0);
    });
  }

  it("reads a message, a string and a number", () => {
    assert.equal(describeError(new Error("boom")), "boom");
    assert.equal(describeError("plain"), "plain");
    assert.equal(describeError(7), "7");
  });

  it("is bounded for a giant message", () => {
    assert.ok(describeError(new Error("x".repeat(10_000_000))).length <= 2 * MAX_TEXT_LENGTH);
  });
});
