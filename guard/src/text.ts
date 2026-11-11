/** Longest a piece of outside text may be in a message or log field, in characters, including the truncation marker. */
export const MAX_TEXT_LENGTH = 500;

const TRUNCATED = "...[truncated]";

// Everything that can forge or hide a log line, or reorder or hide text on screen: backslash (so a literal
// "\u000a" cannot pass for an escape), control characters (Cc), format characters (Cf: bidirectional controls,
// zero-width characters, soft hyphen, byte order mark, the tag block), line and paragraph separators (Zl, Zp),
// surrogates (lone ones: a valid pair is one code point and is left alone), private-use and unassigned code points,
// and the fillers that render as blanks.
const UNSAFE = /[\\\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Co}\p{Cn}\u{e0000}-\u{e007f}\u034f\u115f\u1160\u3164\uffa0]/gu;

function escapeChar(char: string): string {
  const code = char.codePointAt(0) ?? 0;
  const hex = code.toString(16).padStart(4, "0");
  return code > 0xffff ? `\\u{${hex}}` : `\\u${hex}`;
}

/**
 * Text that came from outside the process (RPC answers, registry verdicts, caller-supplied ids) made safe for one
 * line of a line-based log or a terminal: every unsafe character becomes a visible \uXXXX escape (a literal
 * backslash becomes \u005c, so text that merely spells an escape cannot pass for one), and the result is cut to `maxLength`, ending in `...[truncated]`. The input is cut
 * first, so a giant string costs no more than a small one. It is NOT idempotent (the backslash escape sees to that):
 * apply it exactly once, at the point where text enters a log entry or a message.
 */
export function printable(text: string, maxLength = MAX_TEXT_LENGTH): string {
  const input = text.length > maxLength ? text.slice(0, maxLength) : text;
  const escaped = input.replace(UNSAFE, escapeChar);
  if (input === text && escaped.length <= maxLength) return escaped;
  const room = maxLength - TRUNCATED.length;
  // Never end on half of a surrogate pair, or on half of an escape that the cut split.
  const head = escaped.slice(0, room).replace(/[\ud800-\udbff]$/, "").replace(/\\(?:u(?:\{[0-9a-f]*|[0-9a-f]{0,3}))?$/, "");
  return head + TRUNCATED;
}

function attempt<T>(read: () => T): T | undefined {
  try {
    return read();
  } catch {
    return undefined;
  }
}

/**
 * A short description of anything that was thrown, for a reason or a log line. It cannot throw: a thrown value may
 * be an object with no prototype, a throwing `toString`, an Error whose `message` getter throws, or a Proxy. The
 * result is raw text (bounded), to be passed through `printable` where it enters a log entry or a message.
 */
export function describeError(error: unknown): string {
  const text = attempt(() => {
    if (typeof error === "string") return error;
    if (error instanceof Error) return String(error.message);
    return String(error);
  });
  if (text !== undefined) return text.slice(0, 2 * MAX_TEXT_LENGTH);
  return `an unprintable ${attempt(() => typeof error) ?? "value"} was thrown`;
}
