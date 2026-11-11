// Loads the Preflight scanner compiled to WebAssembly (`web-scan/`) and wraps its four-step byte interface.
// Every call gets a fresh instance of the compiled module: WebAssembly memory never shrinks, so a large scan cannot
// leave the page holding its peak, and a trap (a bug in the scanner) cannot poison the next scan.

const OK = 0;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** The scan could not produce a report; `message` is written for the person who pasted the code. */
export class ScanFailed extends Error {}

/** Fetches and compiles the module once. Works whatever content type the host serves `.wasm` with. */
export async function compileScanner(url, fetchImpl = fetch) {
  const response = await fetchImpl(url);
  if (!response.ok) throw new Error(`${url}: the server answered ${response.status}`);
  return WebAssembly.compile(await response.arrayBuffer());
}

// Recursing too deep ends as a call-stack RangeError or as a memory fault just below the module's stack; every other
// trap is a real bug.
const outOfStack = (error) =>
  error instanceof RangeError || (error instanceof WebAssembly.RuntimeError && /out of bounds/.test(error.message));

export function loadScanner(module) {
  function call(op, request) {
    try {
      const { exports } = new WebAssembly.Instance(module, {});
      if (request !== undefined) {
        const bytes = encoder.encode(JSON.stringify(request));
        // The memory view is taken after the call that may grow it.
        const at = exports.preflight_input(bytes.length);
        new Uint8Array(exports.memory.buffer, at, bytes.length).set(bytes);
      }
      const status = exports[op]();
      const text = decoder.decode(new Uint8Array(exports.memory.buffer, exports.preflight_output_ptr(), exports.preflight_output_len()));
      return { status, text };
    } catch (error) {
      throw new ScanFailed(outOfStack(error)
        ? 'This code is nested too deeply for the in-browser build: the scanner ran out of stack space. Scan it with the command line (`preflight`) instead.'
        : `The scanner stopped before it finished (${error.name}: ${error.message}). That is a bug in Preflight, not a verdict on the code.`);
    }
  }

  return {
    /** `{ target, files: [{ path, text }], above?: [text or null] }` in, the report JSON text out: what `preflight --json` prints. */
    scanText(request) {
      const { status, text } = call('preflight_scan', request);
      if (status !== OK) throw new ScanFailed(text);
      return text;
    },
    scan(request) {
      return JSON.parse(this.scanText(request));
    },
    /** `[{ id, title, severity }]` for every rule the module runs. */
    rules() {
      return JSON.parse(call('preflight_rules').text);
    },
  };
}
