// The page's side of `scan-worker.js`: `scan(request)` resolves to the report. One scan runs at a time and the newest
// wins: starting a scan, or aborting its signal, ends the one in flight by terminating its worker (the only way to stop
// WebAssembly that is running); the next scan starts a fresh one. A scan that was ended this way rejects with `ScanCancelled`.
import { ScanFailed } from './scanner.js';

export class ScanCancelled extends Error {}

const spawnWorker = () => new Worker(new URL('scan-worker.js', import.meta.url), { type: 'module' });

export function backgroundScanner(module, spawn = spawnWorker) {
  let worker = null;
  let current = null; // { id, resolve, reject }
  let lastId = 0;

  function end(error) {
    worker?.terminate();
    worker = null;
    const ended = current;
    current = null;
    ended?.reject(error);
  }

  function start() {
    const fresh = spawn();
    fresh.onmessage = ({ data }) => {
      if (!current || data.id !== current.id) return;
      const done = current;
      current = null;
      if (data.failure !== undefined) done.reject(new ScanFailed(data.failure));
      else {
        try {
          done.resolve(JSON.parse(data.text));
        } catch {
          done.reject(new ScanFailed('The scanner returned something that is not a report. That is a bug in Preflight, not a verdict on the code.'));
        }
      }
    };
    fresh.onerror = () => end(new ScanFailed('The scan stopped before it finished. That is a bug in Preflight, not a verdict on the code.'));
    fresh.postMessage({ module });
    return fresh;
  }

  return {
    scan(request, { signal } = {}) {
      if (current) end(new ScanCancelled());
      if (signal?.aborted) return Promise.reject(new ScanCancelled());
      worker ??= start();
      return new Promise((resolve, reject) => {
        current = { id: ++lastId, resolve, reject };
        signal?.addEventListener('abort', () => { if (current?.reject === reject) end(new ScanCancelled()); }, { once: true });
        worker.postMessage({ id: current.id, request });
      });
    },
  };
}
