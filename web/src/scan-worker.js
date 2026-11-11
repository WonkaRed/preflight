// Runs scans off the page's thread, so the page keeps painting and Cancel works while a large scan runs. The first
// message hands over the compiled module; every later one is `{ id, request }` and is answered with `{ id, text }` (the
// report JSON) or `{ id, failure }` (a sentence for the person).
import { loadScanner } from './scanner.js';

let scanner;
self.onmessage = ({ data }) => {
  if (data.module) {
    scanner = loadScanner(data.module);
    return;
  }
  try {
    self.postMessage({ id: data.id, text: scanner.scanText(data.request) });
  } catch (error) {
    self.postMessage({ id: data.id, failure: error.message });
  }
};
