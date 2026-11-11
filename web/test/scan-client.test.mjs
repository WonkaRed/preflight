// The page's side of the scan worker (src/scan-client.js) against a fake worker: one scan at a time, newest wins, and a scan
// that is ended rejects as cancelled. The worker's own half is covered by scanner.test.mjs (the same module) and the browser run.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { backgroundScanner, ScanCancelled } from '../src/scan-client.js';
import { ScanFailed } from '../src/scanner.js';

/** Stands in for `new Worker(...)`: records messages and lets a test answer them. */
function fakeWorkers() {
  const made = [];
  const spawn = () => {
    const worker = {
      sent: [],
      terminated: false,
      postMessage(message) { this.sent.push(message); },
      terminate() { this.terminated = true; },
      answer(data) { this.onmessage({ data }); },
    };
    made.push(worker);
    return worker;
  };
  return { made, spawn };
}
const report = JSON.stringify({ summary: { files_scanned: 1 } });

test('the module is handed over once, then each scan is answered by id', async () => {
  const { made, spawn } = fakeWorkers();
  const scanner = backgroundScanner('MODULE', spawn);
  const first = scanner.scan({ target: 'a' });
  const [worker] = made;
  assert.deepEqual(worker.sent[0], { module: 'MODULE' });
  assert.deepEqual(worker.sent[1], { id: 1, request: { target: 'a' } });
  worker.answer({ id: 1, text: report });
  assert.deepEqual(await first, { summary: { files_scanned: 1 } });
  const second = scanner.scan({ target: 'b' });
  assert.equal(made.length, 1, 'an idle worker is reused');
  worker.answer({ id: 2, text: report });
  await second;
  assert.ok(!worker.terminated);
});

test('starting a scan ends the one in flight: it rejects as cancelled, its worker is stopped and the new scan gets a fresh one', async () => {
  const { made, spawn } = fakeWorkers();
  const scanner = backgroundScanner('M', spawn);
  const old = scanner.scan({ target: 'old' });
  const fresh = scanner.scan({ target: 'new' });
  await assert.rejects(old, ScanCancelled);
  assert.ok(made[0].terminated);
  assert.equal(made.length, 2);
  made[0].answer({ id: 1, text: report }); // a late answer from the stopped worker is ignored
  made[1].answer({ id: 2, text: report });
  assert.deepEqual(await fresh, { summary: { files_scanned: 1 } });
});

test('aborting the signal stops the scan and rejects as cancelled; an already aborted signal never starts one', async () => {
  const { made, spawn } = fakeWorkers();
  const scanner = backgroundScanner('M', spawn);
  const controller = new AbortController();
  const running = scanner.scan({ target: 'a' }, { signal: controller.signal });
  controller.abort();
  await assert.rejects(running, ScanCancelled);
  assert.ok(made[0].terminated);
  await assert.rejects(scanner.scan({ target: 'b' }, { signal: controller.signal }), ScanCancelled);
  assert.equal(made.length, 1, 'no worker was started for the aborted scan');
  const after = scanner.scan({ target: 'c' });
  made[1].answer({ id: 2, text: report });
  await after;
});

test('aborting a scan that already finished does nothing to the next one', async () => {
  const { made, spawn } = fakeWorkers();
  const scanner = backgroundScanner('M', spawn);
  const controller = new AbortController();
  const done = scanner.scan({ target: 'a' }, { signal: controller.signal });
  made[0].answer({ id: 1, text: report });
  await done;
  const next = scanner.scan({ target: 'b' });
  controller.abort();
  made[0].answer({ id: 2, text: report });
  await next;
  assert.ok(!made[0].terminated);
});

test('a failure sentence, an unreadable answer and a crashed worker all reject as ScanFailed', async () => {
  const { made, spawn } = fakeWorkers();
  const scanner = backgroundScanner('M', spawn);
  const failed = scanner.scan({});
  made[0].answer({ id: 1, failure: 'cannot parse src/a.rs:1:1: x' });
  await assert.rejects(failed, (e) => e instanceof ScanFailed && e.message === 'cannot parse src/a.rs:1:1: x');
  const garbled = scanner.scan({});
  made[0].answer({ id: 2, text: 'not json' });
  await assert.rejects(garbled, (e) => e instanceof ScanFailed && /not a report/.test(e.message));
  const crashed = scanner.scan({});
  made[0].onerror(new Event('error'));
  await assert.rejects(crashed, (e) => e instanceof ScanFailed && /stopped before it finished/.test(e.message));
  assert.ok(made[0].terminated);
  const recovered = scanner.scan({});
  made[1].answer({ id: 4, text: report });
  await recovered;
});
