// What the page does when a scan starts, finishes or fails (src/session.js), against a fake scanner and a recording view.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GitHubError } from '../src/github.js';
import { ScanCancelled } from '../src/scan-client.js';
import { ScanFailed } from '../src/scanner.js';
import { createSession, describeFailure } from '../src/session.js';

const report = (files) => ({ summary: { files_scanned: files } });
const repoRead = { target: 'a/b', files: [], above: [], notes: ['a note'] };

/** A view that records what the pane would show, in order, so a test can read the final state. */
function recordingView() {
  const log = [];
  const view = {
    log,
    pending: (label) => log.push(['pending', label]),
    report: (r, meta) => log.push(['report', r.summary.files_scanned, meta.chip, meta.notes]),
    problem: (title, problems) => log.push(['problem', title, problems[0]]),
    progress: (text) => log.push(['progress', text]),
    running: (on) => log.push(['running', on]),
  };
  const shown = () => log.filter(([kind]) => ['pending', 'report', 'problem'].includes(kind)).at(-1);
  return { view, log, shown };
}

const settled = () => new Promise((resolve) => setImmediate(resolve));

test('a scan replaces the pane with "Scanning" at once and then shows the report', async () => {
  const { view, log } = recordingView();
  const session = createSession({ view, readRepo: async () => repoRead, scanner: { scan: async () => report(3) } });
  await session.github({ repo: ' a/b ', ref: '', path: '' });
  assert.deepEqual(log.filter(([k]) => k !== 'progress'), [['pending', 'a/b'], ['running', true], ['report', 3, 'GitHub', ['a note']], ['running', false]]);
});

test('a clean scan of A followed by a failing scan of B shows B\'s failure, never A\'s result', async () => {
  const { view, shown } = recordingView();
  let fail = false;
  const readRepo = async () => { if (fail) throw new GitHubError('b/b was not found.'); return repoRead; };
  const session = createSession({ view, readRepo, scanner: { scan: async () => report(2) } });
  await session.github({ repo: 'a/a', ref: '', path: '' });
  assert.equal(shown()[0], 'report');
  fail = true;
  const second = session.github({ repo: 'b/b', ref: '', path: '' });
  assert.deepEqual(shown(), ['pending', 'b/b'], 'the moment B starts, A\'s result is gone');
  await second;
  assert.deepEqual(shown(), ['problem', 'GitHub could not be read', 'b/b was not found.']);
});

test('every kind of failure ends in a problem, including ones nobody planned for', async () => {
  for (const [error, title] of [
    [new GitHubError('x'), 'GitHub could not be read'],
    [new ScanFailed('x'), 'The scan could not finish'],
    [new TypeError('boom'), 'The page hit an unexpected error'],
    [new DOMException('t', 'TimeoutError'), 'The page hit an unexpected error'],
  ]) {
    const { view, shown } = recordingView();
    const session = createSession({ view, readRepo: async () => { throw error; }, scanner: { scan: async () => report(0) } });
    await session.github({ repo: 'a/b' });
    assert.equal(shown()[1], title);
    const again = recordingView();
    await createSession({ view: again.view, scanner: { scan: async () => { throw error; } } }).source({}, null);
    assert.equal(again.shown()[1], title);
  }
  assert.equal(describeFailure(new ScanCancelled()), null);
  assert.deepEqual(describeFailure(new TypeError('boom')).slice(0, 2), ['The page hit an unexpected error', ['TypeError: boom']]);
});

test('Cancel stops the scan and says there is no result', async () => {
  const { view, shown, log } = recordingView();
  const readRepo = (input, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason)));
  const session = createSession({ view, readRepo, scanner: { scan: async () => report(1) } });
  const running = session.github({ repo: 'a/b' });
  session.cancel();
  await running;
  assert.deepEqual(shown(), ['problem', 'Scan cancelled', 'The scan was stopped before it finished, so there is no result.']);
  assert.deepEqual(log.filter(([k]) => k === 'running'), [['running', true], ['running', false]]);
});

test('the newest scan owns the pane: a slow older GitHub scan that finishes later is dropped', async () => {
  const { view, shown, log } = recordingView();
  const releases = [];
  const scanner = { scan: (request) => new Promise((resolve) => releases.push(() => resolve(report(request.target === 'old' ? 9 : 1)))) };
  const readRepo = async (input) => ({ ...repoRead, target: input.repo });
  const session = createSession({ view, readRepo, scanner });
  const old = session.github({ repo: 'old' });
  await settled();
  const fresh = session.github({ repo: 'new' });
  await settled();
  releases.forEach((release) => release());
  await Promise.all([old, fresh]);
  assert.deepEqual(log.filter(([k]) => k === 'report').map((r) => r[1]), [1]);
  assert.equal(shown()[0], 'report');
  assert.equal(log.filter(([k, on]) => k === 'running' && on === false).length, 1, 'the newer scan alone resets the buttons');
});

test('a pasted-source scan or a refused input replaces a GitHub scan in flight', async () => {
  const { view, shown } = recordingView();
  const readRepo = (input, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason)));
  const session = createSession({ view, readRepo, scanner: { scan: async () => report(4) } });
  const running = session.github({ repo: 'a/b' });
  await session.source({ files: [] }, 'Bundled example');
  await running;
  assert.deepEqual(shown(), ['report', 4, 'Bundled example', undefined]);
  const again = session.github({ repo: 'a/b' });
  session.refuse('Nothing to scan', ['x']);
  await again;
  assert.deepEqual(shown(), ['problem', 'Nothing to scan', 'x']);
});
