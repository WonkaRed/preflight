// The GitHub reader (src/github.js) against a fake `fetch`: which requests it makes, what it keeps, and how it fails.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describeSpec, fetchRepo, GitHubError, LIMITS, parseSpec, plan } from '../src/github.js';
import { scanner } from './helpers.mjs';

const blob = (path, size = 10) => ({ path, type: 'blob', mode: '100644', size });
const json = (body, init = {}) => new Response(JSON.stringify(body), { status: 200, ...init });
const SHA = 'a'.repeat(40);

/** A fetch that answers from `routes` (URL substring -> Response or text) and records every call. The commit lookup is answered unless a route overrides it. */
function fakeFetch(given) {
  const routes = { '/commits/': json({ sha: SHA }), ...given };
  const calls = [];
  const fetch = async (url, options) => {
    calls.push({ url: String(url), options });
    const key = Object.keys(routes).find((k) => String(url).includes(k));
    if (!key) return new Response('no route', { status: 404 });
    const answer = routes[key];
    return typeof answer === 'function' ? answer() : answer instanceof Response ? answer.clone() : new Response(answer);
  };
  return { fetch, calls };
}

const repo = { repo: 'o/r', ref: '', path: '' };

test('the form fields are checked and normalised', () => {
  assert.deepEqual(parseSpec({ repo: ' https://github.com/near/near-sdk-rs.git/ ', ref: '', path: '/examples//x/ ' }),
    { owner: 'near', repo: 'near-sdk-rs', ref: 'HEAD', path: 'examples/x' });
  assert.equal(describeSpec(parseSpec({ repo: 'a/b', ref: 'v1.0', path: 'c/d' })), 'a/b@v1.0:c/d');
  assert.equal(describeSpec(parseSpec({ repo: 'a/b' })), 'a/b');
  for (const bad of ['', 'justone', 'a/b/c', 'a b/c', '-a/b', 'a/..', 'a/b?x=1', 'a/b#x', 'ex ample/r', 'a/b%2F']) {
    assert.throws(() => parseSpec({ repo: bad }), GitHubError, bad);
  }
  for (const ref of ['a..b', '/x', 'x/', 'a b', 'a?b', 'a#b', 'a\\b']) assert.throws(() => parseSpec({ repo: 'a/b', ref }), GitHubError, ref);
  for (const path of ['../x', 'a/../b', 'a/./b', 'a\\b', 'a\u0000b']) assert.throws(() => parseSpec({ repo: 'a/b', path }), GitHubError, JSON.stringify(path));
});

test('two API requests, then one raw request per file, all pinned to the commit the ref pointed at; paths come back relative to the sub-path', async () => {
  const { fetch, calls } = fakeFetch({
    '/git/trees/': json({ tree: [
      blob('README.md'), blob('ex/Cargo.toml'), blob('ex/src/lib.rs'), blob('ex/src/util/mod.rs'), blob('ex/target/debug/x.rs'),
      blob('ex/.cargo/config.rs'), blob('ex/notes.txt'), blob('other/src/lib.rs'), { path: 'ex/sub', type: 'tree' },
      { path: 'ex/link.rs', type: 'blob', mode: '120000', size: 5 },
    ] }),
    'raw.githubusercontent.com': () => new Response('contents'),
  });
  const result = await fetchRepo({ repo: 'o/r', ref: 'main', path: 'ex' }, { fetch });
  assert.equal(result.target, 'o/r@main:ex');
  assert.deepEqual(result.files.map((f) => f.path), ['Cargo.toml', 'src/lib.rs', 'src/util/mod.rs']);
  assert.deepEqual(result.notes, []);
  assert.deepEqual(calls.map((c) => c.url), [
    'https://api.github.com/repos/o/r/commits/main',
    `https://api.github.com/repos/o/r/git/trees/${SHA}?recursive=1`,
    `https://raw.githubusercontent.com/o/r/${SHA}/ex/Cargo.toml`,
    `https://raw.githubusercontent.com/o/r/${SHA}/ex/src/lib.rs`,
    `https://raw.githubusercontent.com/o/r/${SHA}/ex/src/util/mod.rs`,
  ]);
  assert.ok(calls.every((c) => c.options.credentials === 'omit' && !('headers' in c.options)), 'no credentials, no custom headers (no CORS preflight)');
});

test('the Cargo.toml above the sub-path are read too, nearest first: the workspace root sets the build profile', async () => {
  const { fetch, calls } = fakeFetch({
    '/git/trees/': json({ tree: [blob('Cargo.toml'), blob('a/b/Cargo.toml'), blob('a/b/src/lib.rs'), blob('z/Cargo.toml')] }),
    raw: 'text',
  });
  const result = await fetchRepo({ repo: 'o/r', ref: 'main', path: 'a/b' }, { fetch });
  assert.deepEqual(result.above, [null, 'text'], 'a has none, the root has one');
  assert.deepEqual(result.files.map((f) => f.path), ['Cargo.toml', 'src/lib.rs']);
  assert.deepEqual(calls.slice(2).map((c) => c.url.slice(`https://raw.githubusercontent.com/o/r/${SHA}/`.length)).sort(),
    ['Cargo.toml', 'a/b/Cargo.toml', 'a/b/src/lib.rs']);
  const whole = await fetchRepo({ repo: 'o/r', ref: 'main', path: '' }, { fetch });
  assert.deepEqual(whole.above, [], 'nothing is above the whole repository');
});

test('a Cargo.toml above the sub-path that is too large is skipped and said so', async () => {
  const { fetch } = fakeFetch({ '/git/trees/': json({ tree: [blob('Cargo.toml', LIMITS.fileBytes + 1), blob('a/src/lib.rs')] }), raw: 'text' });
  const { above, notes } = await fetchRepo({ repo: 'o/r', ref: '', path: 'a' }, { fetch });
  assert.deepEqual(above, [null]);
  assert.match(notes[0], /^Cargo\.toml is over 1 MB and was not read/);
});

test('a Cargo.toml in the scanned folder over 1 MB is not downloaded and is named in a note, even when it would fit the total budget', async () => {
  for (const size of [LIMITS.fileBytes + 1, 2 * LIMITS.fileBytes, 50 * LIMITS.fileBytes]) {
    const { fetch, calls } = fakeFetch({ '/git/trees/': json({ tree: [blob('Cargo.toml', size), blob('sub/Cargo.toml', 5), blob('src/lib.rs')] }), raw: 'text' });
    const { files, notes } = await fetchRepo(repo, { fetch });
    assert.deepEqual(files.map((f) => f.path), ['sub/Cargo.toml', 'src/lib.rs'], `${size} bytes`);
    assert.ok(!calls.some((c) => c.url.endsWith(`/${SHA}/Cargo.toml`)), `the ${size}-byte manifest is never requested`);
    assert.deepEqual(notes, ['1 file is over 1 MB and was not read: Cargo.toml.']);
  }
  assert.deepEqual(plan([{ path: 'Cargo.toml', size: 2 * LIMITS.fileBytes }, { path: 'a.rs', size: 5 }]).download.map((f) => f.path), ['a.rs']);
  assert.deepEqual(plan([{ path: 'Cargo.toml', size: LIMITS.fileBytes }]).download.map((f) => f.path), ['Cargo.toml'], 'exactly 1 MB is still read');
});

test('manifests count against the byte budget and have a cap of their own, and the Rust files still fit', () => {
  const manifests = Array.from({ length: LIMITS.manifests + 5 }, (_, i) => ({ path: `c${String(i).padStart(3, '0')}/Cargo.toml`, size: 100 }));
  const { download, notes } = plan([...manifests, { path: 'src/lib.rs', size: 100 }]);
  assert.equal(download.filter((f) => f.path.endsWith('Cargo.toml')).length, LIMITS.manifests);
  assert.ok(download.some((f) => f.path === 'src/lib.rs'));
  assert.equal(notes.length, 1);
  assert.match(notes[0], new RegExp(`^Only ${LIMITS.manifests} of ${LIMITS.manifests + 5} Cargo\\.toml files were read`));

  const heavy = plan([{ path: 'a/Cargo.toml', size: LIMITS.fileBytes }, { path: 'b/Cargo.toml', size: LIMITS.fileBytes }, { path: 'c/Cargo.toml', size: LIMITS.fileBytes }, { path: 'd/Cargo.toml', size: LIMITS.fileBytes }, { path: 'x.rs', size: 10 }]);
  assert.equal(heavy.download.length, 4, 'four 1 MB manifests use the whole budget; the manifests go first');
  assert.ok(!heavy.download.some((f) => f.path === 'x.rs'));
  assert.match(heavy.notes[0], /Only 0 of 1 Rust files were read/);
});

test('the note for files over the size limit has the right grammar and names at most ten', () => {
  const big = (n) => Array.from({ length: n }, (_, i) => ({ path: `f${String(i).padStart(2, '0')}.rs`, size: LIMITS.fileBytes + 1 }));
  assert.equal(plan(big(1)).notes[0], '1 file is over 1 MB and was not read: f00.rs.');
  assert.equal(plan(big(2)).notes[0], '2 files are over 1 MB and were not read: f00.rs, f01.rs.');
  assert.match(plan(big(13)).notes[0], /^13 files are over 1 MB and were not read: f00\.rs, .*, f09\.rs, and 3 more\.$/);
});

test('Git submodules are skipped and said so', async () => {
  const { fetch } = fakeFetch({ '/git/trees/': json({ tree: [blob('src/lib.rs'), { path: 'vendor/dep', type: 'commit', mode: '160000' }, { path: 'other/dep', type: 'commit', mode: '160000' }] }), raw: 'x' });
  const { notes } = await fetchRepo(repo, { fetch });
  assert.deepEqual(notes, ['Skipped 2 Git submodules, whose code lives in another repository: vendor/dep, other/dep.']);
  assert.deepEqual((await fetchRepo({ repo: 'o/r', ref: '', path: 'vendor' }, { fetch: fakeFetch({ '/git/trees/': json({ tree: [blob('vendor/a.rs'), { path: 'vendor/dep', type: 'commit' }, { path: 'other/dep', type: 'commit' }] }), raw: 'x' }).fetch })).notes,
    ['Skipped 1 Git submodule, whose code lives in another repository: vendor/dep.']);
});

test('what it downloads scans like the same files on disk would', async () => {
  const text = 'pub fn ok() {}';
  const { fetch } = fakeFetch({ '/git/trees/': json({ tree: [blob('src/lib.rs'), blob('Cargo.toml')] }), '/Cargo.toml': '[package]\nname = "a"\n', raw: text });
  const { target, files, above } = await fetchRepo(repo, { fetch });
  assert.equal(scanner.scan({ target, files, above }).summary.files_scanned, 1);
});

test('the limits cut the list in path order and say so', () => {
  const many = Array.from({ length: LIMITS.rustFiles + 40 }, (_, i) => ({ path: `src/f${String(i).padStart(4, '0')}.rs`, size: 100 }));
  const { download, notes } = plan(many);
  assert.equal(download.length, LIMITS.rustFiles);
  assert.equal(download.at(-1).path, `src/f${String(LIMITS.rustFiles - 1).padStart(4, '0')}.rs`);
  assert.match(notes[0], new RegExp(`Only ${LIMITS.rustFiles} of ${LIMITS.rustFiles + 40} Rust files .* The other 40 were not scanned`));

  const heavy = plan([{ path: 'a.rs', size: LIMITS.fileBytes }, { path: 'b.rs', size: LIMITS.fileBytes }, { path: 'c.rs', size: LIMITS.fileBytes }, { path: 'd.rs', size: LIMITS.fileBytes }, { path: 'e.rs', size: LIMITS.fileBytes }]);
  assert.equal(heavy.download.length, 4, 'the byte budget stops the fifth 1 MB file');
  assert.match(heavy.notes[0], /Only 4 of 5/);

  const huge = plan([{ path: 'big.rs', size: LIMITS.fileBytes + 1 }, { path: 'ok.rs', size: 5 }]);
  assert.deepEqual(huge.download.map((f) => f.path), ['ok.rs']);
  assert.match(huge.notes[0], /1 file is over 1 MB and was not read: big\.rs/);
  assert.deepEqual(plan([{ path: 'ok.rs', size: 5 }]).notes, []);
});

test('a truncated listing is announced', async () => {
  const { fetch } = fakeFetch({ '/git/trees/': json({ truncated: true, tree: [blob('src/lib.rs')] }), raw: 'x' });
  assert.match((await fetchRepo(repo, { fetch })).notes[0], /cut the file list .* short/);
});

test('failures are plain sentences that say what to do', async () => {
  const fails = async (routes, pattern, input = repo) => {
    const { fetch } = fakeFetch(routes);
    await assert.rejects(fetchRepo(input, { fetch }), (error) => error instanceof GitHubError && pattern.test(error.message));
  };
  const reset = String(Math.floor(Date.now() / 1000) + 600);
  await fails({ '/git/trees/': new Response('{}', { status: 403, headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': reset } }) },
    /api\.github\.com is rate-limiting this connection \(GitHub allows 60 requests per hour without a sign-in, and a scan uses 2\)\. It resets at /);
  await fails({ '/git/trees/': new Response('{}', { status: 403, headers: { 'x-ratelimit-remaining': '0' } }), }, /api\.github\.com is rate-limiting this connection \(.*\)\. Try again in a few minutes\./);
  await fails({ raw: new Response('', { status: 429 }), '/git/trees/': json({ tree: [blob('src/lib.rs')] }) }, /^raw\.githubusercontent\.com is rate-limiting this connection\. Try again/);
  await fails({ '/git/trees/': new Response('{}', { status: 429 }) }, /rate-limiting/);
  await fails({ '/git/trees/': new Response('{}', { status: 404 }) }, /o\/r was not found\. .*private repositories cannot be read/);
  await fails({ '/git/trees/': new Response('{}', { status: 409 }) }, /empty repository/);
  await fails({ '/git/trees/': new Response('{}', { status: 500 }) }, /answered 500/);
  await fails({ '/git/trees/': json({ tree: [blob('README.md')] }) }, /has no Rust files\./);
  await fails({ '/git/trees/': json({ tree: [blob('a/README.md')] }) }, /no Rust files in that folder/, { repo: 'o/r', path: 'a' });
  await fails({ '/git/trees/': json({ nope: true }) }, /cannot read/);
  await fails({ '/git/trees/': json({ tree: [blob('src/lib.rs')] }), raw: new Response('', { status: 404 }) }, /not found/);
  const offline = async () => { throw new TypeError('Failed to fetch'); };
  await assert.rejects(fetchRepo(repo, { fetch: offline }), /Could not reach api\.github\.com/);
});

test('one failed download aborts the downloads in flight and starts no more, and is the error reported', async () => {
  const tree = Array.from({ length: 20 }, (_, i) => blob(`src/m${i}.rs`));
  const raw = [];
  const fetch = async (url, { signal }) => {
    if (url.includes('/commits/')) return json({ sha: SHA });
    if (url.includes('/git/trees/')) return json({ tree });
    raw.push(signal);
    if (raw.length === 3) return new Response('', { status: 404 });
    return new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason)));
  };
  await assert.rejects(fetchRepo(repo, { fetch }), (error) => error instanceof GitHubError && /not found/.test(error.message));
  assert.equal(raw.length, 6, 'only the six parallel downloads were ever started');
  assert.ok(raw.filter((_, i) => i !== 2).every((signal) => signal.aborted), 'the other five were told to stop');
});

test('a timeout while the body is still arriving, an answer that is not JSON, and a malformed listing are GitHub errors, not raw exceptions', async () => {
  const timedOut = () => { throw new DOMException('The operation timed out.', 'TimeoutError'); };
  const never = (body) => ({ ok: true, status: 200, headers: new Headers(), json: body, text: body });
  const rejects = async (routes, pattern) => {
    const { fetch } = fakeFetch(routes);
    await assert.rejects(fetchRepo(repo, { fetch }), (error) => error instanceof GitHubError && pattern.test(error.message), String(pattern));
  };
  await rejects({ '/git/trees/': () => never(timedOut) }, /api\.github\.com did not answer within 20 seconds/);
  await rejects({ '/git/trees/': json({ tree: [blob('src/lib.rs')] }), raw: () => never(timedOut) }, /raw\.githubusercontent\.com did not answer within 20 seconds/);
  await rejects({ '/commits/': new Response('<html>'), }, /api\.github\.com sent an answer for o\/r that this page cannot read/);
  await rejects({ '/git/trees/': new Response('<html>not json') }, /cannot read/);
  await rejects({ '/git/trees/': json({ tree: [{ type: 'blob', size: 5 }] }) }, /cannot read/);
  await rejects({ '/git/trees/': json({ tree: [null] }) }, /cannot read/);
  await rejects({ '/git/trees/': json({ tree: [{ path: 'a.rs', type: 'blob', size: 'big' }] }) }, /cannot read/);
  await rejects({ '/commits/': json({ sha: 'main' }) }, /cannot read/);
  await rejects({ '/commits/': json({}) }, /cannot read/);
  const dropped = async () => ({ ok: true, status: 200, headers: new Headers(), json: async () => { throw new TypeError('network error'); } });
  await assert.rejects(fetchRepo(repo, { fetch: dropped }), (error) => error instanceof GitHubError && /Could not reach api\.github\.com/.test(error.message));
});

test('cancelling rejects with the abort, not a GitHub message', async () => {
  const controller = new AbortController();
  const fetch = (url, { signal }) => new Promise((_, reject) => {
    signal.addEventListener('abort', () => reject(signal.reason));
    controller.abort();
  });
  await assert.rejects(fetchRepo(repo, { fetch, signal: controller.signal }), (error) => !(error instanceof GitHubError));
});
