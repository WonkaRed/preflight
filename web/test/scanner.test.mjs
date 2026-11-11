// The scanner as the page runs it: the real built wasm module, checked against the native command line.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ScanFailed } from '../src/scanner.js';
import { siteData } from '../tools/site-data.mjs';
import { cliJson, fixtureDirs, request, scanner } from './helpers.mjs';

const ruleOf = (dir) => dir.split('/')[1].slice(0, 5).toUpperCase();

test('for every fixture, the wasm output is the command line output, byte for byte', () => {
  const dirs = fixtureDirs();
  assert.equal(dirs.length, 2 * scanner.rules().length, 'a vulnerable and a patched directory for every rule the module runs');
  for (const dir of dirs) assert.equal(scanner.scanText(request(dir)), cliJson(dir), dir);
});

test('a vulnerable fixture reports its own rule and a patched one reports nothing', () => {
  for (const dir of fixtureDirs()) {
    const report = scanner.scan(request(dir));
    const ids = report.findings.map((f) => f.rule_id);
    if (dir.endsWith('/vulnerable')) assert.ok(ids.includes(ruleOf(dir)), `${dir} did not report ${ruleOf(dir)}: ${ids}`);
    else assert.deepEqual(report.findings, [], dir);
  }
});

test('the bundled examples show a finding when vulnerable and none when patched', () => {
  const { examples } = siteData();
  assert.ok(examples.length >= 3);
  for (const example of examples) {
    const scan = (variant) => scanner.scan({ target: variant, files: [{ path: 'src/lib.rs', text: example[variant] }] });
    assert.ok(scan('vulnerable').findings.some((f) => f.rule_id === example.rule), `${example.id} vulnerable`);
    assert.deepEqual(scan('patched').findings, [], `${example.id} patched`);
  }
});

test('every rule has a title, a severity and a proof in the repository', () => {
  const rules = scanner.rules();
  const { proofs } = siteData();
  assert.ok(rules.length >= 26);
  assert.deepEqual(rules.map((r) => r.id), [...rules.map((r) => r.id)].sort());
  for (const rule of rules) {
    assert.match(rule.title, /\S/);
    assert.ok(['info', 'low', 'medium', 'high', 'critical'].includes(rule.severity), rule.id);
    assert.ok(proofs[rule.id], `${rule.id} has no fixture pair and exploit test`);
  }
});

test('a file that does not parse is a ScanFailed naming the file and position, and the next scan still works', () => {
  assert.throws(() => scanner.scan({ target: 't', files: [{ path: 'src/a.rs', text: 'fn broken( {' }] }), (error) => {
    assert.ok(error instanceof ScanFailed);
    assert.match(error.message, /^cannot parse src\/a\.rs:1:\d+: /);
    return true;
  });
  assert.equal(scanner.scan({ target: 't', files: [{ path: 'src/a.rs', text: 'pub fn ok() {}' }] }).summary.files_scanned, 1);
});

test('a malformed request is a message, not a crash', () => {
  assert.throws(() => scanner.scan({ target: 't' }), /malformed scan request/);
  assert.throws(() => scanner.scan({ target: 't', files: [{ path: 'a.rs', text: 1 }] }), /malformed scan request/);
});

test('non-ASCII source and file names survive the round trip', () => {
  const report = scanner.scan({ target: 'ünï', files: [{ path: 'src/λ.rs', text: '// 日本語 \u{1F600}\npub fn ok() {}' }] });
  assert.equal(report.target, 'ünï');
});

const CRATES = 'web/test/data/crates';

test('a tree of several crates (a build script, a nested workspace root, a loose file) matches the command line byte for byte, from every starting directory', () => {
  for (const dir of [CRATES, `${CRATES}/a`, `${CRATES}/nested`]) assert.equal(scanner.scanText(request(dir)), cliJson(dir), dir);
});

test('each file is judged under its own crate\'s build profile', () => {
  const pf022 = (dir) => scanner.scan(request(dir)).findings.filter((f) => f.rule_id === 'PF022').map((f) => f.file.split(':')[0]).sort();
  // build.rs sits in a's directory, so it takes a's profile (overflow checks off); nested is its own workspace root with its own profile.
  assert.deepEqual(pf022(CRATES), ['a/build.rs', 'nested/src/lib.rs']);
  assert.deepEqual(pf022(`${CRATES}/a`), ['build.rs']);
  assert.deepEqual(pf022(`${CRATES}/nested`), ['src/lib.rs']);
});

const SCOPE = 'web/test/data/scope';

test('test directories are cut as on the command line: counted and not scanned, byte for byte, with a crate inside tests/ and src/tests still read', () => {
  assert.equal(scanner.scanText(request(SCOPE)), cliJson(SCOPE));
  const report = scanner.scan(request(SCOPE));
  assert.deepEqual([report.summary.files_scanned, report.summary.test_files_skipped], [4, 3]);
  assert.deepEqual([...new Set(report.findings.map((f) => f.file.split(':')[0]))].sort(),
    ['examples/e.rs', 'src/lib.rs', 'src/tests/mod.rs', 'tests/vault/src/lib.rs']);
});

test('a scan that reads no file is a ScanFailed, never a report: no files, no Rust files, only test files', () => {
  const fails = (files, message) => assert.throws(() => scanner.scan({ target: 't', files }), (error) => {
    assert.ok(error instanceof ScanFailed);
    assert.match(error.message, message);
    return true;
  });
  fails([], /^no Rust source file to scan under t$/);
  fails([{ path: 'README.md', text: '# x' }], /^no Rust source file to scan under t$/);
  fails([{ path: 'Cargo.toml', text: '' }, { path: 'tests/it.rs', text: 'fn broken( {' }, { path: 'benches/b.rs', text: '' }],
    /^no Rust source file to scan under t \(2 skipped as test code/);
  assert.equal(scanner.scan({ target: 't', files: [{ path: 'src/a.rs', text: 'pub fn ok() {}' }] }).summary.files_scanned, 1, 'the next scan still works');
});

const nested = (open, close, depth) => `${open.repeat(depth)}${close.repeat(depth)}`;
const deep = {
  blocks: (n) => `pub fn f() { ${nested('{', '}', n)} }`,
  parentheses: (n) => `pub fn f() { let x = ${'('.repeat(n)}1${')'.repeat(n)}; }`,
  matches: (n) => `pub fn f() { ${'match 1 { _ => '.repeat(n)}1${' }'.repeat(n)} }`,
};

test('code nested hundreds of levels deep scans, as it does on the command line (the first build ran out of stack near 290 blocks)', () => {
  for (const [what, source] of Object.entries({ 'nested blocks': deep.blocks(400), 'nested parentheses': deep.parentheses(600), 'nested matches': deep.matches(400) })) {
    const text = scanner.scanText({ target: 't', files: [{ path: 'src/lib.rs', text: source }] });
    assert.equal(JSON.parse(text).summary.files_scanned, 1, what);
  }
});

test('code nested beyond what the page can take is a ScanFailed that names the nesting, not a bug in Preflight, and the next scan works', () => {
  assert.throws(() => scanner.scan({ target: 't', files: [{ path: 'src/lib.rs', text: deep.blocks(20000) }] }), (error) => {
    assert.ok(error instanceof ScanFailed);
    assert.match(error.message, /nested too deeply for the in-browser build/);
    assert.doesNotMatch(error.message, /bug in Preflight/);
    return true;
  });
  assert.equal(scanner.scan({ target: 't', files: [{ path: 'src/a.rs', text: 'pub fn ok() {}' }] }).summary.files_scanned, 1);
});
