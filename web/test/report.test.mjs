// The report model and renderer (src/report.js): validation, verdict, ordering, and the guarantee that scan text only ever
// reaches the page as text.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fakeDocument, walk } from './fake-dom.mjs';
import * as P from '../src/report.js';
import { request, scanner } from './helpers.mjs';

const data = (name) => JSON.parse(readFileSync(new URL(`data/${name}.json`, import.meta.url), 'utf8'));
// A real report from the real scanner, so the schema this page validates is the one the scanner prints.
const sample = (name) => (name === 'pf001-vulnerable' ? scanner.scan(request('fixtures/pf001_callback/vulnerable')) : name === 'pf001-patched' ? scanner.scan(request('fixtures/pf001_callback/patched')) : data(name));
const clone = (o) => structuredClone(o);

const finding = (severity, file = 'src/lib.rs', line = 1, column = 1, rule_id = 'PF001') =>
  ({ rule_id, title: 't', severity, file, line, column, item: 'i', message: 'm', help: 'h' });

test('the scanner\'s own reports and the hostile sample validate, and the report is returned untouched', () => {
  for (const name of ['pf001-vulnerable', 'pf001-patched', 'hostile-strings']) {
    const report = sample(name);
    const r = P.validate(report);
    assert.equal(r.ok, true, `${name}: ${r.errors}`);
    assert.equal(r.report, report);
  }
});

test('the malformed sample is rejected and every defect is named with its path', () => {
  const r = P.validate(sample('malformed-report'));
  assert.equal(r.ok, false);
  const all = r.errors.join('\n');
  for (const path of ['tool.version', 'summary.files_scanned', 'summary.by_severity.critical', 'findings[0].rule_id',
    'findings[0].severity', 'findings[0].line', 'findings[0].column', 'findings[1]']) {
    assert.match(all, new RegExp(path.replace(/[[\]]/g, '\\$&')), `no error for ${path}`);
  }
});

test('non-reports are rejected with a message, never a throw', () => {
  for (const bad of [null, 7, 'text', [], {}, { schema_version: 2 }, { schema_version: '1' }]) {
    const r = P.validate(bad);
    assert.equal(r.ok, false, JSON.stringify(bad));
    assert.ok(r.errors.length > 0);
  }
  assert.match(P.validate({ schema_version: 2 }).errors[0], /version 1, got the number 2/);
});

test('single-field breakage is caught', () => {
  const cases = [
    ['target', (r) => { r.target = 5; }, /target: expected a string/],
    ['findings missing', (r) => { delete r.findings; }, /findings: expected an array/],
    ['rule id shape', (r) => { r.findings[0].rule_id = 'PF0001'; }, /rule_id: expected PF followed by three digits/],
    ['float line', (r) => { r.findings[0].line = 1.5; }, /line: expected an integer of at least 1/],
    ['unknown severity', (r) => { r.findings[0].severity = 'catastrophic'; }, /severity: expected one of critical, high/],
    ['summary count', (r) => { r.summary.findings = 9; }, /summary.findings: says 9 but the report lists 1/],
    ['summary by severity', (r) => { r.summary.by_severity.high = 0; r.summary.by_severity.low = 1; }, /by_severity.high: says 0 but the report lists 1/],
    ['inherited key is not a field', (r) => { delete r.tool; Object.prototype.tool = { name: 'x', version: 'y' }; }, /tool: expected an object/],
  ];
  for (const [name, mutate, expected] of cases) {
    const r = sample('pf001-vulnerable');
    mutate(r);
    try {
      const out = P.validate(r);
      assert.equal(out.ok, false, name);
      assert.match(out.errors.join('\n'), expected, name);
    } finally {
      delete Object.prototype.tool;
    }
  }
});

test('a flood of problems is capped', () => {
  const r = sample('pf001-vulnerable');
  r.findings = Array.from({ length: 200 }, () => 'x');
  const out = P.validate(r);
  assert.equal(out.errors.length, 21);
  assert.match(out.errors.at(-1), /and 180 more problems/);
});

test('verdict follows the findings, not the summary', () => {
  assert.equal(P.verdict([], 1).level, 'clear');
  assert.equal(P.verdict([finding('info')], 1).level, 'minor');
  assert.equal(P.verdict([finding('low'), finding('medium')], 1).level, 'minor');
  assert.equal(P.verdict([finding('medium'), finding('high')], 1).level, 'severe');
  assert.equal(P.verdict([finding('critical')], 1).level, 'severe');
  const lying = sample('pf001-patched');
  lying.findings = [finding('critical')];
  assert.equal(P.verdict(lying.findings, lying.summary.files_scanned).level, 'severe');
});

test('verdict wording states the count by severity and never claims safety or gives an order', () => {
  const text = (...severities) => P.verdictText(P.verdict(severities.map(finding), 2), 2);
  const clear = P.verdictText(P.verdict([], 3), 3);
  assert.equal(clear.headline, 'No known rule fired');
  assert.match(clear.detail, /nothing in 3 files\. That does not mean the contract is safe/);
  assert.match(P.verdictText(P.verdict([], 1), 1).detail, /nothing in 1 file\./);
  assert.equal(text('high', 'high', 'high', 'high').headline, '4 high findings');
  assert.equal(text('high').headline, '1 high finding');
  assert.equal(text('critical', 'high', 'high').headline, '1 critical and 2 high findings');
  assert.equal(text('high', 'low', 'medium', 'high', 'info').headline, '2 high, 1 medium, 1 low and 1 info findings');
  assert.equal(text('low').headline, '1 low finding');
  assert.equal(text('high').detail, 'Each is a pattern match with a proof on a test contract; read each before trusting or dismissing it.');
  for (const t of [clear, text('low'), text('high'), text('critical', 'info')]) {
    assert.doesNotMatch(`${t.headline} ${t.detail}`.replace('does not mean the contract is safe', ''), /safe|secure|passed|block|warn|do not pay|before paying/i);
  }
});

test('a scan of no files is never a clean result', () => {
  const none = P.verdict([], 0);
  assert.equal(none.level, 'empty');
  const text = P.verdictText(none, 0);
  assert.equal(text.headline, 'Nothing was scanned');
  assert.match(text.detail, /read no files.*says nothing about the code/);
  assert.doesNotMatch(`${text.headline} ${text.detail}`, /No known rule fired|safe|clear/);
  assert.notEqual(P.verdict([], 1).level, 'empty');
});

test('the count of skipped test files is optional, must be a count when present, and is shown only when above zero', () => {
  const report = sample('pf001-vulnerable');
  const rows = (r) => {
    const out = [];
    walk(P.renderVerdict(fakeDocument(), r, P.verdict(r.findings, r.summary.files_scanned)), (n) => n.text !== undefined && out.push(n.text));
    return out;
  };
  assert.equal(P.validate(report).ok, true);
  assert.ok(!rows(report).includes('Test files skipped'));
  const skipped = { ...report, summary: { ...report.summary, test_files_skipped: 3 } };
  assert.equal(P.validate(skipped).ok, true);
  assert.deepEqual(rows(skipped).slice(rows(skipped).indexOf('Test files skipped')).slice(0, 2), ['Test files skipped', '3']);
  const zero = { ...report, summary: { ...report.summary, test_files_skipped: 0 } };
  assert.ok(!rows(zero).includes('Test files skipped'));
  for (const bad of [-1, 1.5, '3', null]) {
    const r = P.validate({ ...report, summary: { ...report.summary, test_files_skipped: bad } });
    assert.equal(r.ok, false, String(bad));
    assert.match(r.errors.join('\n'), /summary\.test_files_skipped: expected an integer of at least 0/);
  }
});

test('the verdict sentence says when files were skipped as test code, and only then', () => {
  const clear = P.verdict([], 3);
  assert.ok(!/skipped/.test(P.verdictText(clear, 3).detail));
  assert.ok(!/skipped/.test(P.verdictText(clear, 3, 0).detail));
  assert.match(P.verdictText(clear, 3, 1).detail, /nothing in 3 files\. .* 1 file under tests or benches was skipped as test code and not scanned\.$/);
  const found = P.verdictText(P.verdict(['high'].map(finding), 2), 2, 4);
  assert.match(found.detail, /read each before trusting or dismissing it\. 4 files under tests or benches were skipped as test code and not scanned\.$/);
  const doc = fakeDocument();
  const report = { target: 't', tool: { name: 'preflight', version: '0' }, summary: { files_scanned: 3, test_files_skipped: 2 }, findings: [] };
  const texts = [];
  walk(P.renderVerdict(doc, report, P.verdict([], 3)), (n) => n.text !== undefined && texts.push(n.text));
  assert.ok(texts.some((t) => /2 files under tests or benches were skipped/.test(t)));
});

test('the scanning panel names what is being scanned, as text', () => {
  const doc = fakeDocument();
  const panel = P.renderScanning(doc, '<img src=x onerror=1>a/b');
  assert.deepEqual(panel.attrs, { class: 'verdict verdict-empty', role: 'status' });
  const texts = [];
  walk(panel, (n) => n.text !== undefined && texts.push(n.text));
  assert.equal(texts[0], 'Scanning <img src=x onerror=1>a/b');
});

test('findings sort by severity, then file, line, column, rule id', () => {
  const input = [
    finding('low', 'a.rs'), finding('high', 'b.rs', 2), finding('critical', 'z.rs'), finding('high', 'b.rs', 1, 9),
    finding('high', 'a.rs', 30), finding('high', 'b.rs', 1, 2, 'PF003'), finding('high', 'b.rs', 1, 2, 'PF001'), finding('info', 'a.rs'),
  ];
  const keys = P.sortFindings(input).map((f) => `${f.severity} ${f.file}:${f.line}:${f.column} ${f.rule_id}`);
  assert.deepEqual(keys, [
    'critical z.rs:1:1 PF001', 'high a.rs:30:1 PF001', 'high b.rs:1:2 PF001', 'high b.rs:1:2 PF003',
    'high b.rs:1:9 PF001', 'high b.rs:2:1 PF001', 'low a.rs:1:1 PF001', 'info a.rs:1:1 PF001',
  ]);
  assert.equal(input[0].severity, 'low', 'input is not mutated');
  assert.deepEqual(P.countBySeverity(input), { critical: 1, high: 5, medium: 0, low: 1, info: 1 });
});

test('hostile report text is rendered as text nodes, never as markup', () => {
  const report = sample('hostile-strings');
  const doc = fakeDocument();
  const findings = P.sortFindings(report.findings);
  const trees = [
    P.renderVerdict(doc, report, P.verdict(findings, report.summary.files_scanned)),
    P.renderTally(doc, P.countBySeverity(findings), new Set(), () => {}),
    ...P.renderFindings(doc, findings, new Set(), () => ({ fixture: { path: 'fixtures/x', href: null }, exploit: { path: 'exploits/tests/x.rs', href: null } })),
  ];
  const tags = new Set();
  const texts = [];
  const attrValues = [];
  for (const tree of trees) {
    walk(tree, (n) => {
      if (n.tag) { tags.add(n.tag); attrValues.push(...Object.values(n.attrs)); }
      if (n.text !== undefined) texts.push(n.text);
    });
  }
  const rendered = texts.join('\n');
  const worst = report.findings[0];
  assert.ok(worst.message.includes('<script>') && worst.item.includes('<script>'), 'sample must carry script markup in message and item');
  for (const s of [worst.message, worst.item, worst.title, worst.file.split(':')[0], report.target, report.tool.name]) {
    assert.ok(rendered.includes(s), `missing verbatim text: ${s}`);
  }
  const expected = ['section', 'p', 'code', 'span', 'h2', 'h3', 'dl', 'div', 'dt', 'dd', 'button', 'article', 'li', 'ol', 'b'];
  assert.deepEqual([...tags].filter((t) => !expected.includes(t)), [], 'an element the renderer does not create appeared');
  for (const v of attrValues) assert.doesNotMatch(v, /[<>]|pwned|onerror/, `report text leaked into an attribute: ${v}`);
});

test('an attribute set to false is left off: only an empty severity is disabled', () => {
  const doc = fakeDocument();
  const tally = P.renderTally(doc, { critical: 2, high: 0, medium: 1, low: 0, info: 0 }, new Set(['medium']), () => {});
  const state = Object.fromEntries(tally.kids.map((b) => [b.attrs['data-sev'], b.attrs]));
  assert.ok(!('disabled' in state.critical), 'a severity with findings must stay clickable');
  assert.ok(!('disabled' in state.medium));
  assert.equal(state.high.disabled, '');
  assert.equal(state.low.disabled, '');
  assert.equal(state.medium['aria-pressed'], 'true');
  assert.equal(state.critical['aria-pressed'], 'false');
});

test('proof paths render as links only when the repository address is configured', () => {
  const doc = fakeDocument();
  const proof = (href) => ({ fixture: { path: 'fixtures/pf001_callback', href }, exploit: { path: 'exploits/tests/pf001_callback.rs', href } });
  const tags = (href) => {
    const found = [];
    for (const tree of P.renderFindings(doc, [finding('high')], new Set(), () => proof(href))) walk(tree, (n) => found.push(n));
    return found;
  };
  assert.equal(tags(null).filter((n) => n.tag === 'a').length, 0, 'no dead links while the address is unset');
  const links = tags('https://example.test/tree/main/fixtures/pf001_callback').filter((n) => n.tag === 'a');
  assert.equal(links.length, 2);
  assert.ok(links.every((a) => a.attrs.href.startsWith('https://example.test/') && a.attrs.rel === 'noopener'));
});

test('control and bidirectional characters in scan text are replaced, never rendered', () => {
  const doc = fakeDocument();
  const hostile = finding('high', 'src/\u202Elib.rs', 1, 1);
  hostile.message = 'a\u0000b\u200Fc\u2066d\r\ne\tf';
  const texts = [];
  for (const tree of P.renderFindings(doc, [hostile], new Set())) walk(tree, (n) => n.text !== undefined && texts.push(n.text));
  const rendered = texts.join('');
  assert.match(rendered, /src\/\uFFFDlib\.rs/);
  assert.equal(rendered.includes('\u202E') || rendered.includes('\u0000') || rendered.includes('\u200F') || rendered.includes('\u2066'), false);
  assert.ok(rendered.includes('a\uFFFDb\uFFFDc\uFFFDd\uFFFD\ne\tf'), 'newline and tab stay, carriage return does not');
});

test('a finding\'s fix reads as "Fix", a space, then the help text, so copied text is not "Fixadd"', () => {
  const doc = fakeDocument();
  const texts = [];
  walk(P.renderFindings(doc, [{ ...finding('high'), help: 'add the guard' }], new Set())[0], (n) => n.text !== undefined && texts.push(n.text));
  assert.ok(texts.join('').includes('Fix add the guard'), texts.join('|'));
});

test('a problem renders its title, each line and the hint as text', () => {
  const doc = fakeDocument();
  const texts = [];
  walk(P.renderProblem(doc, 'T <b>', ['one <i>', 'two'], 'hint'), (n) => n.text !== undefined && texts.push(n.text));
  assert.deepEqual(texts, ['T <b>', 'one <i>', 'two', 'hint']);
});
