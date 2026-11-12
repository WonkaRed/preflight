// The "On mainnet today" block: the build reads docs/mainnet-survey.md, the page checks what it is given and paints text only.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { mountSurvey, paintSurvey, parseSurvey, SURVEY_IDS } from '../src/survey.js';
import { mainnetSurvey, REPO_ROOT, surveyFrom } from '../tools/site-data.mjs';
import { fakeDocument, walk } from './fake-dom.mjs';

const page = readFileSync(`${REPO_ROOT}docs/mainnet-survey.md`, 'utf8');
const survey = mainnetSurvey();

test('the build takes every row, the read date and the header sentence from docs/mainnet-survey.md', () => {
  const lines = page.split('\n').filter((line) => line.startsWith('| `'));
  assert.equal(survey.rows.length, lines.length);
  assert.equal(survey.rows.length, 10);
  for (const [i, row] of survey.rows.entries()) assert.ok(lines[i].includes(`\`${row.account}\` | \`${row.codeHash}\` | ${row.fullAccessKeys} |`), row.account);
  assert.match(survey.readOn, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(page.includes(`Read on ${survey.readOn} from NEAR mainnet`));
  assert.equal(survey.summary, 'Having a key that can replace code is a design choice, not a defect; this table only shows that an address alone does not pin the code.');
  assert.ok(page.includes(survey.notEstablished));
  assert.deepEqual(parseSurvey(survey)?.rows, survey.rows, 'what the build writes is what the page accepts');
});

test('a survey page that no longer has the expected shape stops the build instead of shipping a part', () => {
  assert.throws(() => surveyFrom(page.replace('Read on', 'Looked at')), /no "Read on/);
  assert.throws(() => surveyFrom(page.replace('| `wrap.near` | `DL2f5xmZ44cQRP6vBMt94rvseH5d5KKnAGis2WkTAsh1` | 0 |', '| `wrap.near` | `short` | 0 |')), /table rows, 9 of them parse/);
  assert.throws(() => surveyFrom(page.replace('| `aurora` | `HrtBWvCMmVXRLG9vsYAFT7LfJ6mZtCSNTvYnXMF6fwzT` | 1 | 2026-11-12 |', '| `aurora` | `HrtBWvCMmVXRLG9vsYAFT7LfJ6mZtCSNTvYnXMF6fwzT` | 1 | 2026-11-01 |')), /aurora was read on 2026-11-01/);
  assert.throws(() => surveyFrom(page.replace(/^\| `[^\n]+\n/gm, '')), /0 table rows/);
});

test('the page refuses a survey file that is not what the build writes', () => {
  const bad = (change) => parseSurvey({ ...survey, ...change });
  assert.equal(bad({}) !== null, true);
  assert.equal(parseSurvey(null), null);
  assert.equal(bad({ rows: [] }), null);
  assert.equal(bad({ rows: [{ ...survey.rows[0], codeHash: 'x' }] }), null);
  assert.equal(bad({ rows: [{ ...survey.rows[0], account: '<img src=x>' }] }), null);
  assert.equal(bad({ rows: [{ ...survey.rows[0], fullAccessKeys: -1 }] }), null);
  assert.equal(bad({ rows: [{ ...survey.rows[0], fullAccessKeys: '0' }] }), null);
  assert.equal(bad({ readOn: 'yesterday' }), null);
  assert.equal(bad({ summary: '' }), null);
  assert.equal(bad({ endpoint: 'a b' }), null);
});

function sectionElements(doc) {
  return Object.fromEntries(Object.keys(SURVEY_IDS).map((name) => [name, Object.assign(doc.createElement('div'), { textContent: '' })]));
}

test('the table shows one row per contract with its fingerprint and key count, as text, and names no contract unsafe', () => {
  const doc = fakeDocument();
  const els = sectionElements(doc);
  paintSurvey(doc, els, parseSurvey(survey));
  const tags = [];
  const texts = [];
  walk(els.table, (n) => { tags.push(n.tag); if (n.text !== undefined) texts.push(n.text); });
  assert.equal(tags.filter((tag) => tag === 'tr').length, 11, 'a header row and ten contracts');
  for (const row of survey.rows) assert.ok(texts.includes(row.account) && texts.includes(row.codeHash), row.account);
  assert.equal(els.sub.textContent, survey.summary);
  assert.match(els.read.textContent, new RegExp(`Read on ${survey.readOn} from NEAR mainnet through ${survey.endpoint.replaceAll('.', '\\.')}, with read-only calls`));
  const everything = [els.sub.textContent, els.read.textContent, els.limits.textContent, ...texts].join(' ');
  assert.doesNotMatch(everything, /vulnerab|unsafe|\brisk|\bbug/i, 'facts only: no verdict about a named contract');
  assert.doesNotMatch(everything, /—|–/, 'no em or en dashes');
});

test('hostile text in the file is a text node, never markup', () => {
  const doc = fakeDocument();
  const els = sectionElements(doc);
  paintSurvey(doc, els, parseSurvey({ ...survey, summary: '<img src=x onerror=alert(1)>' }));
  assert.equal(els.sub.textContent, '<img src=x onerror=alert(1)>', 'textContent: the DOM takes it as text');
  const tags = [];
  walk(els.table, (n) => tags.push(n.tag));
  assert.ok(!tags.includes('img'));
});

test('a survey that cannot be loaded says so instead of leaving an empty block', async () => {
  for (const load of [async () => null, async () => { throw new Error('offline'); }, async () => ({ rows: [] })]) {
    const doc = fakeDocument();
    const els = sectionElements(doc);
    doc.getElementById = (id) => els[Object.keys(SURVEY_IDS).find((name) => SURVEY_IDS[name] === id)];
    await mountSurvey(doc, load);
    const texts = [];
    walk(els.table, (n) => { if (n.text !== undefined) texts.push(n.text); });
    assert.deepEqual(texts, ['The survey could not be loaded here. It is in the repository, linked below.']);
  }
});

test('the section is in the page, after How it works and before the scanner', () => {
  const html = readFileSync(new URL('../src/index.html', import.meta.url), 'utf8');
  for (const id of Object.values(SURVEY_IDS)) assert.match(html, new RegExp(`id="${id}"`), id);
  const at = (needle) => html.indexOf(needle);
  assert.ok(at('id="how"') < at('id="mainnet"') && at('id="mainnet"') < at('id="scan"'));
  assert.match(html, /<h2 id="mainnet-title">On mainnet today<\/h2>/);
});
