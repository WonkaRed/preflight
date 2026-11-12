// The "On mainnet today" block: the rows of docs/mainnet-survey.md that web/tools/build.mjs wrote to mainnet-survey.json. The
// file is checked for the shape this page expects before it is used, and every value reaches the page as text.
import { isHash } from './near.js';
import { h } from './report.js';
import { isAccountId } from './swap.js';

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const sentence = (v) => typeof v === 'string' && v.length > 0 && v.length <= 700;
const MAX_ROWS = 50;

/** The survey as the page shows it, or null when `json` is not what the build writes. */
export function parseSurvey(json) {
  if (!isObject(json) || !['summary', 'keyMeaning', 'notEstablished'].every((name) => sentence(json[name]))) return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(json.readOn) || !/^[\w.-]{1,80}$/.test(json.endpoint)) return null;
  if (!Array.isArray(json.rows) || json.rows.length === 0 || json.rows.length > MAX_ROWS) return null;
  const rows = json.rows.map((row) => (isObject(row) && isAccountId(row.account) && isHash(row.codeHash) && Number.isSafeInteger(row.fullAccessKeys) && row.fullAccessKeys >= 0
    ? { account: row.account, codeHash: row.codeHash, fullAccessKeys: row.fullAccessKeys } : null));
  if (rows.includes(null)) return null;
  const { summary, keyMeaning, notEstablished, readOn, endpoint } = json;
  return { summary, keyMeaning, notEstablished, readOn, endpoint, rows };
}

/** The table, built from validated rows. */
export function surveyTable(doc, { rows, readOn }) {
  const head = h(doc, 'tr', {}, ...['Contract', 'Code fingerprint', 'Full-access keys'].map((name) => h(doc, 'th', { scope: 'col' }, name)));
  const body = rows.map((row) => h(doc, 'tr', {},
    h(doc, 'th', { scope: 'row' }, h(doc, 'code', {}, row.account)),
    h(doc, 'td', {}, h(doc, 'button', { type: 'button', class: 'hash', 'data-copy': true, title: row.codeHash, 'aria-label': `Copy the full code fingerprint (hash) of ${row.account}` }, row.codeHash)),
    h(doc, 'td', { class: 'num' }, String(row.fullAccessKeys))));
  return h(doc, 'table', { class: 'survey-table' }, h(doc, 'caption', {}, `Read from NEAR mainnet on ${readOn}`), h(doc, 'thead', {}, head), h(doc, 'tbody', {}, ...body));
}

/** Fills the section from a parsed survey, or says it could not be loaded. `els`: sub, read, table, limits. */
export function paintSurvey(doc, els, survey) {
  if (!survey) {
    els.table.replaceChildren(h(doc, 'p', { class: 'hint' }, 'The survey could not be loaded here. It is in the repository, linked below.'));
    return;
  }
  els.sub.textContent = survey.summary;
  els.read.textContent = `${survey.keyMeaning} Read on ${survey.readOn} from NEAR mainnet through ${survey.endpoint}, with read-only calls: no keys, no transactions. A snapshot: a later read can differ.`;
  els.limits.textContent = survey.notEstablished;
  els.table.replaceChildren(surveyTable(doc, survey));
}

export const SURVEY_IDS = { sub: 'mainnet-sub', read: 'mainnet-read', table: 'mainnet-table', limits: 'mainnet-limits' };

/** Loads mainnet-survey.json and paints it. Never throws: whatever goes wrong, the block says so. */
export async function mountSurvey(doc = document, load = () => fetch('mainnet-survey.json').then((r) => (r.ok ? r.json() : null))) {
  const els = Object.fromEntries(Object.entries(SURVEY_IDS).map(([name, id]) => [name, doc.getElementById(id)]));
  let survey = null;
  try { survey = parseSurvey(await load()); } catch { /* the block says it could not load */ }
  paintSurvey(doc, els, survey);
}
