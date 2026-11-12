// What the page needs from the repository besides the scanner: the bundled examples and where each rule's proof lives.
// Both are read from `fixtures/` and `exploits/` at build time, so nothing is copied by hand and a rule added later
// gets its proof links without a change here.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

// Single-file fixtures whose vulnerable version fires a rule that reads well at a glance, in display order.
export const EXAMPLES = ['pf001_callback', 'pf002_one_yocto', 'pf007_unguarded_admin', 'pf012_div_before_mul', 'pf020_uninitialized_default'];

const read = (path) => readFileSync(`${REPO_ROOT}${path}`, 'utf8');
const ruleId = (slug) => slug.slice(0, 5).toUpperCase();

/** The recording the Swap replays when the chain cannot be read: `demo/swap/recorded.json`, or the JSON `null` (no recording yet). */
export const recordedSwaps = () => (existsSync(`${REPO_ROOT}demo/swap/recorded.json`) ? read('demo/swap/recorded.json') : 'null');

/** `{ examples: [{ id, rule, vulnerable, patched }], proofs: { PF001: { fixture, exploit } } }` with repo-relative paths. */
export function siteData() {
  const proofs = {};
  for (const slug of readdirSync(`${REPO_ROOT}fixtures`).filter((name) => /^pf\d{3}_/.test(name)).sort()) {
    const exploit = `exploits/tests/${slug}.rs`;
    if (!existsSync(`${REPO_ROOT}${exploit}`)) throw new Error(`${exploit} is missing: fixtures/${slug} has no exploit test`);
    for (const variant of ['vulnerable', 'patched']) {
      if (!existsSync(`${REPO_ROOT}fixtures/${slug}/${variant}`)) throw new Error(`fixtures/${slug}/${variant} is missing`);
    }
    proofs[ruleId(slug)] = { fixture: `fixtures/${slug}`, exploit };
  }
  const examples = EXAMPLES.map((slug) => ({
    id: slug,
    rule: ruleId(slug),
    vulnerable: read(`fixtures/${slug}/vulnerable/src/lib.rs`),
    patched: read(`fixtures/${slug}/patched/src/lib.rs`),
  }));
  return { examples, proofs };
}

const BASE58 = '[1-9A-HJ-NP-Za-km-z]';

/**
 * `docs/mainnet-survey.md` as the page's "On mainnet today" block shows it: the header sentence, the read date and endpoint, and the
 * table's rows, all taken from that page so the two cannot disagree. It throws when the page no longer has the shape this reads
 * (a row that does not parse, a row read on another day), so a rewritten survey stops the build instead of shipping a half-empty block.
 */
export const mainnetSurvey = () => surveyFrom(read('docs/mainnet-survey.md'));

/** `mainnetSurvey` for the text of the survey page. */
export function surveyFrom(text) {
  const pick = (pattern, what) => {
    const found = pattern.exec(text);
    if (!found) throw new Error(`docs/mainnet-survey.md has no ${what}`);
    return found.slice(1);
  };
  const [summary] = pick(/^# .+\n\n(.+)\n/, 'sentence under its title');
  const [readOn, endpoint] = pick(/^Read on (\d{4}-\d{2}-\d{2}) from NEAR mainnet through the RPC endpoint ([\w.-]+)/m, '"Read on <date> ... through the RPC endpoint <host>" paragraph');
  const [keyMeaning] = pick(/(A full-access key can deploy new code to its account at any time; the count is [^.\n]+\.)/, 'sentence saying what a full-access key can do');
  const [notEstablished] = pick(/^(Not established: .+)$/m, '"Not established:" paragraph');
  const rows = [...text.matchAll(new RegExp(`^\\| \`([^\`]+)\` \\| \`(${BASE58}{32,44})\` \\| (\\d+) \\| (\\d{4}-\\d{2}-\\d{2}) \\|$`, 'gm'))]
    .map(([, account, codeHash, keys, date]) => ({ account, codeHash, fullAccessKeys: Number(keys), date }));
  const tableLines = text.split('\n').filter((line) => line.startsWith('| `')).length;
  if (rows.length === 0 || rows.length !== tableLines) throw new Error(`docs/mainnet-survey.md: ${tableLines} table rows, ${rows.length} of them parse`);
  const stray = rows.find((row) => row.date !== readOn);
  if (stray) throw new Error(`docs/mainnet-survey.md: ${stray.account} was read on ${stray.date}, not ${readOn}`);
  return { summary, keyMeaning, readOn, endpoint, notEstablished, rows: rows.map(({ date, ...row }) => row) };
}
