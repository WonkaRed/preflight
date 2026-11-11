// The report model and its renderer: validation of a scanner report, severity and verdict rules, and the DOM
// builders. Every string that comes from a scan (file paths, item names, messages) is untrusted: it only ever
// reaches the page as a text node, after `clean`. Nothing here parses markup or touches the network.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const SUPPORTED_SCHEMA = 1;
const MAX_PROBLEMS = 20;

const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const own = (o, k) => (Object.hasOwn(o, k) ? o[k] : undefined);
export const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

function describe(v) {
  if (v === undefined) return 'nothing (the field is missing)';
  if (v === null) return 'null';
  if (typeof v === 'string') return `the string ${JSON.stringify(v.length > 40 ? `${v.slice(0, 40)}...` : v)}`;
  if (Array.isArray(v)) return 'an array';
  if (typeof v === 'object') return 'an object';
  return `the ${typeof v} ${v}`;
}

// Checks a parsed report against SPEC.md section 3. Returns { ok, report } or { ok, errors }.
export function validate(data) {
  const errors = [];
  const fail = (path, want, got) => errors.push(`${path}: expected ${want}, got ${describe(got)}`);
  const at = (path, key) => (path ? `${path}.${key}` : key);
  const text = (o, key, path) => {
    const v = own(o, key);
    if (typeof v !== 'string') fail(at(path, key), 'a string', v);
  };
  const count = (o, key, path, min) => {
    const v = own(o, key);
    if (!Number.isInteger(v) || v < min) fail(at(path, key), `an integer of at least ${min}`, v);
  };
  const object = (o, key, path) => {
    const v = own(o, key);
    if (isObject(v)) return v;
    fail(at(path, key), 'an object', v);
    return null;
  };

  if (!isObject(data)) return { ok: false, errors: [`report: expected an object, got ${describe(data)}`] };
  const version = own(data, 'schema_version');
  if (version !== SUPPORTED_SCHEMA) {
    return { ok: false, errors: [`schema_version: this page reads version ${SUPPORTED_SCHEMA}, got ${describe(version)}`] };
  }

  const tool = object(data, 'tool', '');
  if (tool) { text(tool, 'name', 'tool'); text(tool, 'version', 'tool'); }
  text(data, 'target', '');

  const summary = object(data, 'summary', '');
  if (summary) {
    count(summary, 'files_scanned', 'summary', 0);
    if (own(summary, 'test_files_skipped') !== undefined) count(summary, 'test_files_skipped', 'summary', 0);
    count(summary, 'findings', 'summary', 0);
    const by = object(summary, 'by_severity', 'summary');
    if (by) for (const s of SEVERITIES) count(by, s, 'summary.by_severity', 0);
  }

  const findings = own(data, 'findings');
  if (!Array.isArray(findings)) {
    fail('findings', 'an array', findings);
  } else {
    findings.forEach((f, i) => {
      const path = `findings[${i}]`;
      if (!isObject(f)) return fail(path, 'an object', f);
      const id = own(f, 'rule_id');
      if (typeof id !== 'string' || !/^PF\d{3}$/.test(id)) fail(`${path}.rule_id`, 'PF followed by three digits', id);
      if (!SEVERITIES.includes(own(f, 'severity'))) fail(`${path}.severity`, `one of ${SEVERITIES.join(', ')}`, own(f, 'severity'));
      for (const key of ['title', 'file', 'item', 'message', 'help']) text(f, key, path);
      count(f, 'line', path, 1);
      count(f, 'column', path, 1);
    });
  }

  if (!errors.length) {
    const counts = countBySeverity(findings);
    if (summary.findings !== findings.length) {
      errors.push(`summary.findings: says ${summary.findings} but the report lists ${findings.length} findings`);
    }
    for (const s of SEVERITIES) {
      if (summary.by_severity[s] !== counts[s]) {
        errors.push(`summary.by_severity.${s}: says ${summary.by_severity[s]} but the report lists ${counts[s]}`);
      }
    }
  }

  if (errors.length > MAX_PROBLEMS) {
    const more = errors.length - MAX_PROBLEMS;
    errors.length = MAX_PROBLEMS;
    errors.push(`...and ${plural(more, 'more problem')}`);
  }
  return errors.length ? { ok: false, errors } : { ok: true, report: data };
}

// Most severe first, then file, line, column, rule id.
export function sortFindings(findings) {
  const rank = (f) => SEVERITIES.indexOf(f.severity);
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  return [...findings].sort((a, b) =>
    rank(a) - rank(b) || cmp(a.file, b.file) || a.line - b.line || a.column - b.column || cmp(a.rule_id, b.rule_id));
}

export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

// Derived from the findings themselves, never from the report's own summary. The level only picks the panel's tint. A
// scan that read no files is its own level: it must never look like a clean one.
export function verdict(findings, filesScanned) {
  const counts = countBySeverity(findings);
  const level = filesScanned === 0 ? 'empty'
    : counts.critical + counts.high > 0 ? 'severe' : findings.length > 0 ? 'minor' : 'clear';
  return { level, counts, total: findings.length };
}

// States what was found and how many, by severity; it never says whether to pay, trust or ship.
export function verdictText(verdict, filesScanned, testFilesSkipped = 0) {
  const words = verdictWords(verdict, filesScanned);
  if (testFilesSkipped > 0) {
    words.detail += ` ${plural(testFilesSkipped, 'file')} under tests or benches ${testFilesSkipped === 1 ? 'was' : 'were'} skipped as test code and not scanned.`;
  }
  return words;
}

function verdictWords({ level, counts, total }, filesScanned) {
  if (level === 'empty') {
    return { headline: 'Nothing was scanned', detail: 'Preflight read no files, so no rule had anything to check. That says nothing about the code.' };
  }
  if (level !== 'clear') {
    const parts = SEVERITIES.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
    const list = parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}` : parts[0];
    return {
      headline: `${list} ${total === 1 ? 'finding' : 'findings'}`,
      detail: 'Each is a pattern match with a proof on a test contract; read each before trusting or dismissing it.',
    };
  }
  return {
    headline: 'No known rule fired',
    detail: `Preflight's rules matched nothing in ${plural(filesScanned, 'file')}. That does not mean the contract is safe, only that no rule it knows fired.`,
  };
}

// Control and bidirectional-override characters can reorder or hide text (a file name that reads `lib.rs` and is
// not). Each is shown as U+FFFD instead of being dropped, so a hostile name stays visibly odd. Tab and newline are
// kept: messages are laid out with `white-space: pre-line`.
const UNSAFE_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF\uFFF9-\uFFFB]/gu;
export const clean = (text) => text.replace(UNSAFE_CHARS, '\uFFFD');

// Scan strings only ever reach the page as text nodes; props are fixed names and values from this file or the
// page's own configuration, never from a scan.
export function h(doc, tag, props, ...kids) {
  const el = doc.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v === null || v === undefined) continue;
    el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(typeof kid === 'string' ? doc.createTextNode(clean(kid)) : kid);
  }
  return el;
}

export function renderVerdict(doc, report, v, { chip = null } = {}) {
  const words = verdictText(v, report.summary.files_scanned, report.summary.test_files_skipped ?? 0);
  const meta = (label, value) => h(doc, 'div', {}, h(doc, 'dt', {}, label), h(doc, 'dd', {}, value));
  const skipped = report.summary.test_files_skipped ?? 0;
  return h(doc, 'section', { class: `verdict verdict-${v.level}`, role: 'status', 'aria-labelledby': 'verdict-head' },
    h(doc, 'p', { class: 'vtarget' }, h(doc, 'code', {}, report.target), chip && h(doc, 'span', { class: 'chip' }, chip)),
    h(doc, 'h2', { class: 'vhead', id: 'verdict-head' }, words.headline),
    h(doc, 'p', { class: 'vdetail' }, words.detail),
    h(doc, 'dl', { class: 'meta' },
      meta('Files scanned', String(report.summary.files_scanned)),
      skipped > 0 && meta('Test files skipped', String(skipped)),
      meta('Findings', String(v.total)),
      meta('Scanner', `${report.tool.name} ${report.tool.version}`)));
}

/** The result pane while a scan runs, so a finished result can never be read as this scan's. */
export function renderScanning(doc, label) {
  return h(doc, 'section', { class: 'verdict verdict-empty', role: 'status' },
    h(doc, 'h2', { class: 'vhead' }, `Scanning ${label}`),
    h(doc, 'p', { class: 'vdetail' }, 'The result appears here when the scan finishes.'));
}

export function renderTally(doc, counts, selected, onToggle) {
  return h(doc, 'div', { class: 'tally', role: 'group', 'aria-label': 'Filter findings by severity' },
    SEVERITIES.map((s) => {
      const button = h(doc, 'button',
        { type: 'button', class: `tcell sev-${s}`, 'data-sev': s, 'aria-pressed': selected.has(s) ? 'true' : 'false', disabled: counts[s] === 0 },
        h(doc, 'span', { class: 'tnum' }, String(counts[s])),
        h(doc, 'span', { class: 'tlabel' }, LABEL[s]));
      button.addEventListener('click', () => onToggle(s));
      return button;
    }));
}

// `proof(ruleId)` returns what backs a rule: `{ fixture, exploit }`, each `{ path, href }` where `href` is null until
// the repository's address is configured (the path is then shown as text, never as a dead link).
function renderProof(doc, proof) {
  const item = (label, { path, href }) =>
    h(doc, 'span', { class: 'pf' }, label, href ? h(doc, 'a', { href, rel: 'noopener' }, path) : h(doc, 'code', {}, path));
  return h(doc, 'p', { class: 'proof' }, h(doc, 'b', {}, 'Proof'), item('fixture pair', proof.fixture), item('sandbox exploit test', proof.exploit));
}

function renderFinding(doc, f, proof) {
  return h(doc, 'li', {},
    h(doc, 'article', { class: `finding sev-${f.severity}` },
      h(doc, 'div', { class: 'fhead' },
        h(doc, 'span', { class: 'rid' }, f.rule_id),
        h(doc, 'h3', { class: 'ftitle' }, f.title),
        h(doc, 'span', { class: 'badge' }, LABEL[f.severity])),
      h(doc, 'p', { class: 'floc' },
        h(doc, 'code', { class: 'file' }, `${f.file}:${f.line}:${f.column}`),
        h(doc, 'code', { class: 'item' }, f.item)),
      h(doc, 'p', { class: 'msg' }, f.message),
      h(doc, 'p', { class: 'fix' }, h(doc, 'b', {}, 'Fix'), f.help),
      proof && renderProof(doc, proof)));
}

// `findings` must already be sorted; one severity section per non-empty group the filter lets through.
export function renderFindings(doc, findings, selected, proofOf = () => null) {
  return SEVERITIES
    .filter((s) => selected.size === 0 || selected.has(s))
    .map((s) => [s, findings.filter((f) => f.severity === s)])
    .filter(([, items]) => items.length)
    .map(([s, items]) =>
      h(doc, 'section', { class: `group sev-${s}`, 'aria-labelledby': `group-${s}` },
        h(doc, 'h2', { class: 'ghead', id: `group-${s}` }, LABEL[s], h(doc, 'span', { class: 'gcount' }, String(items.length))),
        h(doc, 'ol', { class: 'flist' }, items.map((f) => renderFinding(doc, f, proofOf(f.rule_id))))));
}

export function renderProblem(doc, title, problems, hint = null) {
  return h(doc, 'section', { class: 'problem', role: 'alert' },
    h(doc, 'h2', {}, title),
    h(doc, 'ul', {}, problems.map((p) => h(doc, 'li', {}, p))),
    hint && h(doc, 'p', { class: 'hint' }, hint));
}
