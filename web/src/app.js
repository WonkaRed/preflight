import { REPO_TREE_URL } from './config.js';
import { LIMITS } from './github.js';
import { backgroundScanner } from './scan-client.js';
import { compileScanner, loadScanner } from './scanner.js';
import { createSession } from './session.js';
import { mountSwap } from './swap-view.js';
import { countBySeverity, h, plural, renderFindings, renderProblem, renderScanning, renderTally, renderVerdict, sortFindings, validate, verdict } from './report.js';

const $ = (id) => document.getElementById(id);
const SOURCE_PATH = 'src/lib.rs';
const GITHUB_DEMO = { repo: 'near/near-sdk-rs', ref: '', path: 'examples/lockable-fungible-token' };
const narrow = matchMedia('(max-width: 61.99rem)');

const state = { findings: [], selected: new Set(), proofOf: () => null };

// ---- Result pane -------------------------------------------------------------------------------------------------

function clearResult() {
  for (const id of ['notices', 'verdict', 'tally', 'findings']) $(id).replaceChildren();
}

function problem(title, problems, hint) {
  clearResult();
  $('verdict').append(renderProblem(document, title, problems, hint));
  revealResult();
}

// Stacked below the input on a narrow screen, the result starts off screen; bring it up after a scan the person asked for.
let reveal = false;
function revealResult() {
  if (reveal && narrow.matches) $('result').scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  reveal = false;
}

function showFindings() {
  const { findings, selected, proofOf } = state;
  const shown = findings.filter((f) => selected.size === 0 || selected.has(f.severity)).length;
  const bar = selected.size === 0 ? null : h(document, 'p', { class: 'filterbar' },
    `Showing ${shown} of ${plural(findings.length, 'finding')}`,
    Object.assign(h(document, 'button', { type: 'button', class: 'btn quiet' }, 'Show all'), {
      onclick: () => { selected.clear(); syncTally(); showFindings(); },
    }));
  $('findings').replaceChildren(...[bar, ...renderFindings(document, findings, selected, proofOf)].filter(Boolean));
}

function syncTally() {
  for (const b of $('tally').querySelectorAll('[data-sev]')) b.setAttribute('aria-pressed', String(state.selected.has(b.dataset.sev)));
}

function toggle(severity) {
  if (!state.selected.delete(severity)) state.selected.add(severity);
  syncTally();
  showFindings();
}

function showReport(report, { chip, notes = [] }) {
  const checked = validate(report);
  if (!checked.ok) return problem('The scanner returned a report this page cannot read', checked.errors, 'This is a bug in Preflight. The code you scanned is not at fault.');
  Object.assign(state, { findings: sortFindings(report.findings), selected: new Set() });
  $('notices').replaceChildren(...notes.map((note) => h(document, 'p', { class: 'notice', role: 'note' }, note)));
  $('verdict').replaceChildren(renderVerdict(document, report, verdict(state.findings, report.summary.files_scanned), { chip }));
  $('tally').replaceChildren(renderTally(document, countBySeverity(state.findings), state.selected, toggle));
  showFindings();
  revealResult();
}

async function boot() {
  let module;
  let scanner;
  let site;
  try {
    [module, site] = await Promise.all([
      compileScanner('preflight.wasm'),
      fetch('site-data.json').then((r) => (r.ok ? r.json() : Promise.reject(new Error(`site-data.json: the server answered ${r.status}`)))),
    ]);
    scanner = loadScanner(module);
  } catch (error) {
    return problem('The scanner could not be loaded', [error.message], 'Serve this folder over http (make -C web serve) instead of opening index.html from disk: browsers will not load WebAssembly from file://.');
  }

  // The buttons ship disabled: nothing can be scanned until the module has loaded, and if it did not they stay that way.
  for (const id of ['scan-source', 'scan-github', 'fill-github']) $(id).disabled = false;

  const session = createSession({
    scanner: backgroundScanner(module),
    view: {
      pending: (label) => { clearResult(); $('verdict').append(renderScanning(document, label)); },
      report: showReport,
      problem,
      progress: (text) => { $('github-progress').textContent = text; },
      running: (on) => {
        $('scan-github').disabled = on;
        $('cancel-github').hidden = !on;
        $('fill-github').hidden = on;
        if (!on) $('github-progress').textContent = '';
      },
    },
  });

  const rules = new Map(scanner.rules().map((rule) => [rule.id, rule]));
  $('rule-count').textContent = `${plural(rules.size, 'rule')}, runs in your browser`;
  for (const el of document.querySelectorAll('.rule-total')) el.textContent = `${rules.size} syntactic`;

  const link = (path) => ({ path, href: REPO_TREE_URL ? `${REPO_TREE_URL}/${path}` : null });
  state.proofOf = (id) => (site.proofs[id] ? { fixture: link(site.proofs[id].fixture), exploit: link(site.proofs[id].exploit) } : null);

  // Source tab: an example fills the same box a pasted contract goes in, so editing the example and scanning again needs no extra mode.
  const exampleLabel = (example, variant) => `${example.rule} ${variant} example`;
  const selectedExample = () => site.examples.find((e) => e.id === document.querySelector('input[name=example]:checked')?.value);
  const selectedVariant = () => document.querySelector('input[name=variant]:checked').value;

  for (const example of site.examples) {
    const rule = rules.get(example.rule);
    $('examples').append(h(document, 'label', {},
      h(document, 'input', { type: 'radio', name: 'example', value: example.id }),
      h(document, 'span', { class: `example sev-${rule.severity}` }, h(document, 'b', {}, rule.id), h(document, 'span', {}, rule.title))));
  }

  function scanSource() {
    const text = $('source').value;
    if (!text.trim()) return session.refuse('Nothing to scan', ['Paste some Rust source into the box first.']);
    if (text.length > LIMITS.fileBytes) return session.refuse('This source is too large', [`The box takes up to ${LIMITS.fileBytes / 1048576} MB of Rust. Scan a larger project through the GitHub tab.`]);
    const example = selectedExample();
    const variant = selectedVariant();
    const isExample = example && text === example[variant];
    session.source({ target: isExample ? exampleLabel(example, variant) : 'pasted source', files: [{ path: SOURCE_PATH, text }] }, isExample ? 'Bundled example' : null);
  }

  function loadExample() {
    const example = selectedExample();
    if (!example) return;
    $('source').value = example[selectedVariant()];
    scanSource();
  }

  document.querySelector('input[name=example]').checked = true;
  for (const input of document.querySelectorAll('input[name=example], input[name=variant]')) input.addEventListener('change', () => { reveal = true; loadExample(); });
  $('scan-source').addEventListener('click', () => { reveal = true; scanSource(); });
  $('source').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); reveal = true; scanSource(); }
  });

  // GitHub tab
  const scanGitHub = () => {
    reveal = true;
    session.github({ repo: $('repo').value, ref: $('ref').value, path: $('path').value });
  };
  $('pane-github').addEventListener('submit', (e) => { e.preventDefault(); scanGitHub(); });
  $('cancel-github').addEventListener('click', session.cancel);
  const fillGitHub = ({ repo, ref, path }) => { $('repo').value = repo; $('ref').value = ref; $('path').value = path; };
  $('fill-github').addEventListener('click', () => { fillGitHub(GITHUB_DEMO); $('scan-github').focus(); });

  // Start on a finding, so the first thing on the page is a result.
  loadExample();
  const query = new URLSearchParams(location.search);
  if (query.has('repo')) {
    fillGitHub({ repo: query.get('repo'), ref: query.get('ref') ?? '', path: query.get('path') ?? '' });
    selectTab('github');
    scanGitHub();
  }
}

// ---- Tabs --------------------------------------------------------------------------------------------------------

const TABS = ['source', 'github'];
function selectTab(name) {
  for (const tab of TABS) {
    const on = tab === name;
    $(`tab-${tab}`).setAttribute('aria-selected', String(on));
    $(`tab-${tab}`).tabIndex = on ? 0 : -1;
    $(`pane-${tab}`).hidden = !on;
  }
}
for (const name of TABS) {
  $(`tab-${name}`).addEventListener('click', () => selectTab(name));
  $(`tab-${name}`).addEventListener('keydown', (e) => {
    const step = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
    if (!step) return;
    const next = TABS[(TABS.indexOf(name) + step + TABS.length) % TABS.length];
    selectTab(next);
    $(`tab-${next}`).focus();
  });
}

mountSwap();
boot();
