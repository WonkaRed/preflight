// "Check a contract you know", on the page: `viewModel` turns what account-check.js found into plain strings (tested directly),
// `paint` writes them into the result pane as text nodes and `mountAccountCheck` wires the form. Nothing the visitor typed, and
// nothing the chain or the registry returned, is ever parsed as markup: links are built only from a validated account id or
// hash, the configured explorer, and a report URL that `reportHref` accepts (this repository's own pages on github.com).
import { EXAMPLES, NETWORKS, REGISTRY, checkAccount, validateAccountId } from './account-check.js';
import { isHash } from './near.js';
import { h, plural } from './report.js';
import { RULE_WORDS } from './swap-agent.js';
import { STATUS_OF, isAccountId } from './swap.js';

const MAX_SHOWN = 80;
const shown = (text) => (text.length > MAX_SHOWN ? `${text.slice(0, MAX_SHOWN)}...` : text);
const label = (network) => NETWORKS[network].label;
const where = (network) => `NEAR ${label(network).toLowerCase()}`;
const ruleList = (ids) => ids.join(', ');

// The registry's report URLs point at this repository. A verdict's URL comes from the chain, so it becomes a link only when it is that.
const REPORT_HOST = 'github.com';
const REPORT_PATH = '/WonkaRed/preflight/';
export function reportHref(reportUrl) {
  let url;
  try { url = new URL(reportUrl); } catch { return null; }
  return url.protocol === 'https:' && url.host === REPORT_HOST && url.pathname.startsWith(REPORT_PATH) ? url.href : null;
}

const REGISTRY_NOTE = 'Preflight\'s registry is on testnet for now, so this applies the guard\'s rule to the testnet registry\'s verdicts; a guard on mainnet needs a registry there.';

const WORD = { allow: 'ALLOW', warn: 'WARN', block: 'BLOCK' };

function keysText({ keys, publisher }) {
  const global = publisher ? `This account runs a global contract published by ${publisher}, who can replace it at any time. ` : '';
  if (keys === null) return `${global}The key list could not be read just now.`;
  if (keys > 0) return `${global}${plural(keys, 'full-access key')}. Whoever holds one can deploy new code here at any time.`;
  return `${global}0 full-access keys: no key can redeploy this code directly. That does not mean it can never change: a contract can replace its own code through its own logic, or through a DAO vote.`;
}

function lineFor({ guard, verdict }) {
  if (guard.decision === 'allow') return 'An agent behind the guard may pay this contract. Preflight has a Safe verdict for exactly this code.';
  if (guard.decision === 'warn') {
    return verdict.registered
      ? `The guard would stop and ask a person first. Preflight flagged exactly this code with a warning (${ruleList(verdict.ruleIds)}).`
      : 'The guard would stop and ask a person first. Preflight has no verdict for exactly this code, so it cannot vouch for it.';
  }
  const meaning = verdict.ruleIds.map((id) => (RULE_WORDS[id] ? `${id}: ${RULE_WORDS[id]}` : id)).join('; ');
  return `The guard would refuse to pay. Preflight found a hole in exactly this code${meaning ? ` (${meaning})` : ''}.`;
}

function verdictFact(verdict) {
  const name = 'Preflight verdict for this code';
  if (!verdict.registered) return { label: name, text: 'None yet. Preflight has not looked at this code, or the code changed since it did.', link: null };
  const href = reportHref(verdict.reportUrl);
  const text = `${STATUS_OF[verdict.decision]}${verdict.ruleIds.length ? ` (${ruleList(verdict.ruleIds)})` : ''}${verdict.auditor ? `, published by ${verdict.auditor}` : ''}.`;
  return { label: name, text, link: href && { href, text: 'Read the report' } };
}

function techFor(result) {
  const reads = `Read through ${result.host ?? 'the public RPC'}: view_account (the code hash), view_access_key_list (the full-access keys) and, on NEAR testnet where Preflight's registry lives, get_verdict for that hash. A code hash is the same on every network, so the lookup is the same for a mainnet account.`;
  const rule = 'The guard\'s rule: an Unsafe verdict is BLOCK, a Warn verdict is WARN, a Safe verdict is ALLOW, and no verdict is WARN. A WARN needs a person to approve it; with nobody to ask, the guard refuses. If the chain or the registry cannot be read, it refuses too.';
  const trust = 'This page uses the code hash the RPC reports. The guard also downloads the deployed code and hashes the bytes itself, and it asks one network for both the code and the registry.';
  return [reads, rule, trust];
}

const addressLink = (result) => ({
  address: result.accountId,
  addressHref: isAccountId(result.accountId) ? `${NETWORKS[result.network].explorerUrl}/address/${result.accountId}` : null,
});

function problem(title, items, hint) {
  return { kind: 'problem', problem: { title, items, hint } };
}

const card = (result, body) => ({
  kind: 'card',
  card: { sub: `${label(result.network)}${result.host ? `, read just now through ${result.host}` : ''}`, rules: '', ruleWords: '', facts: [], tech: [], ...addressLink(result), explorer: { href: `${NETWORKS[result.network].explorerUrl}/address/${result.accountId}`, text: `View ${result.accountId} on nearblocks` }, ...body },
});

const mismatch = (result) => {
  if (result.network === 'mainnet' && result.accountId.endsWith('.testnet')) return ' It looks like a testnet account: switch to Testnet.';
  if (result.network === 'testnet' && result.accountId.endsWith('.near')) return ' It looks like a mainnet account: switch to Mainnet.';
  return '';
};

/**
 * What the result pane shows for `view`: `{ phase: 'idle' }`, `{ phase: 'loading', accountId, network }`, `{ phase: 'invalid', input, reason }` or
 * `{ phase: 'done', result }` (account-check.js `checkAccount`). Returns `{ kind: 'idle' | 'loading' | 'problem' | 'card', ... }`.
 */
export function viewModel(view) {
  if (view.phase === 'idle') return { kind: 'idle' };
  if (view.phase === 'loading') return { kind: 'loading', accountId: view.accountId, line: `Asking ${where(view.network)} what code is deployed at ${view.accountId}.` };
  if (view.phase === 'invalid') {
    return problem('That is not a NEAR account name', [view.reason, ...(view.input.trim() === '' ? [] : [`You typed: ${shown(view.input)}`])], 'Account names look like wrap.near, aurora or alice.testnet. Nothing was sent anywhere.');
  }
  const { result } = view;
  if (result.state === 'failed') {
    const source = result.what === 'registry' ? 'Preflight\'s registry' : where(result.network);
    return problem(`Could not read ${source} just now`, ['The public servers did not give a usable answer (they sometimes slow down or turn requests away). No verdict was made.', `Detail: ${shown(result.detail)}`], `Press Check this account to try again in a few seconds. An agent behind the guard refuses to pay while it cannot check.`);
  }
  if (result.state === 'missing') {
    return card(result, {
      tone: 'trust', word: 'NOT FOUND',
      line: `There is no account called ${result.accountId} on ${where(result.network)}.${mismatch(result)} Check the spelling.`,
      tech: ['The chain answered UNKNOWN_ACCOUNT. The guard\'s check allows an account that does not exist (nothing to audit), but a call to it can only fail, so the guarded call refuses it.'],
    });
  }
  if (result.state === 'nocode') {
    return card(result, {
      tone: 'trust', word: 'NO CODE',
      line: 'This account exists, but no contract is deployed on it, so there is no code to check. The guard would BLOCK a call here: it refuses to call an account with no code.',
      tech: ['The account\'s code hash is all zeros, which is how NEAR says "no contract". The guard\'s check allows it (nothing to audit); the guarded call refuses it, because a function call there can only fail or reach code deployed after the check.'],
    });
  }
  if (result.state === 'global') {
    return card(result, {
      tone: 'trust', word: 'GLOBAL',
      line: `This account runs a global contract that its publisher, ${result.publisher}, chose. The account does not name the code, so this page cannot tell which code that is and decides nothing. The guard reads the code itself and checks it.`,
      facts: [{ label: 'Who can swap this code', text: keysText({ keys: result.keys, publisher: result.publisher }), link: null }],
      tech: techFor(result).slice(0, 1),
    });
  }
  const { guard, verdict } = result;
  return card(result, {
    tone: guard.decision, word: WORD[guard.decision], rules: ruleList(verdict.ruleIds), ruleWords: verdict.ruleIds.map((id) => RULE_WORDS[id]).filter(Boolean).join('; '),
    line: lineFor(result),
    facts: [
      { label: 'Who can swap this code', text: keysText(result), link: null },
      verdictFact(verdict),
      ...(result.network === 'mainnet' ? [{ label: 'Where the verdicts live', text: REGISTRY_NOTE, link: null }] : []),
    ],
    hash: isHash(result.codeHash) ? result.codeHash : null,
    tech: techFor(result),
  });
}

const fact = (doc, { label: name, text, link }) => h(doc, 'div', { class: 'fact' },
  h(doc, 'dt', {}, name),
  h(doc, 'dd', {}, text, link && [' ', h(doc, 'a', { href: link.href, target: '_blank', rel: 'noopener noreferrer' }, link.text)]));

function cardNode(doc, c) {
  return h(doc, 'article', { class: 'card', 'data-tone': c.tone },
    h(doc, 'div', { class: 'card-head' },
      h(doc, 'div', { class: 'card-top' },
        h(doc, 'h2', {}, 'Preflight\'s guard'),
        h(doc, 'code', { class: 'addr' }, c.addressHref ? h(doc, 'a', { href: c.addressHref, target: '_blank', rel: 'noopener noreferrer' }, c.address) : c.address)),
      h(doc, 'p', { class: 'card-sub' }, c.sub),
      h(doc, 'p', { class: 'word' }, h(doc, 'span', {}, c.word), h(doc, 'span', { class: 'rules', title: c.ruleWords }, c.rules))),
    h(doc, 'div', { class: 'card-body' },
      h(doc, 'p', { class: 'card-line' }, c.line),
      c.hash && h(doc, 'p', { class: 'hashline' },
        h(doc, 'span', { title: 'A hash of the deployed code: change one byte and it changes.' }, 'Code fingerprint'),
        h(doc, 'button', { type: 'button', class: 'hash', 'data-copy': true, title: c.hash, 'aria-label': 'Copy the full code fingerprint (hash)' }, c.hash)),
      c.facts.length > 0 && h(doc, 'dl', { class: 'facts' }, c.facts.map((f) => fact(doc, f))),
      h(doc, 'p', { class: 'check-link' }, h(doc, 'a', { href: c.explorer.href, target: '_blank', rel: 'noopener noreferrer' }, c.explorer.text)),
      h(doc, 'details', { class: 'tech' }, h(doc, 'summary', {}, 'Technical detail'), c.tech.map((text) => h(doc, 'p', {}, text)))));
}

const legendItem = (doc, word, text) => h(doc, 'li', {}, h(doc, 'b', {}, word), ` ${text}`);

/** Replaces the children of `pane` with what `model` describes. */
export function paint(doc, pane, model) {
  pane.setAttribute('aria-busy', model.kind === 'loading' ? 'true' : 'false');
  if (model.kind === 'problem') {
    const { title, items, hint } = model.problem;
    pane.replaceChildren(h(doc, 'section', { class: 'problem', role: 'alert' }, h(doc, 'h2', {}, title), h(doc, 'ul', {}, items.map((item) => h(doc, 'li', {}, item))), h(doc, 'p', { class: 'hint' }, hint)));
  } else if (model.kind === 'card') {
    pane.replaceChildren(cardNode(doc, model.card));
  } else if (model.kind === 'loading') {
    pane.replaceChildren(h(doc, 'article', { class: 'card', 'data-tone': 'trust' },
      h(doc, 'div', { class: 'card-head' }, h(doc, 'div', { class: 'card-top' }, h(doc, 'h2', {}, 'Preflight\'s guard')), h(doc, 'p', { class: 'word' }, h(doc, 'span', {}, 'CHECKING'))),
      h(doc, 'div', { class: 'card-body' }, h(doc, 'p', { class: 'card-line', role: 'status' }, model.line))));
  } else {
    pane.replaceChildren(h(doc, 'article', { class: 'card', 'data-tone': 'trust' },
      h(doc, 'div', { class: 'card-head' },
        h(doc, 'div', { class: 'card-top' }, h(doc, 'h2', {}, 'What the guard would say')),
        h(doc, 'p', { class: 'card-sub' }, 'Pick an example or type an account name. The answer appears here.')),
      h(doc, 'div', { class: 'card-body' },
        h(doc, 'ul', { class: 'legend' },
          legendItem(doc, 'ALLOW', 'Preflight has a Safe verdict for exactly this code.'),
          legendItem(doc, 'WARN', 'Preflight has no verdict for this code, or a warning. A person has to approve the payment.'),
          legendItem(doc, 'BLOCK', 'Preflight found a hole in this code, or could not check. The guard refuses, and it also refuses an account with no code.')))));
  }
}

const chipNode = (doc, example) => h(doc, 'button', { type: 'button', class: 'chip-pick', 'data-account': example.accountId, 'data-network': example.network },
  h(doc, 'span', {}, example.accountId), h(doc, 'em', {}, `${label(example.network)}: ${example.caption}`));

/** Wires the section. `env` is `{ fetch, sleep }` (account-check.js reads through swap.js's transport). Never throws: a failed read is a state on the page. */
export function mountAccountCheck(doc = document, { env = { fetch: (...args) => globalThis.fetch(...args), sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }, networks = NETWORKS, registry = REGISTRY } = {}) {
  const form = doc.getElementById('check-form');
  const input = doc.getElementById('check-account');
  const button = doc.getElementById('check-go');
  const pane = doc.getElementById('check-result');
  const chips = doc.getElementById('check-chips');
  if (!form || !input || !button || !pane || !chips) return null;
  const radios = [...doc.querySelectorAll('input[name="check-net"]')];
  const network = () => radios.find((radio) => radio.checked)?.value ?? 'mainnet';
  const narrow = matchMedia('(max-width: 61.99rem)');
  const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let latest = 0;

  const show = (view) => paint(doc, pane, viewModel(view));
  async function check() {
    const mine = ++latest;
    const valid = validateAccountId(input.value);
    if (!valid.ok) { button.disabled = false; show({ phase: 'invalid', input: input.value, reason: valid.reason }); return; }
    const net = network();
    show({ phase: 'loading', accountId: valid.accountId, network: net });
    button.disabled = true;
    if (narrow.matches) pane.scrollIntoView?.({ block: 'start', behavior: calm ? 'auto' : 'smooth' });
    const result = await checkAccount(valid.accountId, net, env, { networks, registry });
    if (mine !== latest) return;
    button.disabled = false;
    show({ phase: 'done', result });
  }

  chips.replaceChildren(...EXAMPLES.map((example) => chipNode(doc, example)));
  chips.addEventListener('click', (event) => {
    const chip = event.target?.closest?.('[data-account]');
    if (!chip) return;
    input.value = chip.getAttribute('data-account');
    for (const radio of radios) radio.checked = radio.value === chip.getAttribute('data-network');
    check();
  });
  form.addEventListener('submit', (event) => { event.preventDefault(); check(); });
  show({ phase: 'idle' });
  button.disabled = false;
  return { check };
}
