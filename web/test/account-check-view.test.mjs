// "Check a contract you know" on the page (src/account-check-view.js): the words for every state, that everything reaches the
// page as text, and the form's behaviour (a bad name sends nothing, the newest check wins) against a stand-in DOM.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EXAMPLES, NETWORKS } from '../src/account-check.js';
import { mountAccountCheck, paint, reportHref, viewModel } from '../src/account-check-view.js';
import { fakeDocument, walk } from './fake-dom.mjs';

const HASH = '9EUtV11wgCZ4N16xa24ETnn8E78GjeSit1r7gMyQZ6Zi';
const REPORT = 'https://github.com/WonkaRed/preflight/blob/main/demo/report.json';
const PAYLOAD = '<img src=x onerror=alert(1)>.near';
const verdict = (decision, ruleIds = [], registered = true) => ({ decision, ruleIds, registered, auditor: registered ? 'auditor.example.testnet' : null, reportUrl: registered ? REPORT : null });
const checked = (decision, extra = {}) => ({
  state: 'checked', accountId: 'wrap.near', network: 'mainnet', host: 'free.rpc.fastnear.com', codeHash: HASH, keys: 0, publisher: null,
  verdict: verdict(decision.toUpperCase()), guard: { check: decision, decision }, ...extra,
});
const done = (result) => viewModel({ phase: 'done', result });
const textOf = (node) => { const out = []; walk(node, (n) => { if (typeof n.text === 'string') out.push(n.text); }); return out.join(' '); };
const render = (model) => { const doc = fakeDocument(); const pane = doc.createElement('div'); paint(doc, pane, model); return pane; };

test('a checked contract says the guard\'s decision in its word and tone, with the fingerprint, the keys and the verdict', () => {
  const allow = done(checked('allow')).card;
  assert.deepEqual([allow.tone, allow.word, allow.hash], ['allow', 'ALLOW', HASH]);
  assert.match(allow.line, /may pay this contract.*Safe verdict/);
  assert.deepEqual(allow.facts.map((f) => f.label), ['Who can swap this code', 'Preflight verdict for this code', 'Where the verdicts live']);
  assert.match(allow.facts[1].text, /^Safe, published by auditor\.example\.testnet\./);
  assert.deepEqual(allow.facts[1].link, { href: REPORT, text: 'Read the report' });
  assert.equal(allow.addressHref, 'https://nearblocks.io/address/wrap.near');
  assert.equal(allow.explorer.href, 'https://nearblocks.io/address/wrap.near');
  assert.match(allow.sub, /^Mainnet, read just now through free\.rpc\.fastnear\.com$/);

  const none = done(checked('warn', { verdict: verdict('WARN', [], false) })).card;
  assert.deepEqual([none.tone, none.word], ['warn', 'WARN']);
  assert.match(none.line, /ask a person first.*no verdict for exactly this code/);
  assert.match(none.facts[1].text, /^None yet\. Preflight has not looked at this code, or the code changed since it did\.$/);
  assert.equal(none.facts[1].link, null);

  const unsafe = done(checked('block', { verdict: verdict('BLOCK', ['PF001']) })).card;
  assert.deepEqual([unsafe.tone, unsafe.word, unsafe.rules], ['block', 'BLOCK', 'PF001']);
  assert.match(unsafe.line, /refuse to pay.*PF001: anyone can credit themselves a balance/);
  const warned = done(checked('warn', { verdict: verdict('WARN', ['PF010']) })).card;
  assert.match(warned.line, /flagged exactly this code with a warning \(PF010\)/);
});

test('the registry sentence is on mainnet cards only, in the page\'s voice', () => {
  const mainnet = done(checked('warn', { verdict: verdict('WARN', [], false) })).card.facts;
  assert.deepEqual(mainnet[2], { label: 'Where the verdicts live', text: 'Preflight\'s registry is on testnet for now, so this applies the guard\'s rule to the testnet registry\'s verdicts; a guard on mainnet needs a registry there.', link: null });
  assert.doesNotMatch(mainnet[2].text, /[\u2013\u2014"\u2018\u2019\u201c\u201d]| - /);
  const testnet = done(checked('warn', { network: 'testnet', verdict: verdict('WARN', [], false) })).card.facts;
  assert.deepEqual(testnet.map((f) => f.label), ['Who can swap this code', 'Preflight verdict for this code']);
});

test('"Read the report" is a link only for https://github.com/WonkaRed/preflight/ pages', () => {
  assert.equal(reportHref(REPORT), REPORT);
  assert.equal(reportHref('https://github.com/WonkaRed/preflight/'), 'https://github.com/WonkaRed/preflight/');
  const refused = [
    'https://g\u0456thub.com/WonkaRed/preflight/x', // Cyrillic i: a homograph of github.com
    'https://phish.example/',
    'https://phish.example/WonkaRed/preflight/x',
    'https://github.com.phish.example/WonkaRed/preflight/x',
    'https://github.com@phish.example/WonkaRed/preflight/x',
    'https://github.com:8443/WonkaRed/preflight/x',
    'http://github.com/WonkaRed/preflight/x',
    'https://github.com/WonkaRed/preflight', // the repository root without the trailing slash is not a page under it
    'https://github.com/wonkared/preflight/x',
    'https://github.com/WonkaRed/preflight-evil/x',
    'https://github.com/WonkaRed/preflight/../../evil/x',
    'https://github.com/evil/WonkaRed/preflight/x',
    'javascript:alert(1)', 'data:text/html,x', 'ftp://github.com/WonkaRed/preflight/x', '//github.com/WonkaRed/preflight/x', '', 'not a url', null, undefined, 7,
  ];
  for (const url of refused) {
    assert.equal(reportHref(url), null, String(url));
    const fact = done(checked('allow', { verdict: { ...verdict('ALLOW'), reportUrl: url } })).card.facts[1];
    assert.equal(fact.link, null, `no link for ${url}`);
    assert.match(fact.text, /^Safe, published by auditor\.example\.testnet\.$/);
    const hrefs = [];
    walk(render(done(checked('allow', { verdict: { ...verdict('ALLOW'), reportUrl: url } }))), (n) => { if (n.attrs?.href) hrefs.push(n.attrs.href); });
    assert.ok(hrefs.every((href) => href.startsWith('https://nearblocks.io/address/')), `${String(url)}: ${hrefs}`);
  }
});

test('the key line is honest: zero keys is not "never changes", keys can swap at any time, and an unreadable list says so', () => {
  const keys = (n, extra = {}) => done(checked('warn', { keys: n, verdict: verdict('WARN', [], false), ...extra })).card.facts[0].text;
  assert.match(keys(0), /^0 full-access keys: no key can redeploy this code directly\. That does not mean it can never change: a contract can replace its own code through its own logic, or through a DAO vote\.$/);
  assert.match(keys(1), /^1 full-access key\. Whoever holds one can deploy new code here at any time\.$/);
  assert.match(keys(15), /^15 full-access keys\./);
  assert.match(keys(null), /could not be read just now/);
  assert.match(keys(0, { publisher: 'publisher.near' }), /^This account runs a global contract published by publisher\.near, who can replace it at any time\. 0 full-access keys/);
});

test('an account with no contract or no account is named plainly, with no guess about it being safe', () => {
  const base = { accountId: 'alice.near', network: 'mainnet', host: 'free.rpc.fastnear.com' };
  const nocode = done({ ...base, state: 'nocode' }).card;
  assert.deepEqual([nocode.tone, nocode.word, nocode.facts, nocode.hash], ['trust', 'NO CODE', [], undefined]);
  assert.match(nocode.line, /no contract is deployed on it.*would BLOCK a call here/);
  const missing = done({ ...base, state: 'missing' }).card;
  assert.deepEqual([missing.tone, missing.word], ['trust', 'NOT FOUND']);
  assert.match(missing.line, /There is no account called alice\.near on NEAR mainnet\. Check the spelling\.$/);
  assert.match(done({ ...base, accountId: 'alice.testnet', state: 'missing' }).card.line, /looks like a testnet account: switch to Testnet/);
  assert.match(done({ ...base, accountId: 'alice.near', network: 'testnet', state: 'missing' }).card.line, /looks like a mainnet account: switch to Mainnet/);
  const global = done({ ...base, state: 'global', publisher: 'publisher.near', keys: 2 }).card;
  assert.equal(global.word, 'GLOBAL');
  assert.match(global.line, /publisher\.near, chose.*decides nothing/);
});

test('a failed read, a bad name, loading and the resting pane each say what happened and what to do', () => {
  const failed = (what) => done({ state: 'failed', accountId: 'wrap.near', network: 'mainnet', what, detail: 'RPC query request failed: no answer in time', decision: 'block' }).problem;
  assert.equal(failed('account').title, 'Could not read NEAR mainnet just now');
  assert.equal(failed('registry').title, 'Could not read Preflight\'s registry just now');
  assert.match(failed('account').hint, /Press Check this account to try again.*refuses to pay while it cannot check/);
  assert.match(failed('account').items.join(' '), /No verdict was made/);

  const invalid = viewModel({ phase: 'invalid', input: PAYLOAD, reason: 'A NEAR account name uses only lowercase letters.' }).problem;
  assert.equal(invalid.title, 'That is not a NEAR account name');
  assert.deepEqual(invalid.items, ['A NEAR account name uses only lowercase letters.', `You typed: ${PAYLOAD}`]);
  assert.match(invalid.hint, /Nothing was sent anywhere/);
  assert.equal(viewModel({ phase: 'invalid', input: '  ', reason: 'Type a NEAR account name first.' }).problem.items.length, 1, 'an empty box is not quoted back');
  assert.match(viewModel({ phase: 'invalid', input: 'x'.repeat(100), reason: 'r' }).problem.items[1], /^You typed: x{80}\.\.\.$/);

  assert.match(viewModel({ phase: 'loading', accountId: 'wrap.near', network: 'testnet' }).line, /^Asking NEAR testnet what code is deployed at wrap\.near\.$/);
  assert.equal(viewModel({ phase: 'idle' }).kind, 'idle');
});

test('everything reaches the page as text: a hostile name, hostile chain text and a hostile report link', () => {
  // The name typed
  const pane = render(viewModel({ phase: 'invalid', input: PAYLOAD, reason: 'no' }));
  let tags = [];
  walk(pane, (n) => n.tag && tags.push(n.tag));
  assert.deepEqual([...new Set(tags)].sort(), ['div', 'h2', 'li', 'p', 'section', 'ul'], 'no element came from the text');
  assert.ok(textOf(pane).includes(PAYLOAD), 'it is shown, as text');
  // Text from the chain (account-check.js refuses a verdict like this, so only a bug could hand it over): still no link, no markup
  const html = '<b onclick=alert(1)>';
  const hostile = { decision: 'ALLOW', ruleIds: [], registered: true, auditor: html, reportUrl: 'javascript:alert(1)' };
  for (const state of [checked('allow', { verdict: hostile }), { state: 'failed', accountId: 'a.near', network: 'mainnet', what: 'account', detail: html, decision: 'block' }]) {
    const out = render(done(state));
    const hrefs = [];
    walk(out, (n) => { if (n.attrs?.href) hrefs.push(n.attrs.href); if (n.tag === 'script' || n.tag === 'img') assert.fail(n.tag); for (const k of Object.keys(n.attrs ?? {})) assert.ok(!/^on/i.test(k), k); });
    if (state.state === 'checked') assert.ok(hrefs.length > 0);
    for (const href of hrefs) assert.match(href, /^https:\/\/nearblocks\.io\/address\/(wrap|a)\.near$/);
  }
  assert.ok(textOf(render(done({ state: 'failed', accountId: 'a.near', network: 'mainnet', what: 'account', detail: html, decision: 'block' }))).includes(html));
});

test('the resting pane explains the three answers; the checking pane is a status; a card is one article', () => {
  const rest = render({ kind: 'idle' });
  assert.match(textOf(rest), /ALLOW.*WARN.*BLOCK/);
  assert.equal(rest.attrs['aria-busy'], 'false');
  assert.equal(render(viewModel({ phase: 'loading', accountId: 'a.near', network: 'mainnet' })).attrs['aria-busy'], 'true');
  const pane = render(done(checked('allow')));
  assert.equal(pane.kids.length, 1);
  assert.equal(pane.kids[0].tag, 'article');
  assert.equal(pane.kids[0].attrs['data-tone'], 'allow');
  const copy = [];
  walk(pane, (n) => { if (n.attrs?.['data-copy'] !== undefined) copy.push(n); });
  assert.deepEqual(copy.map((n) => [n.attrs.title, textOf(n)]), [[HASH, HASH]], 'the fingerprint copies itself, whole');
});

// ---- the form ------------------------------------------------------------------------------------------------------

/** A stand-in for the section's elements: just enough DOM for the form to be driven by events. */
function page() {
  const doc = fakeDocument();
  const baseCreate = doc.createElement;
  const make = (tag, props = {}) => {
    const el = baseCreate(tag);
    const listeners = {};
    Object.assign(el, props, {
      listeners,
      addEventListener(type, fn) { (listeners[type] ??= []).push(fn); },
      getAttribute(name) { return this.attrs[name] ?? null; },
      closest(selector) { return selector === '[data-account]' && this.attrs['data-account'] !== undefined ? this : null; },
      scrollIntoView() {},
    });
    return el;
  };
  doc.createElement = make;
  const els = {
    'check-form': make('form'), 'check-account': make('input', { value: '' }), 'check-go': make('button', { disabled: true }),
    'check-result': make('div'), 'check-chips': make('div'),
  };
  const radios = [make('input', { value: 'mainnet', checked: true }), make('input', { value: 'testnet', checked: false })];
  Object.assign(doc, { getElementById: (id) => els[id] ?? null, querySelectorAll: () => radios });
  const submit = () => { let prevented = false; els['check-form'].listeners.submit.forEach((fn) => fn({ preventDefault: () => { prevented = true; } })); return prevented; };
  const click = (chip) => els['check-chips'].listeners.click.forEach((fn) => fn({ target: chip }));
  return { doc, els, radios, submit, click, result: () => els['check-result'] };
}
const pending = () => { let release; const gate = new Promise((resolve) => { release = resolve; }); return { gate, release }; };
globalThis.matchMedia = () => ({ matches: false });

test('a bad name sends no request and shows the reason as text; the button stays usable', async () => {
  const { doc, els, submit, result } = page();
  const requests = [];
  mountAccountCheck(doc, { env: { fetch: async (...args) => { requests.push(args); throw new Error('no request expected'); }, sleep: async () => {} } });
  assert.equal(els['check-go'].disabled, false, 'enabled once the page script runs');
  assert.match(textOf(result()), /What the guard would say/, 'rests on the explanation');
  els['check-account'].value = PAYLOAD;
  assert.equal(submit(), true, 'the form never navigates');
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(requests, []);
  assert.ok(textOf(result()).includes('That is not a NEAR account name') && textOf(result()).includes(PAYLOAD));
  assert.equal(els['check-go'].disabled, false);
});

test('an example fills the name, picks its network and runs the check; while it runs the button is off; the newest check owns the pane', async () => {
  const { doc, els, radios, click, result } = page();
  const first = pending();
  const seen = [];
  const answer = (hash) => ({ ok: true, status: 200, json: async () => ({ jsonrpc: '2.0', id: 'x', result: { code_hash: hash, amount: '1' } }) });
  const env = {
    sleep: async () => {},
    async fetch(url, init) {
      const { params } = JSON.parse(init.body);
      seen.push([new URL(url).hostname, params.request_type, params.account_id]);
      if (params.account_id === 'wrap.near' && params.request_type === 'view_account') { await first.gate; return answer('11111111111111111111111111111111'); }
      if (params.request_type === 'view_account') return answer('11111111111111111111111111111111');
      throw new Error(`unexpected ${JSON.stringify(params)}`);
    },
  };
  mountAccountCheck(doc, { env });
  const chips = els['check-chips'].kids;
  assert.deepEqual(chips.map((c) => c.attrs['data-account']), EXAMPLES.map((e) => e.accountId));
  assert.ok(chips.every((c) => c.kids.length === 2), 'name and caption');

  click(chips[0]); // wrap.near on mainnet, held up
  assert.equal(els['check-account'].value, 'wrap.near');
  assert.equal(radios[0].checked, true);
  assert.equal(els['check-go'].disabled, true);
  assert.match(textOf(result()), /CHECKING/);

  els['check-go'].disabled = false; // a person can still pick another example while one is running
  click(chips[chips.length - 1]); // the chameleon, on testnet
  assert.equal(radios[1].checked, true);
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(textOf(result()), /NO CODE/);
  first.release();
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(textOf(result()).includes('chameleon.preflight-guard.testnet'), 'the older check did not overwrite the newer one');
  assert.equal(els['check-go'].disabled, false);
  assert.ok(seen.some(([host]) => NETWORKS.mainnet.rpcUrls.some((u) => u.endsWith(host))) && seen.some(([host]) => NETWORKS.testnet.rpcUrls.some((u) => u.endsWith(host))));
});
