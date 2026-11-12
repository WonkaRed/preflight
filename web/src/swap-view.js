// The Swap section's page code. `viewModel` turns the controller's state into plain strings and tones (no DOM, so it is
// tested directly), `paint` writes them into the section's elements, and `mountSwap` wires both to the controller.
// Everything that came from the chain or the recording reaches the page as text (textContent, text nodes), and links are
// built only from a validated transaction hash or account id plus the configured explorer.
import { changedSince } from './code-pin.js';
import { isHash } from './near.js';
import { clean, h } from './report.js';
import { createSwap, isAccountId, parseRecorded } from './swap.js';
import { agentScript, mountAgent, RULE_WORDS } from './swap-agent.js';
import { SWAP_CONFIG } from './swap-config.js';

// What each BLOCK says first, in words anyone can read, and the exact technical sentence behind it (shown in the card's fold-out).
const BUG_PLAIN = {
  PF001: 'This code has a hole: anyone can give themselves a balance and take what other people deposited.',
};
const BUG_LINE = {
  PF001: 'Any account can call the contract\'s callback directly, so anyone can credit themselves a balance without paying and withdraw what others deposited.',
};
const HINT = {
  loading: 'Press it. The code behind this address changes, live.',
  live: 'Press it. The code behind this address changes, live.',
  recorded: 'Press it to replay a recorded swap of the code behind this address.',
};

// How long ago, in the words a visitor would use. Whole units, rounded down; under a minute is "a moment".
const since = (ms) => {
  const minutes = Math.floor(Math.max(ms, 0) / 60_000);
  const [n, unit] = minutes < 1 ? [0, ''] : minutes < 60 ? [minutes, 'minute'] : minutes < 1440 ? [Math.floor(minutes / 60), 'hour'] : [Math.floor(minutes / 1440), 'day'];
  return n === 0 ? 'a moment ago' : `${n} ${unit}${n === 1 ? '' : 's'} ago`;
};

// What the account's key list says, as a sentence for the fold under the changed-code line. `full` is a count, or null when it could not be read.
const keyFact = (full) => (full === null ? 'The account\'s key list could not be read just now.'
  : full === 0 ? 'Read from the chain just now: this account has no full-access key, and its code still changes, through one of its own methods. That is exactly why Preflight pins the fingerprint instead of trusting keys.'
    : `Read from the chain just now: this account holds ${full} full-access key${full === 1 ? '' : 's'}, and each can deploy new code to it at any time. Preflight pins the fingerprint, so it does not depend on who holds a key.`);

const when = (state) => state.recorded?.recordedAt ?? '';

const STATUS = {
  loading: () => 'Reading the chain.',
  live: (state) => (state.reconnecting ? 'Live on NEAR testnet. Reconnecting; what you see is from the last read.' : 'Live on NEAR testnet. Every swap is a real transaction.'),
  recorded: (state) => ({
    'rpc-down': `Recorded on ${when(state)}, RPC unreachable. Nothing below is live.`,
    'cannot-pay': `Recorded on ${when(state)}. The demo key can no longer pay for swaps, so the button replays the recording. Nothing below is live.`,
    unconfigured: `Recorded on ${when(state)}. No live contract is set up in this copy of the page. Nothing below is live.`,
  })[state.reason],
  empty: (state) => (state.reason === 'rpc-down'
    ? 'The RPC is unreachable and no recording is bundled with this page.'
    : 'No live contract is set up in this copy of the page, and no recording is bundled.'),
};

/** What the page shows for a state at time `now` (epoch ms). `explorerUrl` is where transaction and account links go. */
export function viewModel(state, { now, explorerUrl }) {
  const { mode, address } = state;
  const replay = mode === 'recorded' ? state.recorded.steps[state.replay] : null;
  const shown = replay ?? state;
  const verdict = replay ?? state.verdict;
  const known = mode === 'live' || mode === 'recorded';

  const pf = { tone: 'none', word: '...', rules: '', ruleWords: '', line: '', tech: '', build: '', hash: '' };
  if (known && verdict) {
    const rule = verdict.ruleIds[0];
    pf.tone = verdict.decision.toLowerCase();
    pf.word = verdict.decision;
    pf.rules = verdict.ruleIds.join(', ');
    pf.ruleWords = RULE_WORDS[rule] ?? '';
    pf.line = verdict.decision === 'BLOCK' ? (BUG_PLAIN[rule] ?? 'This code is marked unsafe.')
      : verdict.decision === 'ALLOW' ? 'This is the fixed code. Preflight says yes.'
        : verdict.registered ? 'This code has a warning on record.' : 'Nobody has vouched for this code, or it changed after it was checked.';
    pf.tech = verdict.decision === 'BLOCK'
      ? (BUG_LINE[rule] ?? `The registry marks this exact code unsafe (${pf.rules}).`)
      : verdict.decision === 'ALLOW' ? 'The registry holds a Safe verdict for this exact code.'
        : verdict.registered ? `The registry marks this exact code Warn (${pf.rules}).` : 'The registry has no verdict for this code: unaudited, or changed since its audit.';
    pf.build = { vulnerable: 'Vulnerable build', patched: 'Patched build' }[shown.build] ?? 'A build this page does not know';
    pf.hash = shown.codeHash;
  } else if (mode === 'empty') {
    pf.word = 'No data';
  }

  const txLink = (hash, text) => (isHash(hash) ? { href: `${explorerUrl}/tx/${hash}`, text } : null);
  // The code that ran here before the last swap, when Preflight judged it differently: the contrast, shown only from chain data.
  const prior = mode === 'live' && verdict && state.before && state.before.verdict.decision !== verdict.decision ? state.before : null;
  const priorRule = prior?.verdict.ruleIds[0];
  const before = prior && {
    title: `Until ${since(now - prior.swappedAt)}, this same address ran different code.`,
    word: prior.verdict.decision,
    rules: prior.verdict.ruleIds.join(', '),
    tone: pf.tone === 'none' ? 'none' : prior.verdict.decision.toLowerCase(),
    reason: prior.verdict.decision === 'BLOCK' && RULE_WORDS[priorRule] ? `That code had a hole: ${RULE_WORDS[priorRule]}.` : '',
    hash: prior.codeHash,
    tx: txLink(prior.txHash, 'The swap transaction'),
  };

  // The auditor-free check: no registry, no verdict, only the fingerprint this visitor first saw against the one live now. Live reads only.
  const change = mode === 'live' ? changedSince(state.arrival, state.codeHash) : null;
  const pin = change && { ...change, keys: keyFact(state.keys?.codeHash === state.codeHash ? state.keys.full : null) };

  const swapping = state.tx !== null && ['pending', 'landing'].includes(state.tx.stage);
  const waitMs = state.waitUntil === null ? 0 : state.waitUntil - now;
  const button = mode === 'recorded' ? { label: 'Replay a recorded swap', disabled: false }
    : swapping ? { label: 'Swapping...', disabled: true }
      : waitMs > 0 ? { label: `Swap again in ${Math.ceil(waitMs / 1000)} s`, disabled: true }
        : { label: before ? 'Swap it back and watch' : 'Swap the code', disabled: mode !== 'live' };

  let tx = null;
  if (replay) tx = replay.txHash ? { text: 'Recorded transaction.', link: txLink(replay.txHash, 'View it on the explorer') } : { text: 'The recording starts here. Each click replays one swap.', link: null };
  else if (state.tx) {
    const { stage, hash } = state.tx;
    const message = clean(state.tx.message);
    tx = {
      pending: { text: hash ? 'Signed in your browser and sent. Waiting for the network.' : 'Signing in your browser.', link: txLink(hash, 'View the transaction') },
      landing: { text: 'The network accepted it. Waiting for the new code to deploy.', link: txLink(hash, 'View the transaction') },
      done: { text: 'Swapped.', link: txLink(hash, 'View the transaction') },
      unseen: { text: 'The transaction succeeded but the chain does not show the new code yet. Still reading.', link: txLink(hash, 'View the transaction') },
      failed: { text: message || 'The swap failed.', link: txLink(hash, 'View the transaction') },
      unconfirmed: { text: `Sent, but the RPC did not confirm it. Check the transaction; the page keeps reading the chain. ${message}`.trim(), link: txLink(hash, 'View the transaction') },
    }[stage];
  }

  return {
    status: { tone: mode, text: STATUS[mode](state) },
    detail: state.reason === 'unconfigured' ? state.detail : '',
    source: mode === 'live' && state.endpoint ? `Via ${state.endpoint}.` : '',
    address: address ?? 'no address yet',
    addressHref: address && isAccountId(address) ? `${explorerUrl}/account/${address}` : null,
    trust: address
      ? { word: 'ALLOW', note: `This address is on its safe list, so it says yes. Every time${before ? ', even for the code before' : ''}.` }
      : { word: 'No data', note: '' },
    pf,
    before,
    pin,
    agent: agentScript({ mode, address, verdict, codeHash: pf.hash, at: now, step: replay ? state.replay : 0, before: prior }),
    hint: HINT[mode] ?? '',
    button,
    tx,
    flips: replay ? (state.replay === 0 ? '' : `Recorded swap ${state.replay} of ${state.recorded.steps.length - 1}`) : mode === 'live' && state.flips !== null ? `Swaps so far: ${state.flips}` : '',
  };
}

/** Writes a view model into the section's elements (`els`, by name). `animate`: nudge the verdict when it changes. */
export function paint(doc, els, model, { animate = false } = {}) {
  const changed = els.pfWord.textContent !== model.pf.word || els.pfHash.textContent !== model.pf.hash;
  els.status.textContent = model.status.text;
  els.status.setAttribute('data-tone', model.status.tone);
  els.detail.textContent = model.detail;
  els.source.textContent = model.source;
  els.address.replaceChildren(model.addressHref
    ? h(doc, 'a', { href: model.addressHref, target: '_blank', rel: 'noopener noreferrer' }, model.address)
    : model.address);
  els.trustWord.textContent = model.trust.word;
  els.trustNote.textContent = model.trust.note;
  els.pfCard.setAttribute('data-tone', model.pf.tone);
  els.pfWord.textContent = model.pf.word;
  els.pfRules.textContent = model.pf.rules;
  els.pfRules.setAttribute('title', model.pf.ruleWords);
  els.pfLine.textContent = model.pf.line;
  els.pfTech.textContent = model.pf.tech;
  els.pfBuild.textContent = model.pf.build;
  els.pfHash.textContent = model.pf.hash;
  els.pfHash.setAttribute('title', model.pf.hash);
  els.before.hidden = model.before === null;
  if (model.before) {
    els.beforeTitle.textContent = model.before.title;
    els.beforeWord.textContent = model.before.word;
    els.beforeWord.setAttribute('data-tone', model.before.tone);
    els.beforeRules.textContent = model.before.rules;
    els.beforeReason.textContent = model.before.reason;
    els.beforeHash.textContent = model.before.hash;
    els.beforeHash.setAttribute('title', model.before.hash);
    els.beforeTx.replaceChildren(...(model.before.tx ? [h(doc, 'a', { href: model.before.tx.href, target: '_blank', rel: 'noopener noreferrer' }, model.before.tx.text)] : []));
  }
  els.pin.hidden = model.pin === null;
  if (model.pin) {
    for (const [name, hash] of [['pinThen', model.pin.then], ['pinNow', model.pin.now], ['pinFoldThen', model.pin.then], ['pinFoldNow', model.pin.now]]) {
      els[name].textContent = hash;
      els[name].setAttribute('title', hash);
    }
    els.pinKeys.textContent = model.pin.keys;
  }
  els.button.textContent = model.button.label;
  els.button.disabled = model.button.disabled;
  els.hint.textContent = model.hint;
  els.flips.textContent = model.flips;
  els.tx.replaceChildren(...(!model.tx ? [] : !model.tx.link ? [model.tx.text]
    : [model.tx.text, ' ', h(doc, 'a', { href: model.tx.link.href, target: '_blank', rel: 'noopener noreferrer' }, model.tx.link.text)]));
  // The swap is the page's event: the Preflight card turns over to its new verdict and the hash it read slides in; the allowlist card is never touched.
  if (animate && changed) {
    els.pfCard.animate?.([{ transform: 'perspective(900px) rotateX(-80deg)', opacity: 0.2 }, { transform: 'perspective(900px) rotateX(8deg)', opacity: 1, offset: 0.7 }, { transform: 'none', opacity: 1 }], { duration: 650, easing: 'cubic-bezier(0.2, 0.8, 0.2, 1)' });
    els.pfHash.animate?.([{ opacity: 0, transform: 'translateY(0.5em)' }, { opacity: 1, transform: 'none' }], { duration: 700, delay: 250, easing: 'ease-out', fill: 'backwards' });
  }
}

export const IDS = {
  status: 'swap-status', detail: 'swap-detail', source: 'swap-source', address: 'swap-address', trustWord: 'trust-word', trustNote: 'trust-note',
  pfCard: 'swap-pf', pfWord: 'pf-word', pfRules: 'pf-rules', pfLine: 'pf-line', pfTech: 'pf-tech', pfBuild: 'pf-build', pfHash: 'pf-hash',
  before: 'swap-before', beforeTitle: 'before-title', beforeWord: 'before-word', beforeRules: 'before-rules', beforeReason: 'before-reason', beforeHash: 'before-hash', beforeTx: 'before-tx',
  pin: 'swap-pin', pinThen: 'pin-then', pinNow: 'pin-now', pinFoldThen: 'pin-fold-then', pinFoldNow: 'pin-fold-now', pinKeys: 'pin-keys',
  button: 'swap-button', hint: 'swap-hint', flips: 'swap-flips', tx: 'swap-tx',
};

/** Starts the section on the page and returns its controller. Never throws: whatever goes wrong, the section shows a state that says so. */
export async function mountSwap(doc = document, config = SWAP_CONFIG) {
  const els = Object.fromEntries(Object.entries(IDS).map(([name, id]) => [name, doc.getElementById(id)]));
  const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let recorded = null;
  try {
    const response = await fetch('swap-recorded.json');
    if (response.ok) recorded = parseRecorded(await response.json());
  } catch { /* no recording: the section says so */ }

  const agent = mountAgent(doc, { calm });
  let swap;
  let watching = false;
  let shown = '';
  const render = () => {
    const state = swap.getState();
    const model = viewModel(state, { now: Date.now(), explorerUrl: config.explorerUrl });
    paint(doc, els, model, { animate: !calm });
    agent.update(model.agent);
    // The visitor asked for a swap: when the verdict it caused is off screen (a phone), bring it up, once, and never on load.
    const verdict = `${model.pf.word}|${model.pf.hash}`;
    if (watching && verdict !== shown) { watching = false; els.pfCard.scrollIntoView?.({ block: 'nearest', behavior: calm ? 'auto' : 'smooth' }); }
    shown = verdict;
  };
  swap = createSwap({ config, recorded, onChange: render });
  render();
  els.button.addEventListener('click', () => { watching = true; Promise.resolve(swap.flip()).finally(() => { watching = false; }); });
  // The countdown on the button needs a repaint each second; nothing else changes between polls.
  setInterval(() => { if (swap.getState().waitUntil !== null) render(); }, 500);
  doc.addEventListener('visibilitychange', () => { if (!doc.hidden) swap.wake(); });
  swap.start();
  return swap;
}
