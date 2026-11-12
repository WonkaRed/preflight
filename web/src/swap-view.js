// The Swap section's page code. `viewModel` turns the controller's state into plain strings and tones (no DOM, so it is
// tested directly), `paint` writes them into the section's elements, and `mountSwap` wires both to the controller.
// Everything that came from the chain or the recording reaches the page as text (textContent, text nodes), and links are
// built only from a validated transaction hash or account id plus the configured explorer.
import { changedSince } from './code-pin.js';
import { isHash } from './near.js';
import { clean, h, plural } from './report.js';
import { createRob } from './rob.js';
import { createSwap, isAccountId, parseRecorded } from './swap.js';
import { agentScript, mountAgent, RULE_WORDS } from './swap-agent.js';
import { createPreview } from './swap-preview.js';
import { SWAP_CONFIG } from './swap-config.js';

// What each BLOCK says first, in words anyone can read, and the exact technical sentence behind it (shown in the card's fold-out).
// The one rule the demo's two builds differ on (the registry's Safe verdict carries no rule ids).
const DEMO_RULE = 'PF001';
const BUG_PLAIN = {
  PF001: 'This code has a hole: anyone can give themselves a balance and take what other people deposited.',
};
const BUG_LINE = {
  PF001: 'Any account can call the contract\'s callback directly, so anyone can credit themselves a balance without paying and withdraw what others deposited.',
};
// The line beside the swap button, after the live status. Live, it follows what the visitor is looking at: the fixed code they arrived to (the button and the preview say it all),
// the bad code they swapped in, the bad code someone else left behind (the contract is shared), and the fixed code after a swap.
const HINT = {
  loading: '',
  resting: 'The code was just swapped. The demo rests a moment between swaps.',
  recorded: 'Press it to replay a recorded swap of the code behind this address.',
  fixed: '',
  fixedAgain: 'The fixed code is back. Swap the bad code in again and watch Preflight react.',
  bad: 'Same address, new code. The address check cannot tell. Preflight can, because it reads the code.',
  badLeft: 'Someone left this contract on its bad code, so Preflight says BLOCK while the address check still says ALLOW. Swap in the fixed code, then swap the bad one back, to watch it change.',
  other: 'Press it. The code behind this address changes, live.',
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

// What the swap button offers, by the build that is live: the owner's move from there.
const SWAP_LABEL = { patched: 'Swap in the bad code', vulnerable: 'Swap in the fixed code' };

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

/** What the hero's preview needs: the recorded run's bad build to turn the card into, or null when there is none to show. */
function previewOf(state) {
  const bad = state.recorded?.steps.find((step) => step.decision === 'BLOCK');
  return bad ? { hash: state.codeHash, bad: pfOf(bad, bad) } : null;
}
const NO_PF = { tone: 'none', word: '', rules: '', ruleWords: '', line: '', tech: '', tag: { text: '', state: 'none' }, build: '', hash: '' };
/** The Preflight card for a code (`shown`: its build and hash) and the registry verdict for it. */
function pfOf(shown, verdict) {
  const rule = verdict.ruleIds[0];
  const rules = verdict.ruleIds.join(', ');
  const word = verdict.decision;
  return {
    tone: word.toLowerCase(),
    word,
    rules,
    ruleWords: RULE_WORDS[rule] ?? '',
    line: word === 'BLOCK' ? (BUG_PLAIN[rule] ?? 'This code is marked unsafe.')
      : word === 'ALLOW' ? 'This is the fixed code. Preflight says yes.'
        : verdict.registered ? 'This code has a warning on record.' : 'Nobody has vouched for this code, or it changed after it was checked.',
    tech: word === 'BLOCK' ? (BUG_LINE[rule] ?? `The registry marks this exact code unsafe (${rules}).`)
      : word === 'ALLOW' ? 'No known issue fired on this exact code (registry status: Safe).'
        : verdict.registered ? `The registry marks this exact code Warn (${rules}).` : 'The registry has no verdict for this code: unaudited, or changed since its audit.',
    // The safe verdict says which check came back clear, as a green chip, instead of showing the id of a bug that was not found.
    tag: word === 'ALLOW' ? { text: `${DEMO_RULE} check: clear`, state: 'clear' } : { text: rules, state: 'found' },
    build: { vulnerable: 'Vulnerable build', patched: 'Patched build' }[shown.build] ?? 'A build this page does not know',
    hash: shown.codeHash,
  };
}

/** What the page shows for a state at time `now` (epoch ms). `explorerUrl` is where transaction and account links go. */
export function viewModel(state, { now, explorerUrl }) {
  const { mode, address } = state;
  const replay = mode === 'recorded' ? state.recorded.steps[state.replay] : null;
  const shown = replay ?? state;
  const verdict = replay ?? state.verdict;
  const known = mode === 'live' || mode === 'recorded';

  const pf = known && verdict ? pfOf(shown, verdict) : { ...NO_PF, word: mode === 'empty' ? 'No data' : '' };

  const txLink = (hash, text) => (isHash(hash) ? { href: `${explorerUrl}/tx/${hash}`, text } : null);
  // The auditor-free check: no registry, no verdict, only the fingerprint this visitor first saw against the one live now. Live reads only.
  const change = mode === 'live' ? changedSince(state.arrival, state.codeHash) : null;
  const pin = change && { ...change, keys: keyFact(state.keys?.codeHash === state.codeHash ? state.keys.full : null) };

  // The code that ran here before the last swap, when Preflight judged it differently: the contrast, from chain data. Only once the code
  // has changed under this visitor: on arrival the contract reads as what it is now, not as a history.
  const prior = change && verdict && state.before && state.before.verdict.decision !== verdict.decision ? state.before : null;
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

  const swapping = state.tx !== null && ['pending', 'landing'].includes(state.tx.stage);
  const waitMs = state.waitUntil === null ? 0 : state.waitUntil - now;
  const resting = mode !== 'recorded' && !swapping && waitMs > 0;
  const button = mode === 'recorded' ? { label: 'Replay a recorded swap', disabled: false }
    : swapping ? { label: 'Swapping...', disabled: true }
      : resting ? { label: `Ready in ${Math.ceil(waitMs / 1000)} s`, disabled: true }
        : { label: SWAP_LABEL[mode === 'live' ? state.build : mode === 'loading' ? 'patched' : null] ?? 'Swap the code', disabled: mode !== 'live' };
  const liveHint = { patched: change ? HINT.fixedAgain : HINT.fixed, vulnerable: change ? HINT.bad : HINT.badLeft }[state.build] ?? HINT.other;

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
      ? { word: 'ALLOW', note: `This address is on its safe list, so it says yes. Every time${change ? ', even though the code behind it just changed' : ''}.` }
      : { word: 'No data', note: '' },
    pf,
    before,
    pin,
    agent: agentScript({ mode, address, verdict, codeHash: pf.hash, at: now, recorded: state.recorded }),
    loading: mode === 'loading',
    keys: `No admin keys, and its code still ${mode === 'live' && state.flips !== null ? `changed ${plural(state.flips, 'time')}` : 'changes'}.`,
    previewNote: '',
    preview: mode === 'live' && state.build === 'patched' && verdict?.decision === 'ALLOW' ? previewOf(state) : null,
    hint: resting && !change ? HINT.resting : mode === 'live' ? liveHint : HINT[mode] ?? '',
    button,
    tx,
    flips: replay ? (state.replay === 0 ? '' : `Recorded swap ${state.replay} of ${state.recorded.steps.length - 1}`) : mode === 'live' && state.flips !== null ? `Swaps so far: ${state.flips}` : '',
  };
}

const PREVIEW_NOTE = {
  safe: 'Preview. Today both checks say yes.',
  swap: 'Preview. The owner swaps the code: the fingerprint changes.',
  bad: 'Preview. Preflight now says BLOCK. The allowlist still says ALLOW.',
  still: 'Preview. If the owner swaps the code, Preflight turns to BLOCK and the allowlist keeps saying ALLOW. Press the button to try it for real.',
};
/** The model with the preview's stage on the Preflight card (from `createPreview`), or as it is when none is showing. Always labelled. */
export function withPreview(model, stage) {
  const { preview } = model;
  if (!stage || !preview) return model;
  const pf = stage === 'bad' ? preview.bad : stage === 'swap' ? { ...model.pf, hash: preview.bad.hash } : model.pf;
  return { ...model, pf, previewNote: PREVIEW_NOTE[stage] };
}

/** Writes a view model into the section's elements (`els`, by name). `animate`: nudge the verdict when it changes. */
export function paint(doc, els, model, { animate = false } = {}) {
  const changed = els.pfWord.textContent !== model.pf.word || els.pfHash.textContent !== model.pf.hash;
  els.status.textContent = model.status.text;
  els.status.setAttribute('data-tone', model.status.tone);
  els.detail.textContent = model.detail;
  els.source.textContent = model.source;
  for (const el of els.address) {
    el.replaceChildren(model.addressHref ? h(doc, 'a', { href: model.addressHref, target: '_blank', rel: 'noopener noreferrer' }, model.address) : model.address);
  }
  els.cards.setAttribute('data-loading', model.loading ? 'on' : 'off');
  els.trustWord.textContent = model.trust.word;
  els.trustNote.textContent = model.trust.note;
  els.pfCard.setAttribute('data-tone', model.pf.tone);
  els.pfWord.textContent = model.pf.word;
  els.pfRules.textContent = model.pf.rules;
  els.pfRules.setAttribute('title', model.pf.ruleWords);
  els.pfLine.textContent = model.pf.line;
  els.pfTech.textContent = model.pf.tech;
  els.pfTag.textContent = model.pf.tag.text;
  els.pfTag.setAttribute('data-state', model.pf.tag.state);
  els.pfTag.hidden = model.pf.tag.text === '';
  els.pfPreview.textContent = model.previewNote;
  els.pfPreview.hidden = els.pfPreviewPill.hidden = model.previewNote === '';
  els.pfCard.setAttribute('data-preview', model.previewNote === '' ? 'off' : 'on');
  els.keys.textContent = model.keys;
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

// "Rob it": ties to the same verdict word the Preflight card shows for the build that is live right now.
const ROB_NARRATIVE = { block: 'This is the code Preflight said BLOCK to.', allow: 'This is the fixed code. Try it: the contract should refuse.' };
const ROB_PLAIN = {
  done: 'A real transaction just forged a balance nobody paid for.',
  refused: 'The fixed code said no. Only the contract itself may run this step.',
};
const nearAmount = (yocto) => {
  const n = BigInt(yocto ?? 0);
  const whole = n / 10n ** 24n;
  const frac = ((n % 10n ** 24n) * 1000n) / 10n ** 24n;
  return `${whole}.${frac.toString().padStart(3, '0')}`;
};

/** What the "Rob it" panel shows for `rob.getState()`, given the Preflight card's current tone (`pf.tone`) and where links go. */
export function robViewModel(robState, pfTone, explorerUrl) {
  const { ok, canAct, stage, before, after, hash, message } = robState;
  const txLink = isHash(hash) ? { href: `${explorerUrl}/tx/${hash}`, text: 'View the transaction' } : null;
  const busy = stage === 'reading' || stage === 'pending';
  const STATUS = {
    reading: ['none', 'Reading the chain.'],
    pending: ['none', 'Sending.'],
    'cannot-pay': ['warn', 'Out of gas allowance.'],
    failed: ['warn', 'Failed.'],
    unconfirmed: ['warn', 'Not confirmed yet.'],
  };
  const [tone, text] = STATUS[stage] ?? ['none', ''];
  // A finished rob is the page's payoff, so it gets a result block in the verdict cards' own language, not a line of small text.
  const result = {
    done: { tone: 'block', word: 'ROBBED', figure: { from: nearAmount(before), to: nearAmount(after), unit: 'testnet NEAR' }, plain: ROB_PLAIN.done, own: '', link: txLink },
    refused: { tone: 'allow', word: 'REFUSED', figure: null, plain: ROB_PLAIN.refused, own: `The contract's own words: "${message}"`, link: txLink },
  }[stage] ?? null;
  const TX = {
    pending: { text: hash ? 'Signed in your browser and sent. Waiting for the network.' : 'Signing in your browser.', link: txLink },
    'cannot-pay': { text: 'The shared key\'s gas allowance is low right now. It refills automatically; try again in a bit.', link: null },
    failed: { text: message || 'The transaction failed.', link: txLink },
    unconfirmed: { text: `Sent, but not yet confirmed. Check the transaction below; this page keeps reading the chain. ${message}`.trim(), link: txLink },
  };
  return {
    narrative: ok && canAct ? (ROB_NARRATIVE[pfTone] ?? '') : '',
    button: { label: busy ? 'Working...' : 'Rob it', disabled: !ok || !canAct || busy },
    hint: !ok ? '' : !canAct ? 'This needs the live chain above; it is disabled until that is ready.' : stage === 'idle' ? 'One click. One real transaction. No wallet.' : '',
    status: { tone, text },
    tx: TX[stage] ?? null,
    result,
  };
}

/** Writes the "Rob it" panel. `animate`: let a new result arrive with a short scale and fade. */
export function paintRob(doc, els, model, { animate = false } = {}) {
  const { result } = model;
  const arrives = result !== null && (els.robCard.hidden || els.robWord.textContent !== result.word);
  els.robNarrative.textContent = model.narrative;
  els.robButton.textContent = model.button.label;
  els.robButton.disabled = model.button.disabled;
  els.robHint.textContent = model.hint;
  els.robStatus.textContent = model.status.text;
  els.robStatus.setAttribute('data-tone', model.status.tone);
  els.robTx.replaceChildren(...(!model.tx ? [] : !model.tx.link ? [model.tx.text]
    : [model.tx.text, ' ', h(doc, 'a', { href: model.tx.link.href, target: '_blank', rel: 'noopener noreferrer' }, model.tx.link.text)]));
  els.robCard.hidden = result === null;
  if (result) {
    els.robCard.setAttribute('data-tone', result.tone);
    els.robWord.textContent = result.word;
    // Each number is its own unbreakable span, so a narrow screen wraps between them and never inside one.
    els.robFigure.replaceChildren(...(!result.figure ? [] : [
      h(doc, 'span', { class: 'rob-num' }, result.figure.from), h(doc, 'span', { class: 'rob-arrow' }, '\u2192'),
      h(doc, 'span', { class: 'rob-num' }, result.figure.to), h(doc, 'span', { class: 'rob-unit' }, result.figure.unit),
    ]));
    els.robPlain.textContent = result.plain;
    els.robOwn.textContent = result.own;
    els.robLink.replaceChildren(...(result.link ? [h(doc, 'a', { href: result.link.href, target: '_blank', rel: 'noopener noreferrer' }, result.link.text)] : []));
  }
  if (animate && arrives) els.robCard.animate?.([{ opacity: 0, transform: 'scale(0.96)' }, { opacity: 1, transform: 'none' }], { duration: 260, easing: 'cubic-bezier(0.2, 0.8, 0.2, 1)' });
}

export const IDS = {
  status: 'swap-status', detail: 'swap-detail', source: 'swap-source', cards: 'swap-cards', keys: 'swap-keys', trustWord: 'trust-word', trustNote: 'trust-note',
  pfCard: 'swap-pf', pfWord: 'pf-word', pfRules: 'pf-rules', pfLine: 'pf-line', pfTech: 'pf-tech', pfBuild: 'pf-build', pfHash: 'pf-hash', pfTag: 'pf-tag', pfPreview: 'pf-preview', pfPreviewPill: 'pf-preview-pill',
  before: 'swap-before', beforeTitle: 'before-title', beforeWord: 'before-word', beforeRules: 'before-rules', beforeReason: 'before-reason', beforeHash: 'before-hash', beforeTx: 'before-tx',
  pin: 'swap-pin', pinThen: 'pin-then', pinNow: 'pin-now', pinFoldThen: 'pin-fold-then', pinFoldNow: 'pin-fold-now', pinKeys: 'pin-keys',
  button: 'swap-button', hint: 'swap-hint', flips: 'swap-flips', tx: 'swap-tx',
};

export const ROB_IDS = {
  robNarrative: 'rob-narrative', robButton: 'rob-button', robHint: 'rob-hint', robStatus: 'rob-status', robTx: 'rob-tx',
  robCard: 'rob-card', robWord: 'rob-word', robFigure: 'rob-figure', robPlain: 'rob-plain', robOwn: 'rob-own', robLink: 'rob-link',
};

/** Starts the section on the page and returns its controller. Never throws: whatever goes wrong, the section shows a state that says so. */
export async function mountSwap(doc = document, config = SWAP_CONFIG) {
  const els = { ...Object.fromEntries(Object.entries(IDS).map(([name, id]) => [name, doc.getElementById(id)])), address: [...doc.querySelectorAll('[data-address]')] };
  const robEls = Object.fromEntries(Object.entries(ROB_IDS).map(([name, id]) => [name, doc.getElementById(id)]));
  const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let recorded = null;
  try {
    const response = await fetch('swap-recorded.json');
    if (response.ok) recorded = parseRecorded(await response.json());
  } catch { /* no recording: the section says so */ }

  const agent = mountAgent(doc, { calm });
  let swap;
  let rob;
  let watching = false;
  let shown = '';
  let pfTone = 'none';
  let model = null;
  let previewShown = false;
  // The preview paints over the live model on the Preflight card only; the allowlist card, the button and the agent never see it.
  const paintHero = () => {
    const stage = preview.stage();
    paint(doc, els, withPreview(model, stage), { animate: !calm && (stage === null ? !previewShown : stage === 'bad') });
    previewShown = stage !== null;
  };
  const preview = createPreview({ calm, onChange: () => { if (model) paintHero(); } });
  // "Rob it" paints on its own clicks too (signing and sending take a moment); it never polls the chain by itself.
  const renderRob = () => paintRob(doc, robEls, robViewModel(rob.getState(), pfTone, config.explorerUrl), { animate: !calm });
  const render = () => {
    const state = swap.getState();
    model = viewModel(state, { now: Date.now(), explorerUrl: config.explorerUrl });
    preview.sync(model.preview && { hash: model.preview.hash });
    paintHero();
    agent.update(model.agent);
    pfTone = model.pf.tone;
    rob.sync(state.mode === 'live', state.mode === 'live' ? state.codeHash : null);
    renderRob();
    // The visitor asked for a swap: when the verdict it caused is off screen (a phone), bring it up, once, and never on load.
    const verdict = `${model.pf.word}|${model.pf.hash}`;
    if (watching && verdict !== shown) { watching = false; els.pfCard.scrollIntoView?.({ block: 'nearest', behavior: calm ? 'auto' : 'smooth' }); }
    shown = verdict;
  };
  swap = createSwap({ config, recorded, onChange: render });
  rob = createRob({ config, onChange: renderRob });
  render();
  els.button.addEventListener('click', () => { preview.press(); watching = true; Promise.resolve(swap.flip()).finally(() => { watching = false; }); });
  robEls.robButton.addEventListener('click', () => { preview.press(); rob.rob(); });
  // The countdown on the button needs a repaint each second; nothing else changes between polls.
  setInterval(() => { if (swap.getState().waitUntil !== null) render(); }, 500);
  doc.addEventListener('visibilitychange', () => { if (!doc.hidden) swap.wake(); });
  swap.start();
  return swap;
}
