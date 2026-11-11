// The Swap section's page code. `viewModel` turns the controller's state into plain strings and tones (no DOM, so it is
// tested directly), `paint` writes them into the section's elements, and `mountSwap` wires both to the controller.
// Everything that came from the chain or the recording reaches the page as text (textContent, text nodes), and links are
// built only from a validated transaction hash or account id plus the configured explorer.
import { isHash } from './near.js';
import { clean, h } from './report.js';
import { createSwap, isAccountId, parseRecorded } from './swap.js';
import { SWAP_CONFIG } from './swap-config.js';

const BUG_LINE = {
  PF001: 'Any account can call the contract\'s callback directly, so anyone can mark an order released without paying for it.',
};

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

  const pf = { tone: 'none', word: '...', rules: '', line: '', build: '', hash: '' };
  if (known && verdict) {
    const rule = verdict.ruleIds[0];
    pf.tone = verdict.decision.toLowerCase();
    pf.word = verdict.decision;
    pf.rules = verdict.ruleIds.join(', ');
    pf.line = verdict.decision === 'BLOCK'
      ? (BUG_LINE[rule] ?? `The registry marks this exact code unsafe (${pf.rules}).`)
      : verdict.decision === 'ALLOW' ? 'The registry holds a Safe verdict for this exact code.'
        : verdict.registered ? `The registry marks this exact code Warn (${pf.rules}).` : 'The registry has no verdict for this code: unaudited, or changed since its audit.';
    pf.build = { vulnerable: 'Vulnerable build', patched: 'Patched build' }[shown.build] ?? 'A build this page does not know';
    pf.hash = shown.codeHash;
  } else if (mode === 'empty') {
    pf.word = 'No data';
  }

  const swapping = state.tx !== null && ['pending', 'landing'].includes(state.tx.stage);
  const waitMs = state.waitUntil === null ? 0 : state.waitUntil - now;
  const button = mode === 'recorded' ? { label: 'Replay a recorded swap', disabled: false }
    : swapping ? { label: 'Swapping...', disabled: true }
      : waitMs > 0 ? { label: `Swap again in ${Math.ceil(waitMs / 1000)} s`, disabled: true }
        : { label: 'Swap the code', disabled: mode !== 'live' };

  const txLink = (hash, text) => (isHash(hash) ? { href: `${explorerUrl}/tx/${hash}`, text } : null);
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
      ? { word: 'ALLOW', note: `${address} is on the allowlist, so it passes.` }
      : { word: 'No data', note: '' },
    pf,
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
  els.pfLine.textContent = model.pf.line;
  els.pfBuild.textContent = model.pf.build;
  els.pfHash.textContent = model.pf.hash;
  els.button.textContent = model.button.label;
  els.button.disabled = model.button.disabled;
  els.flips.textContent = model.flips;
  els.tx.replaceChildren(...(!model.tx ? [] : !model.tx.link ? [model.tx.text]
    : [model.tx.text, ' ', h(doc, 'a', { href: model.tx.link.href, target: '_blank', rel: 'noopener noreferrer' }, model.tx.link.text)]));
  if (animate && changed) els.pfCard.animate?.([{ transform: 'scale(0.985)', opacity: 0.55 }, { transform: 'none', opacity: 1 }], { duration: 380, easing: 'ease-out' });
}

const IDS = {
  status: 'swap-status', detail: 'swap-detail', source: 'swap-source', address: 'swap-address', trustWord: 'trust-word', trustNote: 'trust-note',
  pfCard: 'swap-pf', pfWord: 'pf-word', pfRules: 'pf-rules', pfLine: 'pf-line', pfBuild: 'pf-build', pfHash: 'pf-hash',
  button: 'swap-button', flips: 'swap-flips', tx: 'swap-tx',
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

  let swap;
  const render = () => paint(doc, els, viewModel(swap.getState(), { now: Date.now(), explorerUrl: config.explorerUrl }), { animate: !calm });
  swap = createSwap({ config, recorded, onChange: render });
  render();
  els.button.addEventListener('click', () => swap.flip());
  // The countdown on the button needs a repaint each second; nothing else changes between polls.
  setInterval(() => { if (swap.getState().waitUntil !== null) render(); }, 500);
  doc.addEventListener('visibilitychange', () => { if (!doc.hidden) swap.wake(); });
  swap.start();
  return swap;
}
