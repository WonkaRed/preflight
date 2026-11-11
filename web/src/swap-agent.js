// The Swap's agent panel: a scripted agent that obeys an injected web page and tries to pay the chameleon, and what the
// guard does about it. `agentScript` turns what the Swap already read (the code hash and the registry verdict) into the
// panel's text, with no DOM and no request of its own, so it is tested directly. `mountAgent` plays it: one row at a time,
// again whenever the verdict changes. No model runs here and nothing is signed or sent; the decision it shows comes from
// the same registry verdict the Preflight card shows, in the log line shape of guard/src/log.ts.
import { guardEntry, STATUS_OF } from './swap.js';

/** The call the injected page asks for: the chameleon's payable `deposit` (demo/swap/chameleon), with 0.5 NEAR attached. */
export const CALL = { method: 'deposit', deposit: '500000000000000000000000', label: '0.5 NEAR' };

const OUTCOME = {
  BLOCK: { tone: 'block', word: 'REFUSED', line: 'The guard refused the call before signing. Nothing was signed or sent.' },
  WARN: { tone: 'warn', word: 'DECLINED', line: 'The guard asks a human before it signs a Warn. Nobody is here, so the call is declined. Nothing was signed or sent.' },
  ALLOW: { tone: 'allow', word: 'ALLOWED', line: 'Guard allows; the call would be signed (not sent in this demo). This exact code holds a Safe verdict: the vault credits the deposit to the agent, less its 1% fee, and the agent can withdraw it.' },
};
/** What the verdict says is wrong with the code, in the vault's terms (the chameleon is a deposit vault). */
const HARM = {
  PF001: 'On this build anyone can credit themselves a balance without paying and withdraw what the agent deposits (PF001).',
};
const harm = (verdict) => HARM[verdict.ruleIds.find((rule) => HARM[rule])] ?? `The registry marks this exact code Unsafe${verdict.ruleIds.length ? ` (${verdict.ruleIds.join(', ')})` : ''}.`;
const NOTE = {
  live: 'Composed here from the live reads above, with the guard\'s decision-log fields.',
  recorded: 'Composed from the recorded verdict, not a live check, with the guard\'s decision-log fields.',
};

const verdictText = (verdict) => (verdict.registered
  ? `${STATUS_OF[verdict.decision]}${verdict.ruleIds.length ? ` (${verdict.ruleIds.join(', ')})` : ''}`
  : 'none: unaudited code, or code changed since its audit');

/**
 * What the panel shows. `show` is false when there is no address to name (the section hides). `key` is null until a verdict
 * is known; the panel plays again when it changes. `at` (epoch ms) stamps the log line only for a live check.
 */
export function agentScript({ mode, address, verdict, codeHash, at, step = 0 }) {
  if (!address) return { show: false, key: null };
  const call = `${address}.${CALL.method} with ${CALL.label}`;
  if (!['live', 'recorded'].includes(mode) || !verdict || !codeHash) return { show: true, key: null, address, call };
  const entry = guardEntry({ contract: address, method: CALL.method, deposit: CALL.deposit, codeHash, verdict, at: mode === 'live' ? at : null });
  return {
    show: true,
    key: `${mode}|${address}|${codeHash}|${verdict.decision}|${step}`,
    address,
    call,
    codeHash,
    verdict: verdictText(verdict),
    outcome: verdict.decision === 'BLOCK' ? { ...OUTCOME.BLOCK, line: `${OUTCOME.BLOCK.line} ${harm(verdict)}` } : OUTCOME[verdict.decision],
    log: JSON.stringify(entry, null, 2),
    note: NOTE[mode],
  };
}

/**
 * Milliseconds after the start at which each row appears: the agent's side (task, page, call) needs no chain data and starts
 * at once; the check and the outcome follow it, and wait for the verdict if it has not been read yet.
 */
export const ROW_DELAYS = [0, 600, 1500, 2500, 3600];
const BEAT_MS = 400;
const ROWS = ['task', 'page', 'call', 'check', 'out'];
const AGENT_ROWS = 3;
export const AGENT_IDS = {
  section: 'swap-agent', replay: 'agent-replay', inject: 'agent-inject', call: 'agent-call', hash: 'agent-hash', verdict: 'agent-verdict',
  out: 'agent-out', word: 'agent-word', line: 'agent-line', log: 'agent-log', note: 'agent-note',
  ...Object.fromEntries(ROWS.map((row) => [`row-${row}`, `agent-row-${row}`])),
};

/**
 * Wires the panel's elements. `calm`: no staging, the final state at once. `schedule(fn, ms)` returns a function that cancels
 * it; `now()` is the clock the staging is measured on.
 */
export function mountAgent(doc, { calm = false, now = () => Date.now(), schedule = (fn, ms) => { const id = setTimeout(fn, ms); return () => clearTimeout(id); } } = {}) {
  const els = Object.fromEntries(Object.entries(AGENT_IDS).map(([name, id]) => [name, doc.getElementById(id)]));
  const rows = ROWS.map((row) => els[`row-${row}`]);
  const cancels = { agent: [], verdict: [] };
  let started = null; // the address whose agent rows are staged, and when that began
  let startedAt = 0;
  let playing = null; // the key of the verdict rows on screen
  let last = null;

  const setRow = (i, on) => rows[i].setAttribute('data-state', on ? 'on' : 'off');
  const stop = (which) => { for (const name of which) cancels[name].splice(0).forEach((cancel) => cancel()); };
  const reveal = (i, delay, bucket) => (calm || delay <= 0 ? setRow(i, true) : cancels[bucket].push(schedule(() => setRow(i, true), delay)));

  function startAgent(script) {
    stop(['agent', 'verdict']);
    rows.forEach((_, i) => setRow(i, false));
    started = script.address;
    startedAt = now();
    els.inject.textContent = script.address;
    els.call.textContent = script.call;
    for (let i = 0; i < AGENT_ROWS; i++) reveal(i, ROW_DELAYS[i], 'agent');
  }

  function playVerdict(script) {
    // Not yet read: the rows stay hidden. Read already, or read late: keep the pace the script has, but never skip the beat.
    stop(['verdict']);
    for (let i = AGENT_ROWS; i < rows.length; i++) setRow(i, false);
    if (script.key === null) return;
    els.hash.textContent = script.codeHash;
    els.verdict.textContent = script.verdict;
    els.out.setAttribute('data-tone', script.outcome.tone);
    els.word.textContent = script.outcome.word;
    els.line.textContent = script.outcome.line;
    els.log.textContent = script.log;
    els.note.textContent = script.note;
    const first = Math.max(ROW_DELAYS[AGENT_ROWS] - (now() - startedAt), BEAT_MS);
    reveal(AGENT_ROWS, first, 'verdict');
    reveal(AGENT_ROWS + 1, first + ROW_DELAYS[AGENT_ROWS + 1] - ROW_DELAYS[AGENT_ROWS], 'verdict');
  }

  const api = {
    /** Shows `script` (from `agentScript`). The agent's rows play once per address; the check and outcome play again whenever the script's key changes. */
    update(script) {
      els.section.hidden = !script.show;
      if (!script.show) { stop(['agent', 'verdict']); started = null; playing = null; last = null; return; }
      last = script;
      if (started !== script.address) { startAgent(script); playing = undefined; }
      if (script.key === playing) return;
      playing = script.key;
      playVerdict(script);
    },
    /** Plays everything again from the first row. */
    replay() {
      if (!last) return;
      startAgent(last);
      playVerdict(last);
    },
  };
  els.replay.addEventListener('click', api.replay);
  return api;
}
