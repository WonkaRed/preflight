// The Swap's agent panel: a scripted agent that obeys an injected web page and tries to pay the chameleon, and what the
// guard does about it. `agentScript` turns what the Swap already read (the code hash and the registry verdict) into the
// panel's text, with no DOM and no request of its own, so it is tested directly. `mountAgent` plays it: one row at a time,
// again whenever the verdict changes. No model runs here and nothing is signed or sent; the decision it shows comes from
// the same registry verdict the Preflight card shows, in the log line shape of guard/src/log.ts.
import { whenSeen } from './page.js';
import { guardEntry, STATUS_OF } from './swap.js';

/** The call the injected page asks for: the chameleon's payable `deposit` (demo/swap/chameleon), with 0.5 NEAR attached. */
export const CALL = { method: 'deposit', deposit: '500000000000000000000000', label: '0.5 NEAR' };

/** What each registry decision does to the call. Only a BLOCK ends the story: it is the call the owner's swap turns into a refusal. */
const OUTCOME = {
  BLOCK: { tone: 'block', word: 'REFUSED', line: 'The guard refused the call before signing. Nothing was signed or sent.' },
  WARN: { tone: 'warn', word: 'DECLINED', line: 'The guard asks a human before it signs a Warn. Nobody is here, so the call is declined. Nothing was signed or sent.' },
  ALLOW: { tone: 'allow', word: 'ALLOWED', line: 'Fixed code. Payment goes through.' },
};
/** What the verdict says is wrong with the code, in the vault's terms (the chameleon is a deposit vault). */
const HARM = {
  PF001: 'On the vulnerable build anyone can credit themselves a balance without paying and withdraw what the agent deposits (PF001).',
};
/** What a rule id means, in words. */
export const RULE_WORDS = { PF001: 'anyone can credit themselves a balance' };
const harm = (verdict) => HARM[verdict.ruleIds.find((rule) => HARM[rule])] ?? `The registry marks that code Unsafe${verdict.ruleIds.length ? ` (${verdict.ruleIds.join(', ')})` : ''}.`;
const NOTE = {
  live: 'Composed here from the live reads above, with the guard\'s decision-log fields.',
  recorded: 'Composed from the recorded verdict, not a live check, with the guard\'s decision-log fields.',
};
const SOURCE = { live: 'Live read', recorded: 'Recorded' };

const verdictText = (verdict) => (verdict.registered
  ? `${STATUS_OF[verdict.decision]}${verdict.ruleIds.length ? ` (${verdict.ruleIds.join(', ')})` : ''}`
  : 'none: unaudited code, or code changed since its audit');
/** The first recorded step with this decision: the other build's side of the story, for a recording only (a live page never takes a hash from one). */
const recordedStep = (recorded, decision) => recorded?.steps.find((step) => step.decision === decision) ?? null;

/**
 * What the panel shows: always two beats, whatever the live state. Today the fixed code is ALLOWED; then the owner swaps the
 * code at the same address and the guard REFUSES. Live, each beat is the verdict of the code live right now when it
 * has that decision and otherwise the registry's verdict for the other build (`other`, read from the chain with it); a live page never
 * takes a hash or a verdict from the recording. In a recording, each beat is its first step with that decision. `source` says which. `show` is false when there is no address to name (the section
 * hides). `key` is null until a verdict is known; the panel plays again when it changes. `at` (epoch ms) stamps the log line
 * only for a live check. `today` is null when no verdict can be shown for it; `swapped` is null when no refusal is on record
 * and the live code is not one (the panel then shows today alone and claims nothing more).
 */
export function agentScript({ mode, address, verdict, codeHash, at, other = null, recorded = null }) {
  if (!address) return { show: false, key: null };
  const call = `${address}.${CALL.method} with ${CALL.label}`;
  if (!['live', 'recorded'].includes(mode) || !verdict || !codeHash) return { show: true, key: null, address, call };
  const live = mode === 'live' ? { source: 'live', verdict, codeHash } : null;
  const otherBeat = other && { source: 'live', verdict: other.verdict, codeHash: other.codeHash };
  const recordedBeat = (decision) => { const step = recordedStep(recorded, decision); return step && { source: 'recorded', verdict: step, codeHash: step.codeHash }; };
  const beat = (decision) => (!live ? recordedBeat(decision) : live.verdict.decision === decision ? live : otherBeat?.verdict.decision === decision ? otherBeat : null);
  const fixed = beat('ALLOW') ?? live;
  const bad = beat('BLOCK');
  const today = fixed && {
    source: fixed.source, hash: fixed.codeHash, verdict: verdictText(fixed.verdict), word: OUTCOME[fixed.verdict.decision].word, tone: OUTCOME[fixed.verdict.decision].tone,
    when: fixed.verdict.decision === 'ALLOW' ? 'Today: fixed code.' : 'Today: no verdict for this code.',
    line: fixed.verdict.decision === 'ALLOW' ? OUTCOME.ALLOW.line : 'The guard asks a human first, and nobody is here.',
  };
  const swapped = bad && {
    ...OUTCOME.BLOCK, source: bad.source, hash: bad.codeHash, verdict: verdictText(bad.verdict), why: harm(bad.verdict),
    log: JSON.stringify(guardEntry({ contract: address, method: CALL.method, deposit: CALL.deposit, codeHash: bad.codeHash, verdict: bad.verdict, at: bad === live ? at : null }), null, 2),
    note: NOTE[bad.source],
  };
  return { show: true, key: `${mode}|${address}|${live?.codeHash}|${today?.source}:${today?.hash}|${swapped?.source}:${swapped?.hash}`, address, call, today, swapped };
}

/**
 * Milliseconds after the start at which each row appears: the agent's side (task, page, call) needs no chain data and starts
 * at once; the check and the outcome follow it, and wait for the verdict if it has not been read yet.
 */
export const ROW_DELAYS = [0, 800, 1900, 3100, 4500];
const BEAT_MS = 400;
const ROWS = ['task', 'page', 'call', 'check', 'out'];
const AGENT_ROWS = 3;
export const AGENT_IDS = {
  section: 'swap-agent', replay: 'agent-replay', inject: 'agent-inject', call: 'agent-call',
  todayWord: 'agent-today-word', todaySrc: 'agent-today-src', todayHash: 'agent-today-hash', todayVerdict: 'agent-today-verdict', todayLine: 'agent-today-line',
  out: 'agent-out', src: 'agent-src', word: 'agent-word', line: 'agent-line', why: 'agent-why', hash: 'agent-hash', verdict: 'agent-verdict', log: 'agent-log', note: 'agent-note',
  ...Object.fromEntries(ROWS.map((row) => [`row-${row}`, `agent-row-${row}`])),
};

/**
 * Wires the panel's elements. `calm`: no staging, the final state at once. `schedule(fn, ms)` returns a function that cancels
 * it; `now()` is the clock the staging is measured on. The staging waits until the panel is on screen (`seen(el, run)`, by
 * default `whenSeen`), so a visitor who scrolls down finds it starting rather than finished.
 */
export function mountAgent(doc, { calm = false, now = () => Date.now(), schedule = (fn, ms) => { const id = setTimeout(fn, ms); return () => clearTimeout(id); }, seen = whenSeen } = {}) {
  const els = Object.fromEntries(Object.entries(AGENT_IDS).map(([name, id]) => [name, doc.getElementById(id)]));
  const rows = ROWS.map((row) => els[`row-${row}`]);
  const cancels = { agent: [], verdict: [] };
  let started = null; // the address whose agent rows are staged, and when that began
  let startedAt = 0;
  let playing = null; // the key of the verdict rows on screen
  let last = null;
  let released = calm; // false until the panel has been seen once
  let waiting = false;

  const setRow = (i, on) => rows[i].setAttribute('data-state', on ? 'on' : 'off');
  if (!calm) rows.forEach((_, i) => setRow(i, false)); // the page ships every row showing, so it reads in full without script
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

  const paintSource = (el, source, text) => { el.textContent = SOURCE[source]; el.setAttribute('data-source', source); el.setAttribute('title', text); };
  const paintHash = (el, hash) => { el.textContent = hash; el.setAttribute('title', hash); };
  function paintToday(today) {
    if (!today) return;
    els.todayWord.textContent = today.word;
    els.todayWord.setAttribute('data-tone', today.tone);
    els.todayLine.textContent = today.line;
    els.todayVerdict.textContent = today.verdict;
    paintHash(els.todayHash, today.hash);
    paintSource(els.todaySrc, today.source, today.source === 'live' ? 'Read from the chain just now.' : 'The registry\'s verdict for the fixed build, from a recorded testnet run. Not a live check.');
  }
  function paintSwapped(swapped) {
    els.out.setAttribute('data-tone', swapped.tone);
    els.word.textContent = swapped.word;
    els.line.textContent = swapped.line;
    els.why.textContent = swapped.why;
    els.verdict.textContent = swapped.verdict;
    paintHash(els.hash, swapped.hash);
    els.log.textContent = swapped.log;
    els.note.textContent = swapped.note;
    paintSource(els.src, swapped.source, swapped.source === 'live' ? 'Read from the chain just now.' : 'The registry\'s verdict for the vulnerable build, from a recorded testnet run. Not a live check.');
  }

  function playVerdict(script) {
    // Not yet read: the rows stay hidden. Read already, or read late: keep the pace the script has, but never skip the beat.
    stop(['verdict']);
    for (let i = AGENT_ROWS; i < rows.length; i++) setRow(i, false);
    if (script.key === null) return;
    paintToday(script.today);
    rows[AGENT_ROWS].hidden = !script.today;
    rows[AGENT_ROWS + 1].hidden = !script.swapped;
    if (script.swapped) paintSwapped(script.swapped);
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
      if (!released) {
        if (!waiting) { waiting = true; seen(els.section, () => { released = true; if (last) api.update(last); }); }
        return;
      }
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
