// The hero's preview: while the fixed code is live and the visitor has not pressed anything, the two cards play what a swap does
// (both ALLOW, the fingerprint changes, Preflight alone turns to BLOCK), labelled "Preview" so it never reads as a live result.
// This file is only the clock: which stage is showing and when it ends. What each stage looks like is `withPreview` in
// swap-view.js. The preview stops for good on the first real press, and as soon as the live code is not the code it started on.

/** The stages in order, and how long each stays (about 4 s in all, then it repeats). */
export const STAGES = [['safe', 1600], ['swap', 900], ['bad', 1900]];

/**
 * `calm` (reduced motion): no loop, one static stage. `schedule(fn, ms)` returns a function that cancels it.
 * `onChange` is called whenever `stage()` changes.
 */
export function createPreview({ calm = false, onChange = () => {}, schedule = (fn, ms) => { const id = setTimeout(fn, ms); return () => clearTimeout(id); } } = {}) {
  let stage = null; // the stage on screen, or null
  let began = null; // the code hash the preview started on, or null before it has started
  let over = false;
  let cancel = () => {};

  const show = (next) => { stage = next; onChange(); };
  const step = (i) => {
    show(STAGES[i][0]);
    cancel = schedule(() => step((i + 1) % STAGES.length), STAGES[i][1]);
  };
  const stop = () => { over = true; cancel(); if (stage !== null) show(null); };

  return {
    stage: () => stage,
    /** `live` is `{ hash }` while the page offers the preview (fixed code live, a recorded bad build to show), else null. */
    sync(live) {
      if (over) return;
      if (began !== null && (!live || live.hash !== began)) { stop(); return; }
      if (!live || began !== null) return;
      began = live.hash;
      if (calm) show('still'); else step(0);
    },
    /** The visitor sent a transaction: the preview has done its job. */
    press: stop,
  };
}
