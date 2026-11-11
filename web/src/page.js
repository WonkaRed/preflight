// Page behaviours that need no data: sections fade in as they are scrolled to, a panel can wait until it is on screen, and
// a hash copies itself when clicked. Every one of them is an enhancement: with no IntersectionObserver, or with reduced motion
// asked for, the content is simply there. `Observer` is injectable so the tests need no browser.

const NEAR_END = '0px 0px -15% 0px';

/** Calls `run` once, when `el` first comes into view (at once when there is no IntersectionObserver). Returns a cancel. */
export function whenSeen(el, run, { Observer = globalThis.IntersectionObserver } = {}) {
  if (!Observer || !el) { run(); return () => {}; }
  const observer = new Observer((entries) => {
    if (entries.some((entry) => entry.isIntersecting)) { observer.disconnect(); run(); }
  }, { rootMargin: NEAR_END });
  observer.observe(el);
  return () => observer.disconnect();
}

/**
 * Hides every `[data-reveal]` element until it scrolls into view, then lets it fade in. Nothing is hidden unless the observer
 * that will show it exists, and nothing at all when `calm` (reduced motion): the page reads in full without JavaScript.
 */
export function revealOnScroll(doc, { Observer = globalThis.IntersectionObserver, calm = false } = {}) {
  if (!Observer || calm) return;
  const observer = new Observer((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add('in');
      observer.unobserve(entry.target);
    }
  }, { rootMargin: NEAR_END });
  for (const el of doc.querySelectorAll('[data-reveal]')) {
    el.classList.add('reveal');
    observer.observe(el);
  }
}

/**
 * Clicking an element marked `data-copy` copies its text and shows "Copied" for a moment (`data-copied`). Where the clipboard
 * is unavailable or refuses, nothing is claimed: the full value is still in the element's `title`.
 */
export function copyOnClick(doc, { clipboard = globalThis.navigator?.clipboard, schedule = setTimeout } = {}) {
  doc.addEventListener('click', async (event) => {
    const el = event.target?.closest?.('[data-copy]');
    const text = el?.textContent;
    if (!text || !clipboard?.writeText) return;
    try { await clipboard.writeText(text); } catch { return; }
    el.setAttribute('data-copied', '');
    schedule(() => el.removeAttribute('data-copied'), 1400);
  });
}
