// The page's scroll and copy behaviours (src/page.js): enhancements only, so every test also checks what happens without them.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { copyOnClick, revealOnScroll, whenSeen } from '../src/page.js';

class FakeObserver {
  static last = null;
  constructor(callback, options) { this.callback = callback; this.options = options; this.watched = new Set(); this.disconnected = false; FakeObserver.last = this; }
  observe(el) { this.watched.add(el); }
  unobserve(el) { this.watched.delete(el); }
  disconnect() { this.disconnected = true; }
  see(...targets) { this.callback(targets.map((target) => ({ target, isIntersecting: true }))); }
}
const element = () => { const classes = new Set(); return { classList: { add: (name) => classes.add(name), has: (name) => classes.has(name) } }; };

test('reveal: sections are hidden only once an observer is watching them, and shown as each is reached', () => {
  const [a, b] = [element(), element()];
  const doc = { querySelectorAll: (selector) => (selector === '[data-reveal]' ? [a, b] : []) };
  revealOnScroll(doc, { Observer: FakeObserver });
  assert.ok(a.classList.has('reveal') && b.classList.has('reveal'));
  assert.ok(!a.classList.has('in'));
  FakeObserver.last.see(a);
  assert.ok(a.classList.has('in') && !b.classList.has('in'), 'only the one that arrived');
  assert.ok(!FakeObserver.last.watched.has(a) && FakeObserver.last.watched.has(b), 'a shown section is not watched again');
});

test('reveal: with no IntersectionObserver, or reduced motion, nothing is touched and the page reads in full', () => {
  const a = element();
  const doc = { querySelectorAll: () => [a] };
  revealOnScroll(doc, { Observer: undefined });
  revealOnScroll(doc, { Observer: FakeObserver, calm: true });
  assert.ok(!a.classList.has('reveal'));
});

test('whenSeen runs once when the element arrives, at once with no observer, and can be cancelled', () => {
  let runs = 0;
  const el = {};
  whenSeen(el, () => { runs += 1; }, { Observer: undefined });
  assert.equal(runs, 1, 'no observer: the panel just plays');
  whenSeen(el, () => { runs += 1; }, { Observer: FakeObserver });
  assert.equal(runs, 1, 'not yet on screen');
  FakeObserver.last.see(el);
  assert.equal(runs, 2);
  assert.ok(FakeObserver.last.disconnected);
  const cancel = whenSeen(el, () => { runs += 1; }, { Observer: FakeObserver });
  cancel();
  assert.ok(FakeObserver.last.disconnected);
});

test('copy: clicking a marked hash copies its full text and says so for a moment; a refusing clipboard claims nothing', async () => {
  let handler;
  const doc = { addEventListener: (type, fn) => { if (type === 'click') handler = fn; } };
  const attrs = new Set();
  const hash = { textContent: 'CNtPsVA7xqz', setAttribute: (name) => attrs.add(name), removeAttribute: (name) => attrs.delete(name) };
  const target = { closest: (selector) => (selector === '[data-copy]' ? hash : null) };
  const copied = [];
  const timers = [];
  copyOnClick(doc, { clipboard: { writeText: async (text) => { copied.push(text); } }, schedule: (fn) => timers.push(fn) });
  await handler({ target: { closest: () => null } });
  assert.deepEqual(copied, [], 'a click elsewhere copies nothing');
  await handler({ target });
  assert.deepEqual(copied, ['CNtPsVA7xqz']);
  assert.ok(attrs.has('data-copied'));
  timers[0]();
  assert.ok(!attrs.has('data-copied'));

  attrs.clear();
  copyOnClick(doc, { clipboard: { writeText: async () => { throw new Error('denied'); } }, schedule: (fn) => timers.push(fn) });
  await handler({ target });
  assert.ok(!attrs.has('data-copied'), 'no "Copied" when the clipboard said no');
  copyOnClick(doc, { clipboard: undefined });
  await handler({ target });
  assert.ok(!attrs.has('data-copied'));
});
