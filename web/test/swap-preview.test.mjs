// The hero's preview clock (src/swap-preview.js): which stage shows and when, and that it stops for good. What each stage looks
// like is `withPreview` (tested with the view model in swap-view.test.mjs).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPreview, STAGES } from '../src/swap-preview.js';

function clock(options = {}) {
  let now = 0;
  const timers = [];
  const seen = [];
  const schedule = (fn, ms) => { const timer = { fn, at: now + ms, live: true }; timers.push(timer); return () => { timer.live = false; }; };
  const advance = (ms) => {
    now += ms;
    for (const timer of timers.filter((t) => t.live && t.at <= now).sort((a, b) => a.at - b.at)) { timer.live = false; timer.fn(); }
  };
  const preview = createPreview({ schedule, onChange: () => seen.push(preview.stage()), ...options });
  return { preview, advance, seen, timers };
}

test('it plays safe, swap, bad in a loop of about four seconds, and repeats', () => {
  const { preview, advance, seen } = clock();
  assert.equal(preview.stage(), null, 'nothing before the page offers it');
  preview.sync({ hash: 'A' });
  assert.equal(preview.stage(), 'safe');
  const total = STAGES.reduce((sum, [, ms]) => sum + ms, 0);
  assert.ok(total >= 3500 && total <= 4500, `about 4 s (${total} ms)`);
  advance(STAGES[0][1]);
  advance(STAGES[1][1]);
  assert.equal(preview.stage(), 'bad');
  advance(STAGES[2][1]);
  assert.deepEqual(seen, ['safe', 'swap', 'bad', 'safe'], 'and round again');
});

test('syncing the same live code again starts nothing new', () => {
  const { preview, timers } = clock();
  preview.sync({ hash: 'A' });
  const scheduled = timers.length;
  preview.sync({ hash: 'A' });
  preview.sync({ hash: 'A' });
  assert.equal(timers.length, scheduled);
});

test('a real press ends it for good, even if the fixed code comes back', () => {
  const { preview, advance, seen } = clock();
  preview.sync({ hash: 'A' });
  advance(STAGES[0][1]);
  preview.press();
  assert.equal(preview.stage(), null);
  advance(60_000);
  preview.sync({ hash: 'A' });
  assert.equal(preview.stage(), null);
  assert.deepEqual(seen, ['safe', 'swap', null], 'it said it was over, once');
});

test('a press before it ever started means it never starts', () => {
  const { preview, timers } = clock();
  preview.press();
  preview.sync({ hash: 'A' });
  assert.equal(preview.stage(), null);
  assert.equal(timers.filter((t) => t.live).length, 0);
});

test('the live state changing under it (other code, or the page leaving the fixed build) ends it for good', () => {
  for (const next of [{ hash: 'B' }, null]) {
    const { preview, advance } = clock();
    preview.sync({ hash: 'A' });
    advance(STAGES[0][1]);
    preview.sync(next);
    assert.equal(preview.stage(), null);
    preview.sync({ hash: 'A' });
    assert.equal(preview.stage(), null, 'not restarted by the code coming back');
    advance(60_000);
    assert.equal(preview.stage(), null);
  }
});

test('before the first read nothing happens, and it is not counted as over', () => {
  const { preview } = clock();
  preview.sync(null);
  preview.sync({ hash: 'A' });
  assert.equal(preview.stage(), 'safe');
});

test('reduced motion: one still stage, no timer is ever set, and it still ends on a press or a change', () => {
  const { preview, advance, timers } = clock({ calm: true });
  preview.sync({ hash: 'A' });
  assert.equal(preview.stage(), 'still');
  advance(60_000);
  assert.deepEqual([preview.stage(), timers.length], ['still', 0]);
  preview.sync({ hash: 'B' });
  assert.equal(preview.stage(), null);
});
