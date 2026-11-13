import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, strip, OffframeError } from '../engine.js';
import { fx, inflate } from './helpers.js';

// Small seeded PRNG so failures are reproducible.
function rng(seed) { let s = seed >>> 0; return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; }; }

for (const name of ['trail-photo.jpg', 'screen-capture.png', 'trailer.jpg']) {
  test(`fuzz ${name}: 1500 mutations never crash or hang; accepted outputs re-parse`, async () => {
    const base = fx(name);
    const rand = rng(12345 + name.length);
    let accepted = 0, rejected = 0;
    const t0 = Date.now();
    for (let i = 0; i < 1500; i++) {
      const m = base.slice();
      const kind = rand();
      if (kind < 0.5) { for (let k = 0; k < 1 + Math.floor(rand() * 4); k++) m[Math.floor(rand() * m.length)] = Math.floor(rand() * 256); }
      else if (kind < 0.75) { /* truncate */ var cut = m.subarray(0, Math.floor(rand() * m.length)); await run(cut); continue; }
      else { const a = Math.floor(rand() * m.length), b = Math.min(m.length, a + Math.floor(rand() * 64)); m.fill(0xff, a, b); }
      await run(m);
    }
    async function run(bytes) {
      try {
        const r = await strip(bytes, { inflate });
        accepted++;
        const again = await analyze(r.bytes, { inflate });
        assert.ok(again.width > 0 && again.height > 0);
        assert.ok(r.bytes.length <= bytes.length + 64, 'output is not larger than input beyond the orientation block');
      } catch (e) {
        if (!(e instanceof OffframeError)) throw e; // anything else is a bug
        rejected++;
      }
    }
    assert.ok(accepted + rejected === 1500);
    assert.ok(Date.now() - t0 < 60000, 'fuzz run stays fast');
    console.log(`  ${name}: accepted ${accepted}, rejected ${rejected}`);
  });
}
