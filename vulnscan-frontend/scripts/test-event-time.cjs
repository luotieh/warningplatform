const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const ts = createRequire(path.join(root, 'package.json'))('typescript');

(async () => {
  const source = fs.readFileSync(path.join(root, 'apps/web/src/utils/ly.ts'), 'utf8');
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext } }).outputText;
  const { formatTimestamp, normalizeLyEvent, eventTimestampMs } = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'));
  const ms = Date.parse('2026-09-14T16:05:00Z');
  for (const zone of ['UTC', 'Asia/Shanghai', 'America/Los_Angeles']) {
    process.env.TZ = zone;
    for (const input of ['2026-09-14T16:05:00Z', '2026-09-15T00:05:00+08:00', '2026-09-15 00:05:00', '2026-09-15T00:05:00', ms / 1000, ms, ms * 1000]) {
      assert.equal(formatTimestamp(input), '2026-09-15 00:05:00', `${zone}: ${input}`);
      assert.equal(eventTimestampMs(input), ms);
    }
    assert.equal(formatTimestamp('2026-09-14T16:00:00Z'), '2026-09-15 00:00:00');
    assert.equal(formatTimestamp('2026-09-15', false), '2026-09-15');
  }
  const closed = normalizeLyEvent({ event_count: 1, is_final: true, first_time: '2026-09-14T16:05:00Z', converged_at: '2026-09-15T00:05:00+08:00', duration: 0 });
  assert.equal(closed.aggregationStatusText, '已收敛');
  assert.equal(closed.convergedTimeText, '2026-09-15 00:05:00');
  assert.equal(closed.durationText, '0秒');
  assert.equal(normalizeLyEvent({ event_count: 1, is_final: false }).aggregationStatusText, '进行中');
  assert.equal(formatTimestamp(null), '-');
  console.log('PASS: Beijing rendering across 3 host timezones, seconds/ms/us, midnight, single-hit lifecycle');
})().catch(error => { console.error(error); process.exitCode = 1; });
