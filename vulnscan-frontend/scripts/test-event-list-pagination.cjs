const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const root = path.resolve(__dirname, '..');
const requireApp = createRequire(path.join(root, 'apps/web/package.json'));
const ts = requireApp('typescript');
const vue = requireApp('vue');

function evaluate(source, bindings, result) {
  const parsed = ts.createSourceFile('subject.ts', source, ts.ScriptTarget.Latest, true);
  for (const statement of [...parsed.statements].reverse()) {
    if (ts.isImportDeclaration(statement)) {
      source = source.slice(0, statement.getFullStart()) + source.slice(statement.end);
    }
  }
  source = source.replace(/^export /gm, '');
  const js = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS },
  }).outputText;
  return new Function(...Object.keys(bindings), 'exports', `${js}\nreturn ${result};`)(...Object.values(bindings), {});
}

const queryTime = evaluate(fs.readFileSync(path.join(root, 'apps/web/src/utils/ly-query-time.ts'), 'utf8'), {}, '({ eventDateWindow, pickerTimeToEpoch, epochToPickerTime })');
const pending = [];
let failRank = false;
const store = evaluate(fs.readFileSync(path.join(root, 'apps/web/src/store/ly.ts'), 'utf8'), {
  defineStore: (_name, options) => {
    const instance = options.state();
    for (const [name, action] of Object.entries(options.actions)) instance[name] = action.bind(instance);
    return instance;
  },
  deepflowGetEvents: (params) => new Promise((resolve, reject) => pending.push({ params, resolve, reject })),
  normalizeLyEvents: (items) => items,
}, 'useLyStore');

const source = fs.readFileSync(path.join(root, 'apps/web/src/views/ly/event/list/index.vue'), 'utf8')
  .match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const page = evaluate(source, {
  ...vue,
  ...queryTime,
  onMounted: () => {}, onUnmounted: () => {}, defineOptions: () => {},
  useRoute: () => ({ query: {} }), useLyStore: () => store,
  eventAssetNames: () => [],
  deepflowGetEventRank: async () => { if (failRank) throw new Error('rank offline'); return { attackDevice: [{ name: 'test', value: 20 }], victimDevice: [], typeText: [] }; },
}, '({ state, loadEvents, onPageChange, filteredRows, selectedAsset, onlyAssetRelated, ranks, rankError })');
const settle = async () => { await vue.nextTick(); await new Promise((resolve) => setImmediate(resolve)); };
const reply = (request, total, id) => request.resolve({ total, items: [{ event_id: id }] });

(async () => {
  const initial = page.loadEvents();
  reply(pending.shift(), 2140, 'initial');
  await initial;
  assert.equal(Math.ceil(page.state.total / page.state.pageSize), 107);
  page.state.page = 107;
  page.state.rankKey = 'attackDevice';
  page.state.rankValue = 'old';
  page.state.keyword = '185.230';
  await vue.nextTick();
  const filtered = pending.shift();
  assert.equal(filtered.params.page, 1);
  assert.equal(filtered.params.keyword, '185.230');
  assert.equal(filtered.params.rank_key, undefined);
  reply(filtered, 140, 'filtered');
  await settle();
  assert.equal(page.state.page, 1);
  assert.equal(Math.ceil(page.state.total / page.state.pageSize), 7);
  assert.equal(page.filteredRows.value.length, 1, 'server results must not be filtered again by keyword');
  page.onPageChange(7);
  assert.equal(pending[0].params.keyword, '185.230');
  reply(pending.shift(), 140, 'page7');
  await settle();
  assert.equal(page.state.page, 7);

  page.state.keyword = 'old';
  await vue.nextTick();
  const old = pending.shift();
  page.state.keyword = 'new';
  await vue.nextTick();
  const newest = pending.shift();
  reply(newest, 20, 'newest');
  await settle();
  reply(old, 2140, 'stale');
  await settle();
  assert.equal(page.state.total, 20);
  assert.equal(store.events[0].event_id, 'newest');
  assert.equal(store.loading, false);

  page.state.keyword = '';
  await vue.nextTick();
  const cleared = pending.shift();
  assert.equal(cleared.params.page, 1);
  assert.equal(cleared.params.keyword, undefined);
  reply(cleared, 2140, 'cleared');
  await settle();
  assert.equal(page.state.total, 2140);
  page.selectedAsset.value = '10.0.0.0/24';
  await vue.nextTick();
  const asset = pending.shift();
  assert.equal(asset.params.asset, '10.0.0.0/24');
  assert.equal(asset.params.page, 1);
  reply(asset, 40, 'subnet-result');
  await settle();
  assert.equal(page.filteredRows.value.length, 1);
  assert.equal(page.state.total, 40);
  page.selectedAsset.value = '';
  page.onlyAssetRelated.value = true;
  await vue.nextTick();
  const related = pending.shift();
  assert.equal(related.params.only_asset_related, true);
  assert.equal(related.params.asset, undefined);
  reply(related, 20, 'registered-result');
  await settle();
  assert.equal(page.state.total, 20);
  failRank = true;
  const fail = page.loadEvents();
  reply(pending.shift(), 20, 'rank-failed');
  await fail;
  assert.equal(page.ranks.value.attackDevice.length, 0, 'old rank tags must be cleared');
  assert.ok(page.rankError.value);
  failRank = false;
  const listFail = page.loadEvents();
  pending.shift().reject(new Error('list offline'));
  await listFail;
  assert.equal(page.state.total, 0);
  assert.equal(store.events.length, 0);
  assert.equal(store.eventError, 'list offline');
  assert.equal(page.ranks.value.attackDevice.length, 0);
  const obsolete = page.loadEvents();
  const oldFailed = pending.shift();
  const current = page.loadEvents();
  reply(pending.shift(), 5, 'current');
  await current;
  oldFailed.reject(new Error('obsolete failure'));
  await obsolete;
  assert.equal(store.eventTotal, 5);
  assert.equal(store.eventError, '');
  page.state.starttime = new Date(2026, 9, 9).getTime();
  page.state.endtime = new Date(2026, 9, 8).getTime();
  await page.loadEvents();
  assert.equal(pending.length, 0, 'invalid date range must not query');
  assert.ok(store.eventError);
  assert.equal(store.eventTotal, 0);
  console.log('PASS: keyword and asset pagination, registered assets, clear, and stale response protection');
})().catch((error) => { console.error(error); process.exitCode = 1; });
