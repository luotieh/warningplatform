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

const pending = [];
const store = evaluate(fs.readFileSync(path.join(root, 'apps/web/src/store/ly.ts'), 'utf8'), {
  defineStore: (_name, options) => {
    const instance = options.state();
    for (const [name, action] of Object.entries(options.actions)) instance[name] = action.bind(instance);
    return instance;
  },
  deepflowGetEvents: (params) => new Promise((resolve) => pending.push({ params, resolve })),
  normalizeLyEvents: (items) => items,
}, 'useLyStore');

const source = fs.readFileSync(path.join(root, 'apps/web/src/views/ly/event/list/index.vue'), 'utf8')
  .match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const page = evaluate(source, {
  ...vue,
  onMounted: () => {}, onUnmounted: () => {}, defineOptions: () => {},
  useRoute: () => ({ query: {} }), useLyStore: () => store,
  eventAssetNames: () => [],
  deepflowGetEventRank: async () => ({ attackDevice: [], victimDevice: [], typeText: [] }),
}, '({ state, loadEvents, onPageChange, filteredRows })');
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
  console.log('PASS: 107 -> 7 pages on keyword change, paging, clear, and stale response protection');
})().catch((error) => { console.error(error); process.exitCode = 1; });
