const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const root = path.resolve(__dirname, '..');
const appRequire = createRequire(path.join(root, 'apps/web/package.json'));
const ts = appRequire('typescript');
const vue = appRequire('vue');

function evaluate(source, bindings, result) {
  const parsed = ts.createSourceFile('subject.ts', source, ts.ScriptTarget.Latest, true);
  for (const node of [...parsed.statements].reverse()) {
    if (ts.isImportDeclaration(node)) source = source.slice(0, node.getFullStart()) + source.slice(node.end);
  }
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS } }).outputText;
  return new Function(...Object.keys(bindings), `${js}\nreturn ${result};`)(...Object.values(bindings));
}
const route = vue.reactive({ query: { ioc_value: 'example.com', ioc_type: 'domain', victim: '10.0.0.1' } });
const pending = [];
const reportStarts = [];
const archiveReads = [];
const file = fs.readFileSync(path.join(root, 'apps/web/src/views/ly/event/history/index.vue'), 'utf8');
const page = evaluate(file.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1], {
  ...vue, defineOptions: () => {}, onUnmounted: () => {}, useRoute: () => route,
  lyAssetList: async () => [], eventAssetNames: () => [], normalizeLyEvents: (rows) => rows,
  deepflowGetEventsPage: (params) => new Promise((resolve, reject) => pending.push({ params, resolve, reject })),
  deepflowListHistoryReports: async () => [{ report_id: 'saved', generated_at: '2026-10-23', event_count: 25 }],
  deepflowGetHistoryReport: async (id) => { archiveReads.push(id); return { report_id: id, markdown: 'saved report' }; },
  deepflowGenerateHistoryReport: (params) => new Promise((resolve, reject) => reportStarts.push({ params, resolve, reject })),
}, '({ form, query, rows, total, page, search, changeMode, changePage, error, loading, generateReport, report, reportLoading, reportError, savedReports, savedReportId, openSavedReport })');
const settle = async () => { await vue.nextTick(); await new Promise((resolve) => setImmediate(resolve)); };

(async () => {
  const initial = pending.shift();
  assert.deepEqual(initial.params, { ioc_value: 'example.com', ioc_type: 'domain', victim: '10.0.0.1', scope: 'all', page: 1, page_size: 20 });
  initial.resolve({ items: [{ event_id: 'same' }], total: 40 });
  await settle();
  page.changePage(2);
  const next = pending.shift();
  assert.equal(next.params.victim, '10.0.0.1');
  assert.equal(next.params.page, 2);
  next.resolve({ items: [], total: 40 });
  await settle();
  page.form.mode = 'all';
  page.changeMode();
  const all = pending.shift();
  assert.equal(all.params.victim, undefined);
  assert.equal(all.params.ioc_value, 'example.com');
  assert.equal(all.params.page, 1);
  all.resolve({ items: [{ event_id: 'all' }], total: 100 });
  await settle();
  assert.equal(page.total.value, 100);
  const generation = page.generateReport();
  assert.deepEqual(reportStarts[0].params, { ioc_value: 'example.com', ioc_type: 'domain' }, 'report scope must omit page and include all targets');
  reportStarts.shift().resolve({ markdown: 'comprehensive' });
  await generation;
  assert.equal(page.report.value.markdown, 'comprehensive');
  assert.equal(page.reportLoading.value, false);

  const failedGeneration = page.generateReport();
  reportStarts.shift().reject(new Error('model unavailable'));
  await failedGeneration;
  assert.equal(page.reportError.value, 'model unavailable');
  assert.equal(page.report.value.markdown, 'comprehensive', 'failed generation must preserve the last completed report');
  await settle();
  assert.equal(page.savedReports.value[0].report_id, 'saved');
  page.savedReportId.value = 'saved';
  await page.openSavedReport();
  assert.equal(page.report.value.markdown, 'saved report');
  assert.deepEqual(archiveReads, ['saved']);
  assert.equal(reportStarts.length, 0, 'reading saved reports must not invoke generation');

  const staleGeneration = page.generateReport();
  const oldStart = reportStarts.shift();
  page.form.mode = 'same';
  page.changeMode();
  oldStart.resolve({ markdown: 'stale' });
  await staleGeneration;
  assert.equal(page.report.value, null, 'report for old scope must never appear in new query');
  const same = pending.shift();
  assert.equal(same.params.victim, '10.0.0.1');
  same.resolve({ items: [], total: 40 });
  await settle();
  page.search();
  const stale = pending.shift();
  route.query = { ioc_value: 'other.com', ioc_type: 'domain', victim: '10.0.0.2' };
  await vue.nextTick();
  const fresh = pending.shift();
  fresh.resolve({ items: [{ event_id: 'fresh' }], total: 1 });
  await settle();
  stale.resolve({ items: [{ event_id: 'stale' }], total: 999 });
  await settle();
  assert.equal(page.total.value, 1);
  assert.equal(page.rows.value[0].event_id, 'fresh');
  page.search();
  pending.shift().reject(new Error('query failed'));
  await settle();
  assert.equal(page.error.value, 'query failed');
  assert.equal(page.loading.value, false);
  assert.equal(page.rows.value.length, 0);
  route.query = { ioc_value: 'example.com' };
  await settle();
  assert.equal(pending.length, 0, 'missing victim must not silently query all victims');

  const table = fs.readFileSync(path.join(root, 'apps/web/src/views/ly/event/components/LyEventTable.vue'), 'utf8');
  let destination;
  const menu = evaluate(table.slice(table.indexOf('const iocMenu ='), table.indexOf('const reportVisible =')), {
    reactive: vue.reactive, router: { push: (value) => { destination = value; } },
  }, '({ openIOCMenu, viewIOCHistory, iocMenu })');
  let prevented = false;
  menu.openIOCMenu({ clientX: 10, clientY: 20, preventDefault: () => { prevented = true; }, stopPropagation: () => {} }, {
    ioc: { ioc_value: 'example.com', ioc_type: 'domain' }, victimDevice: '10.0.0.1',
  });
  assert.equal(prevented, true);
  assert.equal(menu.iocMenu.show, true);
  menu.viewIOCHistory();
  assert.deepEqual(destination, { path: '/ly/event/history', query: { ioc_value: 'example.com', ioc_type: 'domain', victim: '10.0.0.1' } });
  console.log('PASS: IOC history, manual report generation, report scope, direct failure handling, stale report protection');
})().catch((error) => { console.error(error); process.exitCode = 1; });
