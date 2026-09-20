const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const root = path.resolve(__dirname, '..');
const req = createRequire(path.join(root, 'package.json'));
const ts = req('typescript');
const sfc = req('vue/compiler-sfc');
const componentRoot = path.join(root, 'apps/web/src/views/ly/event');
const ref = (value) => ({ value });
function component(file) {
  const { descriptor, errors } = sfc.parse(fs.readFileSync(path.join(componentRoot, file), 'utf8'));
  assert.equal(errors.length, 0);
  const template = sfc.compileTemplate({ source: descriptor.template.content, filename: file, id: 'test' });
  assert.equal(template.errors.length, 0, JSON.stringify(template.errors));
  return ts.createSourceFile(file + '.ts', descriptor.scriptSetup.content, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}
function run(source, statements, mocks, expose) {
  const js = ts.transpileModule(statements.map((n) => n.getText(source)).join('\n'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const context = vm.createContext({ ...mocks, ref, console, Set });
  vm.runInContext(js + '\nglobalThis.api = {' + expose.join(',') + '};', context);
  return context.api;
}
function pendingAPI() {
  const calls = [];
  return { calls, fetch: (...args) => new Promise((resolve, reject) => calls.push({ args, resolve, reject })) };
}
const page = (id, cursor = '', version = 1) => ({ items: [{ hit_id: id, time: '2026-09-14T16:00:00Z' }], next_cursor: cursor, total: 2, snapshot_version: version, statistics_quality: 'verified' });

(async () => {
  // Execute the production component's handlers, with only its UI/API dependencies mocked.
  const source = component('components/LyEventTable.vue');
  const vars = ['occVisible','occLoading','occCursor','occTotal','occQuality','occDeclared','occSnapshot','evidenceVisible','evidenceHitId','occRequest','occRows','expandedOccIndices','expandedHex','currentEventContext'];
  const funcs = ['buildOccRows','openOccurrences','loadOccurrencePage'];
  const selected = source.statements.filter(n => ts.isFunctionDeclaration(n) ? funcs.includes(n.name?.text) :
    ts.isVariableStatement(n) && n.declarationList.declarations.some(d => vars.includes(d.name.getText(source))));
  const backend = pendingAPI();
  const errors = [];
  const api = run(source, selected, { deepflowGetOccurrences: backend.fetch, formatTimestamp: x => x, formatBytes: String, message: { error: e => errors.push(e) } }, [...vars.filter(x => x !== 'occRequest'), ...funcs]);
  const first = api.openOccurrences({ event_id: 'event-a' });
  const second = api.openOccurrences({ event_id: 'event-b' });
  backend.calls[0].resolve(page('obsolete'));
  await first;
  assert.equal(api.occRows.value.length, 0, 'late event-a response must not pollute event-b');
  backend.calls[1].resolve(page('hit-b1', 'fixed-snapshot-cursor', 7));
  await second;
  assert.equal(api.occSnapshot.value, 7);
  assert.equal(api.occRows.value[0].hit_id, 'hit-b1');
  const next = api.loadOccurrencePage();
  await api.loadOccurrencePage();
  assert.equal(backend.calls.length, 3, 'double click must not create duplicate page requests');
  assert.deepEqual(backend.calls[2].args, ['event-b','fixed-snapshot-cursor']);
  backend.calls[2].resolve(page('hit-b2', '', 7));
  await next;
  assert.deepEqual(Array.from(api.occRows.value, r => r.idx), [1,2]);
  assert.equal(api.occCursor.value, '');
  const failure = api.openOccurrences({ event_id: 'failed' });
  backend.calls[3].reject(new Error('test failure'));
  await failure;
  assert.equal(api.occLoading.value, false);
  assert.equal(api.occRows.value.length, 0);
  assert.equal(errors.length, 1);

  const dialog = component('detail/components/EvidenceDialog.vue');
  const detailAPI = pendingAPI();
  const props = { eventId: 'event-b', hitId: 'hit-b1', visible: true, version: 7 };
  let change;
  const detail = run(dialog, dialog.statements.filter(n => !ts.isImportDeclaration(n)), {
    defineProps: () => props, defineEmits: () => () => {}, watch: (_, callback) => { change = callback; }, deepflowGetOccurrences: detailAPI.fetch,
  }, ['evidence','error','loading']);
  const old = change();
  assert.deepEqual(detailAPI.calls[0].args, ['event-b','','hit-b1',7]);
  props.hitId = 'hit-b2';
  props.version = 8;
  const current = change();
  detailAPI.calls[0].resolve(page('obsolete-evidence'));
  await old;
  assert.equal(Object.keys(detail.evidence.value).length, 0);
  detailAPI.calls[1].resolve(page('hit-b2','',8));
  await current;
  assert.equal(detail.evidence.value.hit_id, 'hit-b2');
  assert.equal(detail.loading.value, false);
  component('detail/components/ChatBox.vue');
  component('detail/components/ReportModal.vue');
  console.log('PASS: actual Vue handlers — snapshot cursor paging, duplicate clicks, stale responses, failed fetch, versioned precise evidence, template compilation');
})().catch(error => { console.error(error); process.exitCode = 1; });
