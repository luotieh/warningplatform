const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const root = path.resolve(__dirname, '..');
const req = createRequire(path.join(root, 'apps/web/package.json'));
const ts = req('typescript');
const vue = req('vue');
function read(file) { return fs.readFileSync(path.join(root, 'apps/web/src', file), 'utf8'); }
function evaluate(source, bindings, result) {
  const parsed = ts.createSourceFile('subject.ts', source, ts.ScriptTarget.Latest, true);
  for (const s of [...parsed.statements].reverse()) {
    if (ts.isImportDeclaration(s)) source = source.slice(0, s.getFullStart()) + source.slice(s.end);
  }
  source = source.replace(/^export /gm, '');
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  return new Function(...Object.keys(bindings), 'exports', `${js}\nreturn ${result}`)(...Object.values(bindings), {});
}
const time = evaluate(read('utils/ly-query-time.ts'), {}, '({eventDateWindow,pickerTimeToEpoch,epochToPickerTime})');
const settle = async () => { await vue.nextTick(); await new Promise(r => setImmediate(r)); };
(async () => {
  const now = Date.parse('2026-10-07T16:30:00Z');
  for (const [scope, day] of [['today','08'],['3','06'],['7','02']]) {
    const window = time.eventDateWindow(scope, null, null, now);
    assert.equal(window.starttime, Date.parse(`2026-10-${day}T00:00:00+08:00`) / 1000);
    assert.equal(window.endtime, now / 1000);
  }
  const picker = new Date(2026, 9, 8, 13, 25).getTime();
  assert.equal(time.pickerTimeToEpoch(picker), Date.parse('2026-10-08T13:25:00+08:00'));
  assert.equal(time.epochToPickerTime(time.pickerTimeToEpoch(picker)), picker);
  const custom = time.eventDateWindow('all', picker, picker);
  assert.equal(custom.starttime, Date.parse('2026-10-08T00:00:00+08:00')/1000);
  assert.equal(custom.endtime, Date.parse('2026-10-09T00:00:00+08:00')/1000);
  const requests = [];
  let incomplete = false;
  const api = evaluate(read('api/ly/deepflow.ts'), {
    useAccessStore: () => ({ accessToken: 'test' }), localStorage: { getItem: () => null },
    fetch: async (url) => {
      const params = new URL(url, 'http://local').searchParams;
      requests.push(params);
      const page = Number(params.get('page'));
      const items = page === 1 ? Array.from({length:200}, (_,i) => ({event_id:String(i)})) : incomplete ? [] : [{event_id:'archived-201', archive_date:'2026-10-08'}];
      return { ok: true, json: async () => ({code:200,data:{items,total:201,page,page_size:200}}) };
    },
  }, '({deepflowGetAllEvents})');
  const all = await api.deepflowGetAllEvents();
  assert.equal(all.length, 201);
  assert.equal(all[200].event_id, 'archived-201');
  assert.equal(requests.length, 2);
  assert.ok(requests.every(p => p.get('scope') === 'all'));
  incomplete = true;
  await assert.rejects(api.deepflowGetAllEvents(), /不完整/);
  const store = evaluate(read('store/ly.ts'), {
    defineStore: (_, options) => { const instance = options.state(); for (const [name,fn] of Object.entries(options.actions)) instance[name] = fn.bind(instance); return instance; },
    deepflowGetEvents: async () => ({items:[{event_id:'filtered-page'}],total:1}),
    deepflowGetAllEvents: async () => all,
    normalizeLyEvents: x => x,
  }, 'useLyStore');
  await store.loadEvents({keyword:'test'});
  await store.loadOverviewEvents();
  assert.equal(store.events.length, 1);
  assert.equal(store.overviewEvents.length, 201);
  assert.equal(store.events[0].event_id, 'filtered-page');
  const pending = [];
  const errors = [];
  const search = evaluate(read('views/ly/search/index.vue').match(/<script[^>]*>([\s\S]*?)<\/script>/)[1], {
    ...vue, ...time, onMounted:()=>{}, defineOptions:()=>{}, useRoute:()=>({query:{}}),
    normalizeLyEvents:x=>x, message:{error:x=>errors.push(x)},
    lyEventSearch: params => new Promise((resolve,reject)=>pending.push({params,resolve,reject})),
  }, '({form,state,startSearch,onPageChange,onPageSizeChange,resetSearch})');
  search.form.keyword = 'a b';
  search.startSearch();
  let request = pending.shift();
  assert.equal(request.params.scope, 'all');
  assert.equal(request.params.keyword, 'a b');
  request.resolve({items:[{event_id:'server-match',archive_date:'2026-10-08'}],total:201});
  await settle();
  assert.equal(search.state.rows.length,1,'server multi-token match must not be filtered again');
  search.form.keyword='unsubmitted edit';
  search.onPageChange(11);
  request=pending.shift();
  assert.equal(request.params.page,11);
  assert.equal(request.params.keyword,'a b','page changes must keep submitted query');
  request.resolve({items:[{event_id:'archived-last-page'}],total:201});
  await settle();
  assert.equal(search.state.total,201);
  search.form.keyword='old'; search.startSearch();
  const old = pending.shift();
  search.form.keyword='new'; search.startSearch();
  const current = pending.shift();
  current.resolve({items:[{event_id:'new'}],total:1}); await settle();
  old.resolve({items:[{event_id:'old'}],total:201}); await settle();
  assert.equal(search.state.rows[0].event_id,'new');
  search.startSearch(); request=pending.shift(); search.resetSearch();
  request.resolve({items:[{event_id:'reset-stale'}],total:1}); await settle();
  assert.equal(search.state.searched,false);
  assert.equal(search.state.rows.length,0);
  search.form.starttime=new Date(2026,9,9).getTime();
  search.form.endtime=new Date(2026,9,8).getTime(); search.startSearch();
  assert.equal(pending.length,0);
  assert.equal(errors.length,1);
  console.log('PASS: Beijing date windows, archived rows beyond 200, separate overview cache, search pagination and stale requests');
})().catch(e=>{console.error(e);process.exitCode=1});
