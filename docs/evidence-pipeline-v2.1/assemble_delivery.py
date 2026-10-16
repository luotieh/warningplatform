"""Assemble review artifacts from saved, locally executed tests; never fetch remote data."""
import csv
import difflib
import hashlib
import json
from collections import Counter
from pathlib import Path

D = Path(__file__).resolve().parent
R = D.parent.parent
B = R / '.local/v21-baseline'

def load(p):
    return json.loads(Path(p).read_text(encoding='utf-8-sig'))

def save(name, value):
    (D/name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

def doc(name, value):
    (D/name).write_text(value.strip()+'\n', encoding='utf-8')

raw = load(R/'.local/pipeline-v21-coverage180-report-replay.json')
summary = []
seen = {}
for row in raw:
    ledger = row['normalized_evidence']['items']
    for item in ledger:
        if item.get('kind') in ('fact', 'semantic'):
            seen.setdefault(item['rule_id'], Counter())[item.get('terminal_status', 'unknown')] += 1
    units = []
    for u in row['phase_one']['result']['units']:
        fact = u.get('fact') or {}
        units.append({k: u[k] for k in ('id','ioc_type','ioc_value','scope','status','reason','score') if k in u})
        units[-1]['fact'] = {k: fact[k] for k in ('fact_id','observation_kind','status','reason','stats','quality','window','ioc_type','ioc_value') if k in fact}
        units[-1]['fact_source_count'] = len(fact.get('source_ids') or [])
    summary.append({k: row[k] for k in ('event_id','snapshot_version','watermark','revision_watermark','status','reason','declared_hits','loaded_hits','raw_bytes','issues','protocol_inputs','production_writes','model_called','report_rendered') if k in row})
    summary[-1].update(c_units=units, c_score=row['phase_one']['result']['score'], normalized_counts=row['normalized_evidence']['counts'], catalog_total=row['pipeline']['catalog_total'], catalog_terminal_count=row['pipeline']['catalog_terminal_count'], executed_instances=row['pipeline']['executed_instances'], accepted_instances=row['pipeline']['accepted_instances'], ledger_items=len(ledger), ledger_score_sum=sum(x.get('score_contribution',0) for x in ledger))
save('real-replay-summary.json', {'source':'.local/pipeline-v21-coverage180-report-replay.json','real_model_called':False,'production_writes':False,'snapshots':summary,'c01_snapshot34':{'event_id':'ly-e0eeedcf-1be2-4469-9482-1306573557a3','independent_events':85,'days_active':22,'score':10,'status':'observed','verification':'TestPhaseOneArchivedSnapshot34C01; real-replay.log'}})

cases = []
for name in ('f-validation-cases.csv','s-validation-cases.csv'):
    with (D/name).open(encoding='utf-8-sig', newline='') as f:
        cases.extend(csv.DictReader(f))
maps = load(D/'input-field-map.json')
headers = ['rule_id','rule_kind','input_families','go_field_paths','mock_case_count','mock_scenarios','mock_passed','real_material_available','real_execution_verified','real_terminal_counts','real_model_verified','remaining_blocker']
with (D/'execution-validation-matrix.csv').open('w', encoding='utf-8-sig', newline='') as f:
    w=csv.DictWriter(f,headers); w.writeheader()
    for entry in maps:
        group=[x for x in cases if x['rule_id']==entry['id']]
        states=seen.get(entry['id'],Counter())
        executed=sum(v for k,v in states.items() if k in ('observed','not_observed','neutral','contradict','explanation'))
        w.writerow(dict(rule_id=entry['id'],rule_kind=entry['kind'],input_families=';'.join(entry['input_families']),go_field_paths=';'.join(entry['available_typed_field_paths']),mock_case_count=len(group),mock_scenarios=';'.join(x['scenario'] for x in group),mock_passed=bool(group) and all(x['test_result']=='passed' for x in group),real_material_available='executed_input_available' if executed else 'not_proven_by_frozen_replay',real_execution_verified=bool(executed),real_terminal_counts=json.dumps(states,sort_keys=True),real_model_verified=False if entry['kind']=='S' else 'not_applicable',remaining_blocker='live model quota exhausted; labelled accuracy set absent' if entry['kind']=='S' else 'rule-specific numerical boundary sweeps and production capacity not fully accepted'))
assert len(maps)==82 and len(cases)==479

events=[]
for line in (D/'tests.jsonl').read_text(encoding='utf-8-sig').splitlines():
    if line.startswith('{'):
        events.append(json.loads(line))
assert not [e for e in events if e.get('Action')=='fail']
counts=Counter(e['Action'] for e in events if e.get('Test'))
save('test-summary.json', {'actions':dict(counts),'failed':False,'controlled_f_cases':295,'controlled_s_cases':184,'semantic_role_cases':69,'fixtures':len(list((D/'mock-fixtures').glob('*.json'))),'real_replay_snapshots':len(summary)})

# Compare against the frozen dirty v2 workspace, not HEAD (which predates v2).
manifest=load(D/'baseline-files.json')
files=set(manifest)
files.update(str(p.relative_to(R)).replace('\\','/') for p in (R/'vulnscan-backend').rglob('*.go') if not any(x in p.parts for x in ('node_modules','.git','vendor')))
files.add('vulnscan-backend/traffic/internal/service/testdata/prepared-controlled-http.json')
patch=[]; changed=[]
for rel in sorted(files):
    old=B/rel; new=R/rel
    a=old.read_text(encoding='utf-8-sig') if old.exists() else ''
    b=new.read_text(encoding='utf-8-sig') if new.exists() else ''
    # Harness copied to baseline solely for before/after measurement is new delivery code.
    if rel.endswith('/evidence_capacity_v21_test.go'):
        a=''
    if a==b: continue
    patch.append('diff --git a/'+rel+' b/'+rel+'\n')
    if not a:
        patch.append('new file mode 100644\n')
    elif not b:
        patch.append('deleted file mode 100644\n')
    for line in difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile='a/'+rel if a else '/dev/null',tofile='b/'+rel if b else '/dev/null'):
        patch.append(line if line.endswith('\n') else line+'\n\\ No newline at end of file\n')
    changed.append(rel)
(D/'code-changes.patch').write_bytes(''.join(patch).encode('utf-8'))
save('changed-files.json',changed)
oldmap=R/'docs/evidence-pipeline-v2/input-field-map.json'
if not (D/'input-field-map-v2-before.json').exists():
    (D/'input-field-map-v2-before.json').write_bytes(oldmap.read_bytes())
oldmap.write_bytes((D/'input-field-map.json').read_bytes())

descriptions={
'evidence_prepared.go':'扩展现有独立入口：1.1合同、模式、严格导入、覆盖与输出校验。',
'evidence_prepared_contract.go':'校验范围、时间、IOC原始字段、事务、材料引用、覆盖及归一化不变量。',
'evidence_contract_schema.go':'从真实Go结构生成Schema、82项字段映射和导入结构校验。',
'evidence_normalized_contract.go':'输出输入摘要、版本、覆盖、诊断和去重来源索引。',
'evidence_report_input.go':'正式链路接入合同；缓存输入摘要与覆盖，避免热缓存重复读原始数据。',
'normalization.go':'区分中立/反证/解释/恶意支持；实例身份加入IOC与观测种类。',
'types.go':'保留独立时间观测种类。',
'evidence_pipeline.go':'目录与实例执行统计分开；语义分类汇总；联合实例来源身份。',
'evidence_pipeline_journal.go':'发布有界分页索引，保留旧审计格式兼容与完整性校验。',
'evidence_pipeline_pages.go':'每页100实例、源字典裁剪与哈希校验；只解压请求页。',
'evidence_pipeline_limits.go':'历史冻结并发默认4且硬限制4。',
'evidence_pipeline_snapshot.go':'有界历史冻结，保存逐源失败/预算诊断和确定性结果。',
'evidence_pipeline_time.go':'按资产、IOC和观测种类分别构建独立时间序列。',
'phase_one.go':'联合计算选择同类观测，禁止混合TCP/DNS/HTTP样本。',
'evidence_pipeline_metrics.go':'保留微秒阶段耗时。',
'evidence_semantic_report.go':'分别记录语义规划和执行/验收耗时。',
'report_evidence.go':'报告来源使用同一实例身份，附加上下文ID避免碰撞。',
}
doc('file-changes.md','# 逐文件增量\n\n基线为本轮开始时含既有未提交v2改动的本地副本；不是HEAD。清单不包含原有未改动业务文件。\n\n'+'\n'.join('- `'+p+'`：'+descriptions.get(Path(p).name,'合同、回归、性能或受控样例验证；详见增量diff。') for p in changed)+'\n\n文档：v2.1目录为本轮交付；旧v2/input-field-map.json更新为相同的Go生成映射，更新前文件保存在input-field-map-v2-before.json。')

doc('architecture-delta.md','''# 架构增量

保留现有L1冻结、L2预处理、59F/23S执行、C联合评价、L5归一化及报告链路。没有第二套F/S/C实现，没有调整一期阈值或计分策略。

标准入口为现有 `DecodePreparedEvidence` → `ExecutePreparedEvidence`，只消费PreparedEvidenceBundle与注入语义模型，不创建Store，不解析原始报文。正式链路继续使用原执行器，并生成相同的完整规范化结果；一致性测试比较F、S规划、C与完整归一化账本。

Prepared合同升级为1.1，增加按数据族/范围覆盖。导入拒绝旧版本、未知字段、错误范围/事务/引用、来源冲突及伪造绑定；Schema由真实Go类型反射导出，兼容保留旧结构中的大写JSON键。不是把草案字段改名后硬接到执行器。可用字段映射不是每项必须同时具备的字段清单，实际适用性由原规则合同及前置条件决定。

归一化复用现有执行结果，附加版本合同、source_index/source_sets及覆盖诊断。解释型槽位不进入恶意支持；neutral与contradict保留各自终态。只有原C条件成立才有分数，同源去重不变，分数不是校准概率。

实例身份增加IOC与观测种类，修复大快照多IOC同范围碰撞；TCP发起、DNS问题、完整HTTP事务分开构建时间序列。历史冻结采用最多4个工作线程、每源诊断与固定水位。

审计保留原压缩完整账本并增加分页索引。请求仍校验全部压缩块哈希，但只解压命中页；不声称数据库读取量已经与页大小完全无关。完整性、旧格式回读及索引损坏测试通过。索引增加写入量及耗时，需继续容量验收。
''')

doc('test-results.md',f'''# 本地测试结果

Go1.26.8，Windows/amd64。基线与最终工作区相同工具链。

- `go build ./...`：通过，build.log。
- `go vet ./evidence ./traffic/...`：通过，vet.log。
- `go test ./evidence ./traffic/... -count=1 -json`：通过；tests.jsonl，测试级动作汇总 {dict(counts)}。
- `go test ./traffic/internal/service -run '^TestPreparedEvidenceMockNoStore$|^TestPreparedEvidenceFormalParity$' -count=1 -v`：通过，final-prepared-tests.log；成功路径显式使用stub模式。
- `python docs/evidence-pipeline-v2.1/verify_contracts.py`：通过，82项4493字段路径和两份Schema真实样例。
- 59F×5=295个受控案例；23S×8=184个案例；23S×3=69个角色与终态案例。逐项详见CSV和测试源码。
- 7个冻结真实快照及C01快照34正式报告链路：通过，real-replay.log。

F边界案例为非法快照版本这一共同输入边界，并不表示59项数值阈值均已穷举。S反例包含伪造引用、另一真实事务引用、非法强度和模型失败；Stub不验证模型理解准确率。

中途日志保留了已修复失败：完整账本实例ID冲突、字节切片字段映射、缓存摘要不一致及并行执行时20ms定时测试波动。最终有效结果以上述日志为准。竞态、真实模型与生产容量不在通过项中。
''')

doc('semantic-validation.md','''# 语义验收边界

23个槽位均完成结构规划与受控响应验收，184个案例；另69个角色/终态案例。support、neutral、contradict、解释型槽位、缺材料、错误引用及模型失败分别保留状态。解释型槽位不是恶意支持；risk_support_eligible也不是直接分数，C仍负责联合门控。

mock-execution-result.json为无数据库执行的受控Stub结果；mock-fixtures中的141份分规则材料不是一个覆盖82项阳性的事件。受控S任务材料及前置F仅证明合同和引用验收。

真实模型本轮调用次数为0。遵照用户要求，K2.7额度不足后停止调用并跳过；没有再次要求Qwen配置。没有人工标注准确率数据，不能声称真实语义或最终报告LLM验收通过。冻结回放S的missing/model_unavailable不等于有效阴性。
''')
doc('race-test.md','''# 竞态测试

尝试 `CGO_ENABLED=1 go test -race ./evidence ./traffic/internal/service`，未通过编译。当前Windows环境缺少gcc（race-test.log），不能计为竞态测试通过。Docker Linux引擎不可用，未修改180工具链或生产环境。

需要在具备C编译器的隔离Windows或Linux环境运行同一测试并保存输出。普通单测、受控4并发测试和vet不能替代race。
''')

old=load(D/'performance-v20.json'); new=load(D/'performance-v21.json')
lines=[]
for mode in ('cold','warm'):
    a=old['summaries'][mode]; b=new['summaries'][mode]
    lines.append(f"| {mode} | {a['p50_us']/1000:.2f}/{a['p95_us']/1000:.2f} | {b['p50_us']/1000:.2f}/{b['p95_us']/1000:.2f} | {a['mean_allocated_bytes']}/{b['mean_allocated_bytes']} |")
stages={}
for mode in ('cold','warm'):
    rows=[x for x in new['samples'] if x['mode']==mode]
    keys=set(k for x in rows for k in x['pipeline']['metrics'].get('stage_us',{}))
    stages[mode]={}
    for key in sorted(keys):
        vals=sorted(x['pipeline']['metrics'].get('stage_us',{}).get(key,0) for x in rows)
        stages[mode][key]={'p50_us':vals[len(vals)//2],'p95_us':vals[-1]}
save('performance-stage-summary.json',stages)
doc('performance.md','''# 性能与容量

对比本轮开始时冻结的本地v2，双方同样执行59F/23S，非早期仅一期版本。固定24个HTTP请求，15次冷、15次热，语义是确定性Stub，没有真实推理或最终LLM耗时。原始JSON及日志均保留。

| 模式 | v2 P50/P95 ms | v2.1 P50/P95 ms | v2/v2.1平均分配字节 |
|---|---:|---:|---:|
'''+ '\n'.join(lines)+'''

新版整体仍有耗时增加，不能判为性能最终通过。冷路径增加索引写入、覆盖/来源合同与不变量校验；热路径额外合同校验。阶段P50/P95见performance-stage-summary.json（阶段存在包含关系，不可简单相加）。热跑没有原始分页读取与模型重调用；token字段仅估计，真实token数未知。

分页受控容量：1000/10000实例，每实例共享500来源，单并发15次、4并发20次。10000实例单请求P95由1116.124ms降为30.024ms，4并发P95由1658.387ms降为23.539ms，平均分配由334886013降为7061225字节。20ms采样的测试进程RSS峰值约239.2→76.1MiB；不是严格瞬时峰值。完整压缩数据仍需读取验哈希。

代价：10000实例持久化由1076.576ms增至2197.541ms。完整账本与索引双写；需实际数据库容量、存储占用、并发与回滚演练，不代表生产吞吐验收通过。没有跑百万实例或180压测。

历史冻结：受控1ms单查询延迟，1/25/100快照；100快照串行179.498ms、4工作线程43.665ms，峰值4，两种配置冻结摘要一致。缺失、超预算、重复ID、取消都有显式诊断。该数字不是180网络/数据库实测。
''')

doc('remaining-issues.md','''# 未完成与限制

1. K2.7额度不足：真实23S语义准确率与最终LLM报告行为未验收；没有人工标注集。
2. race未通过：缺gcc，需隔离环境补跑。
3. 整体耗时回归、索引双写代价，生产数据库容量/并发/审计存储/回滚尚未验收。
4. 59F共同输入边界通过，但每条算法的数值边界组合并未全部新增穷举。
5. 冻结真实样本不能覆盖全部82项阳性；每条材料和执行状态见矩阵。缺材料不得当作有效阴性。
6. Prepared合同1.1明确拒绝旧1.0，旧导出需由正式预处理重新生成。缓存版本已隔离；上线前需确认迁移和回滚。
7. 审计索引保持完整性时仍读取全压缩账本校验，尚非数据库读取量随页大小恒定的实现。
''')
doc('deployment-readiness.md','''# 部署判定

不具备生产部署候选条件。本轮没有部署180、没有修改生产数据库、没有自动提交或推送。

M1–M5核心代码修复及本地合同验证通过；M8的7个冻结快照和既有C01–C07链路回归通过。M6有分页和历史冻结受控改善，但整体延迟回归且生产容量未验收；M7真实模型与race未完成。

上线前需补齐模型/人工标注、race、性能预算、实际审计存储和回滚演练。保留缺失状态与诊断，不能用Mock替代这些验收。
''')
doc('README.md',f'''# Evidence Pipeline v2.1交付

本轮已修改真实后端并完成本地增量修复，保留原有五层及59F/23S/C实现。未部署、未写生产库、未提交推送。完整验收仍有外部与性能阻断，不宣称生产可用。

1. 业务变更：Prepared1.1可执行合同、82项Go字段映射、独立无Store执行、正式/独立一致性、解释型S状态、完整归一化合同、实例IOC身份和独立观测种类、历史冻结及审计分页。详见file-changes.md和code-changes.patch（{len(changed)}个后端文件）。
2. 修复明确缺陷：旧映射NodeID与真实device_id不符；neutral/contradict混入missing；不同IOC实例ID冲突；不同通信对象时间序列混用；热缓存摘要与正式/离线不一致；整账本解压分页及串行历史冻结成本。
3. prepared-evidence.example.json可直接Decode→Execute，不需要数据库、原始报文解析或正式报告入口。复用同一执行器，完整结果与正式入口比较通过。
4. 59F受控正/反、缺材料、无效绑定、共同输入边界共295例。没有声称59个数值阈值已逐一穷举。
5. 23S受控结构验收184例；角色/终态69例。82项逐项矩阵将目录、执行、受控与真实验证分列。
6. 真实模型验收0项。本轮按用户要求停止额度不足的K2.7调用，不追问Qwen；Stub不能证明准确率。
7. 7个冻结真实快照回放通过，C01快照34复现85事件22日、10分；C02包含30组完整阴性；C03 TCP66次真实阳性；C04完整HTTP168次真实阴性。C05–C07保持协议/材料/模型诊断，不冒充语义阳性。详见real-replay-summary.json及real-replay.log。
8. 归一化验证来源索引、唯一实例、非C不加分、缺失不加分、去重和总分一致；分数仍是策略证据分，不是校准概率。
9. 构建、单测、vet、Schema外部校验通过。10000实例分页P95明显下降，但整体流水线延迟仍增加，详见performance.md。
10. 上线阻断：真实模型与人工标注、race编译工具链、整体延迟、生产容量/存储/回滚。详见remaining-issues.md及deployment-readiness.md。

主要可核查文件：architecture-delta.md、两份schema、input-field-map.json、execution-validation-matrix.csv、141份mock-fixtures、mock-execution-result.json、test-results.md、各原始测试日志。Schema和字段映射由Go导出，verify_contracts.py验证82项4493字段路径。旧输入设计草案不作为本运行合同。

增量基线：baseline-head.txt仅记录Git锚点；实际diff以本轮开始时含未提交v2工作区的914文件摘要和.local/v21-baseline副本为准，避免将既有改动冒充本轮新增。交付目录保留中间失败日志，最终结果以test-results.md列出的最终日志为准。
''')
save('artifact-hashes.json',{str(p.relative_to(D)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in D.rglob('*') if p.is_file() and p.name!='artifact-hashes.json'})
print(json.dumps({'changed_backend_files':len(changed),'matrix_rules':len(maps),'cases':len(cases),'real_snapshots':len(summary),'tests':dict(counts)}))
