"""Build the report-only 59+23 supply/execution journal from saved real reports.

This does not query or modify a database, run a model, or infer execution from
catalog registration. Missing report outputs are explicitly pending.
"""
import argparse
import collections
import json
import pathlib
import re


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--design', required=True)
    p.add_argument('--contracts', required=True)
    p.add_argument('--baseline', required=True)
    p.add_argument('--taskbook', required=True)
    p.add_argument('--reports')
    p.add_argument('--journal', help='Read-only production record export; computation is not report acceptance')
    p.add_argument('--output', required=True)
    a = p.parse_args()
    read = lambda f: json.loads(pathlib.Path(f).read_text(encoding='utf-8-sig'))
    design, contracts, baseline = read(a.design), read(a.contracts), read(a.baseline)
    fields = {}
    for line in pathlib.Path(a.taskbook).read_text(encoding='utf-8').splitlines():
        if line.startswith('| F_'):
            cells = [x.strip() for x in line.split('|')[1:-1]]
            key = re.search(r'F_[A-Z_]+', cells[0]).group()
            fields[key] = cells[-1]
    families = {(x['layer'], x['input']): x for x in baseline['families']}
    runtime = collections.defaultdict(list)
    reports = []
    computed = collections.defaultdict(list)
    if a.journal:
        records = [json.loads(line) for line in pathlib.Path(a.journal).read_text(encoding='utf-8').splitlines()]
        versions = {}
        def adapter(record):
            value = record['value']
            return value.get('manifest', {}).get('adapter_version', value.get('adapter_version', ''))
        def version_order(version):
            return tuple(int(x) for x in version.rsplit('-', 1)[-1].split('.'))
        for record in records:
            version = adapter(record)
            if record['kind'] in ('evidence_result', 'semantic_result') and (version.startswith('report-snapshot-adapter-') or version.startswith('snapshot-semantic-adapter-1.3')):
                key = (record['kind'], record['group'])
                versions[key] = max(versions.get(key, ()), version_order(version))
        for record in records:
            value = record['value']
            if record['kind'] not in ('evidence_result', 'semantic_result'):
                continue
            version = value.get('manifest', {}).get('adapter_version', value.get('adapter_version', ''))
            if not (version.startswith('report-snapshot-adapter-') or version.startswith('snapshot-semantic-adapter-1.3')):
                continue
            if version_order(version) != versions[(record['kind'], record['group'])]:
                continue
            result = value.get('result') or {}
            ref = {'event_id': record['group'], 'record_key': record['key'], 'adapter_version': version,
                   'snapshot_version': result.get('snapshot_version', result.get('plan', {}).get('snapshot_version')),
                   'report_id': None, 'acceptance': 'computed_not_report_acceptance'}
            if record['kind'] == 'evidence_result':
                executions = result.get('execution_plan', [])
                for finding in result.get('algorithm_findings', []):
                    matches = [x for x in executions if x['fact_id'] == finding['fact_id'] and x.get('scope') == finding.get('scope')]
                    computed[finding['fact_id']].append({**ref, **finding, 'execution': matches})
            else:
                findings = {x['task_id']: x for x in result.get('semantic_findings', [])}
                for execution in result.get('plan', {}).get('executions', []):
                    slot = execution['slot']; key = slot['id'] + '/' + slot.get('subtype', '')
                    computed[key].append({**ref, **execution, 'finding': findings.get(execution.get('task_id'))})
    if a.reports:
        for file in sorted(pathlib.Path(a.reports).glob('*-report.json')):
            obj = read(file)
            doc = obj.get('data', obj)
            if not isinstance(doc, dict) or not doc.get('evidence'):
                continue
            report_ref = {'event_id': doc['event_id'], 'report_id': doc.get('summary_id'),
                          'snapshot_version': doc['evidence']['snapshot_version'],
                          'build_revision': doc.get('build_revision'), 'file': file.name}
            reports.append(report_ref)
            for item in doc['evidence'].get('normalized_evidence', {}).get('items', []):
                key = item['rule_id'] if item['kind'] == 'fact' else item['rule_id'].split('/')[0] + '/' + item['rule_id'].split('/')[-1]
                runtime[key].append({**report_ref, **item})
    original = {x['fact_id']: x for x in design['facts']}
    rows = []
    for rule in contracts['facts']:
        key = rule['fact_id']
        required = rule['inputs']
        rows.append({'id': key, 'kind': 'fact', 'name': rule['name'],
                     'original_fields': original[key]['data_required'],
                     'algorithm': rule['definition'], 'execution_contract': fields[key],
                     'material_families': required,
                     'baseline_supply': [families[('fact', x)] for x in required],
                     'current_reader': 'traffic/internal/service/evidence_report_input.go → SnapshotEvidenceInput → report/history adapter → evidence.Engine',
                     'storage': 'traffic_event_hits(raw_json)+固定快照；traffic_aggregation_records(evidence_inputs/evidence_sources)；events历史只读；现有PCAP/交换报文',
                     'execution': runtime[key], 'production_computations': computed[key],
                     'actual_status': 'pending_real_report' if not runtime[key] else dict(collections.Counter(x.get('execution_status') or x['status'] for x in runtime[key]))})
    definitions = {x['key']['id'] + '/' + x['key'].get('subtype', ''): x for x in contracts['semantic_definitions']}
    for rule in contracts['semantic_contracts']:
        slot = rule['slot']; key = slot['id'] + '/' + slot.get('subtype', '')
        rows.append({'id': key, 'kind': 'semantic', 'name': definitions[key]['prerequisite'],
                     'target': slot['target'], 'original_fields': rule['material_kinds'],
                     'required_positive_facts': {'all': rule['all_facts'], 'any': rule['any_facts']},
                     'baseline_supply': [families[('semantic', x)] for x in rule['material_kinds']],
                     'current_reader': 'evidence_semantic_input.go → prepareReportSemantics → SemanticEngine.Plan/Evaluate → 引用/逐字摘录核验',
                     'storage': '同一次固定快照读取+已有目录/历史；semantic_materials、semantic_model_input、semantic_result、semantic_diagnostics',
                     'execution': runtime[key], 'production_computations': computed[key],
                     'actual_status': 'pending_real_report' if not runtime[key] else dict(collections.Counter(x['status'] for x in runtime[key]))})
    assert len(rows) == 82 and len(original) == 59
    out = {'purpose': '逐项原设计、读取位置及真实执行记录；注册或合成测试不算生产完成',
           'baseline_date': baseline['audit_date'], 'baseline_note': '供应分类来自2026-10-10固定样本审计，不冒充本轮运行状态；本轮以execution字段为准',
           'computation_note': '每事件/层取实际存在的最高适配器版本；缺少当前部署版结果时不冒称已运行新版。生产计算不是报告发布或业务验收。record_key可回查完整不可变记录。',
           'report_history_override': '报告专用参数参考全部匹配历史；默认语义目录键保持兼容，送达R06/R07为活动关联和替代解释',
           'reports': reports, 'items': rows}
    target = pathlib.Path(a.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
    md = ['# 59事实与23语义：材料供应及真实执行矩阵', '', out['baseline_note'], '',
          '| ID | 原字段/材料 | 执行所需条件 | 已发布报告状态 | 生产计算状态（版本分开） | 缺口及来源 |',
          '|---|---|---|---|---|---|']
    for row in rows:
        gaps = '; '.join(x['input'] + ':' + x['reason'] for x in row['baseline_supply'] if x['status'] != 'recoverable')
        condition = row.get('execution_contract', row.get('name', ''))
        statuses = collections.defaultdict(collections.Counter)
        for instance in row['production_computations']:
            statuses[instance['adapter_version']][instance.get('status', 'unknown') + ':' + instance.get('reason_code', instance.get('reason', ''))] += 1
        values = [row['id'], ', '.join(row['original_fields']), condition,
                  str(row['actual_status']), '; '.join(v + ':' + str(dict(c)) for v, c in sorted(statuses.items())), gaps]
        md.append('| ' + ' | '.join(str(v).replace('|', '\\|').replace('\n', ' ') for v in values) + ' |')
    md += ['', '全部实例、指标、参数、范围、来源与报告ID见同名JSON；待生成状态不计完成。',
           '范围外依赖：正常流量分母/基线、实际角色与作息、授权工单、品牌/服务/基础设施及信任目录、群体/战役/阶段证明、合法应用明文等；不通过修改采集或数据库结构在本期补造。']
    target.with_suffix('.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    print(json.dumps({'items': len(rows), 'real_reports': len(reports)}))


if __name__ == '__main__':
    main()
