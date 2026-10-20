"""Compare independent CLI runs, explicitly excluding runtime-only values."""
import argparse
import copy
import json
from pathlib import Path

SCENARIOS = ['c2', 'botnet', 'phishing', 'network-activity']

def normalized_result(value):
    value = copy.deepcopy(value)
    value['Context'] = json.loads(value['Context'])
    context = value['Context']
    context.get('phase_one_evidence', {}).pop('cache_key', None)
    manifest = context.get('input_manifest', {})
    manifest.get('semantic_evidence', {}).pop('result_key', None)
    manifest.get('algorithm_evidence', {}).pop('evidence_result_key', None)
    semantics = value['Semantics']
    semantics.pop('result_key', None)
    semantics.pop('elapsed_ms', None)
    for batch in semantics.get('result', {}).get('batches', []):
        batch.pop('elapsed_ms', None)
    pipeline = value['Evidence']['pipeline']
    pipeline.pop('key', None)
    pipeline.pop('elapsed_ms', None)
    pipeline.get('metrics', {}).pop('stage_ms', None)
    pipeline.get('metrics', {}).pop('stage_us', None)
    value['Evidence']['phase_one'].pop('cache_key', None)
    return value

def normalized_bundle(value):
    value = copy.deepcopy(value)
    # CLI MemoryStore initialization assigns time.Now independently per run.
    # Only these registry/event update timestamps and their digest are ignored.
    value.pop('input_digest')
    value['event'].pop('updated_at', None)
    for asset in value['assets']:
        asset.pop('created_at', None)
        asset.pop('updated_at', None)
    return value

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    results = []
    for scenario in SCENARIOS:
        for file, normalize in [('prepared-bundle.json', normalized_bundle),
                                ('normalized-result.json', normalized_result),
                                ('coverage-proof-matrix.json', lambda x: x)]:
            before, after = [json.loads((args.directory / phase / scenario / file).read_text(encoding='utf-8'))
                             for phase in ['before', 'after']]
            equal = normalize(before) == normalize(after)
            results.append({'scenario': scenario, 'artifact': file, 'equal': equal})
    report = {'passed': all(x['equal'] for x in results), 'comparisons': results,
              'excluded': ['CLI-created event/asset timestamps and resulting bundle digest',
                           'pipeline stage durations, semantic batch durations and cache keys'],
              'retained': 'All Bundle inputs, findings, reasons, source relations, semantic results, scores and coverage proofs'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'comparisons': len(results)}))
    if not report['passed']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
