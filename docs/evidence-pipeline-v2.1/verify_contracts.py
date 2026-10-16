"""Validate real Go-generated schemas, fixtures and all 82 generated field maps."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

HERE=Path(__file__).resolve().parent

def load(name):
    return json.loads((HERE/name).read_text(encoding='utf-8-sig'))

def check():
    prepared=load('prepared-evidence.schema.json')
    results=[]
    for schema_name,data_name in [('prepared-evidence.schema.json','prepared-evidence.example.json'),
                                   ('normalized-evidence.schema.json','mock-execution-result.json')]:
        schema=load(schema_name);Draft202012Validator.check_schema(schema)
        errors=list(Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(load(data_name)))
        assert not errors, [(e.json_path,e.message) for e in errors[:5]]
        results.append({'schema':schema_name,'example':data_name,'passed':True})
    def expand(node):
        if '$ref' in node:
            return expand(prepared['$defs'][node['$ref'].split('/')[-1]])
        if 'anyOf' in node:
            return expand(next(x for x in node['anyOf'] if x.get('type')!='null'))
        return node
    mappings=load('input-field-map.json')
    assert len(mappings)==82 and len({r['id'] for r in mappings})==82
    paths=0
    for row in mappings:
        for path in row['available_typed_field_paths']+row['scope_fields']:
            node=prepared
            for part in path.split('.'):
                node=expand(node)
                key=part[:-2] if part.endswith('[]') else part
                if key=='*':
                    node=node['additionalProperties']
                else:
                    assert key in node.get('properties',{}),(row['id'],path,key)
                    node=node['properties'][key]
                if part.endswith('[]'):
                    node=expand(node)['items']
            paths+=1
    result={'schema_tests':results,'mapped_rules':82,'resolved_paths':paths,
            'claim':'wire shape and real Go field resolution; not supplier completeness or model accuracy'}
    (HERE/'schema-verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':
    check()
