"""Offline draft-contract validation, not an F/S algorithm or a production adapter."""
import base64
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

HERE = Path(__file__).resolve().parent
SCHEMA = json.loads((HERE/'input.schema.json').read_text(encoding='utf-8'))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

def payload(artifact):
    return (artifact['content'].encode('utf-8') if artifact['encoding']=='utf8'
            else base64.b64decode(artifact['content'], validate=True))

def validate(bundle):
    errors = [str(e.json_path)+': '+e.message for e in VALIDATOR.iter_errors(bundle)]
    if errors:
        return errors
    def check(ok, message):
        if not ok: errors.append(message)
    ids = {}
    families = {}
    records = []
    for family in ('snapshots','sources','windows','scopes','indicators','coverage','artifacts'):
        for row in bundle[family]:
            key=row['id']; check(key not in ids,'duplicate ID: '+key)
            ids[key]=row; families[key]=family
    for family,rows in dict(bundle['datasets'], relations=bundle['relations']).items():
        for row in rows:
            key=row['meta']['id']; check(key not in ids,'duplicate ID: '+key)
            ids[key]=row; families[key]=family; records.append((family,row))
    ref_families={'source_id':'sources','source_ids':'sources','identity_source_ids':'sources',
        'duplicate_source_ids':'sources','snapshot_ref':'snapshots','source_snapshot_refs':'snapshots',
        'window_ref':'windows','training_window_ref':'windows','scope_ref':'scopes',
        'coverage_ref':'coverage','indicator_ref':'indicators','indicator_refs':'indicators',
        'chunk_refs':'transfer_chunks','transaction_ref':'http_transactions',
        'connection_ref':'connections','connection_refs':'connections','session_ref':'sessions',
        'contact_refs':'contacts','binding_refs':'ioc_bindings','decode_chain_ref':'decode_chains',
        'trust_reference_ref':'tls_references','authorization_ref':'authorizations',
        'stage_proof_ref':'stage_campaign_proofs','campaign_proof_ref':'stage_campaign_proofs',
        'response_pair_ref':'relations','redirect_link_refs':'relations'}
    def refs(node):
        if isinstance(node,list):
            for x in node: refs(x)
        elif isinstance(node,dict):
            for k,v in node.items():
                if k.endswith('_ref') or k.endswith('_refs') or k in ref_families:
                    for value in (v if isinstance(v,list) else [v]):
                        if value is None: continue
                        check(value in ids,'unresolved '+k+': '+str(value))
                        expected = 'artifacts' if 'artifact_ref' in k else ref_families.get(k)
                        if expected and value in ids:
                            check(families[value]==expected,'wrong reference family '+k+': '+value)
                else: refs(v)
    refs(bundle)
    if errors: return errors
    for w in bundle['windows']:
        check(datetime.fromisoformat(w['start'].replace('Z','+00:00')) < datetime.fromisoformat(w['end'].replace('Z','+00:00')),'invalid window '+w['id'])
    for a in bundle['artifacts']:
        try:
            raw=payload(a)
            check(len(raw)==a['byte_length'],'artifact byte length mismatch '+a['id'])
            check(hashlib.sha256(raw).hexdigest()==a['sha256'],'artifact hash mismatch '+a['id'])
        except Exception:
            errors.append('invalid artifact encoding '+a['id'])
    coverage_counts={c['id']:0 for c in bundle['coverage']}
    dedup=set()
    def resolve_field(data,path):
        for key in path.split('.'):
            if not isinstance(data,dict) or key not in data: return None
            data=data[key]
        return data
    for family,row in records:
        m,d=row['meta'],row['data'];c=ids[m['coverage_ref']]
        coverage_counts[c['id']]+=1
        check((c['family'],c['scope_ref'],c['window_ref'])==(family,m['scope_ref'],m['window_ref']),'coverage identity mismatch '+m['id'])
        check(c['indicator_ref'] is None or c['indicator_ref'] in m['indicator_refs'],'coverage indicator mismatch '+m['id'])
        for fs in m['field_sources']:
            check(fs['source_id'] in m['source_ids'],'field provenance outside record sources '+m['id'])
            check(resolve_field(d,fs['field']) is not None,'unknown field provenance '+m['id']+': '+fs['field'])
        if family=='ioc_bindings':
            observation=ids[d['observation_ref']];indicator=ids[d['indicator_ref']];scope=ids[m['scope_ref']]
            check('data' in observation,'IOC observation must be a typed record')
            if 'data' in observation:
                check(resolve_field(observation['data'],d['field_path'])==d['observed_value'],'IOC original field value mismatch '+m['id'])
                check(observation['meta']['scope_ref']==m['scope_ref'],'IOC observation scope mismatch '+m['id'])
            check(d['observed_type']==indicator['type'] and d['observed_value']==indicator['value'],'IOC value/type mismatch '+m['id'])
            check((d['asset_id'],d['device_id'],d['remote_endpoint'])==(scope['asset_id'],scope['device_id'],scope['endpoint']),'IOC asset/device/endpoint mismatch '+m['id'])
        if family=='contacts':
            expected={'tcp_connection':'connections','http_transaction':'http_transactions','dns_transaction':'dns_transactions'}[d['kind']]
            check(families[d['observation_ref']]==expected,'contact is not an independent '+expected)
            key=(m['scope_ref'],tuple(sorted(m['indicator_refs'])),d['kind'],d['dedup_key'])
            check(key not in dedup,'duplicate contact '+m['id']);dedup.add(key)
        if family in ('content_classifications','transfer_chunks'):
            http=ids[d['transaction_ref']]['data'];a=ids[d['artifact_ref']]
            check(d['artifact_ref']==http['request']['body_artifact_ref'],'payload is not this HTTP request body '+m['id'])
            check(a['visibility']=='plaintext' and a['complete'],'unreadable/incomplete semantic payload '+m['id'])
            if family=='transfer_chunks':
                check(d['bytes']==a['byte_length'] and d['bytes']==http['request']['body_bytes'],'chunk volume mismatch '+m['id'])
            else:
                for span in d['spans']:
                    check(span['offset_bytes']+span['length_bytes']<=a['byte_length'],'classification span out of bounds '+m['id'])
        if family=='transfer_links':
            chunks=[ids[x]['data'] for x in d['chunk_refs']]
            check(len({x['transaction_ref'] for x in chunks})==len(chunks),'transfer needs distinct transactions')
            check(len({x['sequence'] for x in chunks})==len(chunks),'transfer needs distinct sequences')
            check(all(x['transfer_id']==d['transfer_id'] for x in chunks),'transfer identity mismatch')
            check(d['join_verified'],'unverified transfer join')
        if family=='decode_chains':
            previous=None
            for step in d['steps']:
                ia,oa=ids[step['input_artifact_ref']],ids[step['output_artifact_ref']]
                check(ia['visibility']=='plaintext' and oa['visibility']=='plaintext','ciphertext cannot be a plaintext decode')
                check(ia['complete'] and oa['complete'],'incomplete decode chain')
                check(previous is None or previous==ia['id'],'broken decode continuity')
                try:
                    raw=payload(ia)
                    decoded={'hex':lambda:bytes.fromhex(raw.decode('ascii')),
                        'base32':lambda:base64.b32decode(raw), 'base64':lambda:base64.b64decode(raw,validate=True),
                        'base64url':lambda:base64.b64decode(raw,altchars=b'-_',validate=True)}[step['encoding']]()
                    check(decoded==payload(oa) and step['roundtrip_verified'],'decode output mismatch')
                    if previous is None:
                        origin=ids[d['origin_observation_ref']]
                        value=resolve_field(origin.get('data',{}),d['origin_field_path'])
                        origin_bytes=value.encode('utf8') if isinstance(value,str) else b''
                        if d['origin_slice']:
                            part=d['origin_slice'];offset=part['offset_bytes'];length=part['length_bytes']
                            check(offset+length<=len(origin_bytes),'decode origin slice out of bounds')
                            origin_bytes=origin_bytes[offset:offset+length]
                        check(origin_bytes==raw,'decode origin field mismatch')
                except Exception: errors.append('decode failed '+m['id'])
                previous=oa['id']
        if family=='semantic_materials':
            a=ids[d['artifact_ref']]
            check(a['visibility']=='plaintext','semantic material is not plaintext '+m['id'])
            if d['decode_chain_ref']:
                chain=ids[d['decode_chain_ref']]['data']
                check(chain['origin_observation_ref']==d['observation_ref'] and chain['origin_field_path']==d['field_path'],'semantic decode origin mismatch')
                check(chain['steps'][-1]['output_artifact_ref']==d['artifact_ref'],'semantic decode artifact mismatch')
    for c in bundle['coverage']:
        check(c['loaded_records']==coverage_counts[c['id']],'coverage loaded count mismatch '+c['id'])
        if c['availability']!='available':
            check(c['loaded_records']==0 and c['population_completeness']!='complete','unavailable population cannot be complete '+c['id'])
        if c['population_completeness']=='complete':
            check(bool(c['denominator_description']),'complete population needs denominator '+c['id'])
            if c['expected_records'] is not None:
                check(c['expected_records']==c['loaded_records']+c['excluded_records']+c['duplicate_records'],'complete population count mismatch '+c['id'])
        if c['content_completeness']=='complete':
            check(not c['missing_fields'],'complete content declares missing fields '+c['id'])
    return errors

if __name__=='__main__':
    failed=False
    for name in sys.argv[1:]:
        errors=validate(json.loads(Path(name).read_text(encoding='utf-8')))
        print(name+': '+('PASS' if not errors else '\n  '+'\n  '.join(errors)))
        failed=failed or bool(errors)
    sys.exit(1 if failed else 0)
