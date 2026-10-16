"""Build the proposed input contract from evidence needs, not service structs.
Run from any directory. Does not change application code or query any service.
"""
from pathlib import Path
import csv
import json
import re

OUT = Path(__file__).resolve().parent
ROOT = OUT.parent.parent
CATALOG = ROOT / 'docs/evidence-pipeline-v2/catalog-input-contracts.json'
VERSION = 'evidence-input-1.0.0'

def obj(props, required=None):
    return {'type': 'object', 'additionalProperties': False,
            'properties': props, 'required': list(props) if required is None else required}

def arr(item, minimum=0):
    return {'type': 'array', 'items': item, 'minItems': minimum}

def ref(name):
    return {'$ref': '#/$defs/' + name}

def enum(*values):
    return {'enum': list(values)}

def nullable(value):
    return {'anyOf': [value, {'type': 'null'}]}

S = {'type': 'string'}
ID = {'type': 'string', 'minLength': 1}
N = {'type': 'number'}
U = {'type': 'integer', 'minimum': 0}
T = {'type': 'string', 'format': 'date-time'}
B = {'type': 'boolean'}
IDS = arr(ID)
M = lambda p: {k: nullable(v) for k, v in p.items()}

defs = {
    'window': obj({'id': ID, 'start': T, 'end': T, 'timezone': ID,
                   'boundary': {'const': '[start,end)'}}),
    'snapshot': obj({'id': ID, 'event_id': ID, 'version': U, 'watermark': U,
                     'revision_watermark': U, 'as_of': T}),
    'source': obj({'id': ID, 'kind': enum('packet', 'flow', 'http_log', 'dns_log',
                    'event', 'registry', 'baseline', 'adjudication', 'configuration'),
                   'snapshot_ref': nullable(ID), 'origin': ID, 'record_key': ID,
                   'version': ID, 'sha256': nullable({'type': 'string', 'pattern': '^[a-f0-9]{64}$'})}),
    'scope': obj({'id': ID, 'kind': enum('asset_endpoint', 'asset', 'asset_group', 'reference'),
                  'asset_id': nullable(ID), 'device_id': nullable(ID),
                  'endpoint': nullable(obj({'transport': enum('tcp', 'udp'), 'ip': ID, 'port': {'type': 'integer', 'minimum': 1, 'maximum': 65535}})),
                  'group_id': nullable(ID), 'identity_source_ids': IDS}),
    'indicator': obj({'id': ID, 'type': enum('ip', 'domain', 'url', 'hash', 'other'),
                      'value': ID, 'upstream_labels': arr(S), 'source_ids': arr(ID, 1)}),
    'field_source': obj({'field': ID, 'source_id': ID, 'source_field': ID}),
    'coverage': obj({'id': ID, 'family': ID, 'scope_ref': ID, 'window_ref': ID,
                     'indicator_ref': nullable(ID),
                     'population': enum('saved_alert_matches', 'independent_contacts', 'dns_transactions',
                          'http_transactions', 'connection_attempts', 'sessions', 'historical_events', 'reference_records', 'supplied_materials'),
                     'selection': ID, 'source_snapshot_refs': IDS,
                     'availability': enum('available', 'unavailable', 'not_applicable'),
                     'population_completeness': enum('complete', 'partial', 'unknown'),
                     'content_completeness': enum('complete', 'partial', 'unknown'),
                     'expected_records': nullable(U), 'loaded_records': U,
                     'excluded_records': U, 'duplicate_records': U,
                     'missing_fields': arr(S), 'reason_codes': arr(S),
                     'denominator_description': nullable(S)}),
    'meta': obj({'id': ID, 'scope_ref': ID, 'window_ref': ID,
                 'indicator_refs': IDS, 'coverage_ref': ID, 'source_ids': arr(ID, 1),
                 'producer': obj({'name': ID, 'version': ID}),
                 'verification': enum('verified', 'unverified', 'conflicted'),
                 'verification_checks': arr(S), 'missing_fields': arr(S),
                 'field_sources': arr(ref('field_source'), 1)}),
    'artifact': obj({'id': ID, 'source_ids': arr(ID, 1), 'source_field': ID,
                     'media_type': ID, 'visibility': enum('plaintext', 'ciphertext', 'metadata'),
                     'encoding': enum('utf8', 'base64'), 'content': S,
                     'byte_length': U, 'sha256': {'type': 'string', 'pattern': '^[a-f0-9]{64}$'},
                     'complete': B, 'redacted': B}),
}

direction = enum('outbound', 'inbound', 'unknown')
endpoint = obj({'transport': enum('tcp', 'udp'), 'ip': ID, 'port': {'type': 'integer', 'minimum': 1, 'maximum': 65535}})
metric = obj({'value': N, 'unit': ID, 'statistic': ID})
header = obj({'name': ID, 'value': S})
http_field = obj({'name': ID, 'location': enum('query', 'body', 'header'), 'value_artifact_ref': nullable(ID), 'value_redacted': B})

# Each family has a concrete payload schema; no opaque map[string]any payload.
FAMILIES = {
 'alert_matches': obj({'hit_id': ID, 'occurred_at': T, 'rule_id': ID, 'rule_family': nullable(S), 'observation_ref': nullable(ID)}),
 'ioc_bindings': obj({'indicator_ref': ID, 'observation_ref': ID, 'field_path': ID, 'observed_type': ID,
                      'observed_value': ID, 'asset_id': ID, 'device_id': ID, 'remote_endpoint': nullable(endpoint), 'direction': direction}),
 'contacts': obj({'contact_id': ID, 'occurred_at': T, 'kind': enum('tcp_connection', 'dns_transaction', 'http_transaction'),
                  'observation_ref': ID, 'dedup_key': ID, 'duplicate_source_ids': IDS,
                  'packets_per_contact': nullable(U), 'application_payload_bytes': nullable(U)}),
 'dns_transactions': obj({'transaction_id': ID, 'question_at': T, 'response_at': nullable(T), 'question_name_raw': ID,
                          'question_name_ascii': ID, 'registrable_domain': nullable(ID), 'psl_version': ID,
                          'qtype': ID, 'rcode': nullable(U), 'answers': arr(obj({'type': ID, 'value': ID})),
                          'request_artifact_ref': nullable(ID), 'response_artifact_ref': nullable(ID),
                          'connection_refs': IDS, 'retransmission_key': ID}),
 'http_transactions': obj({'transaction_id': ID, 'session_ref': nullable(ID), 'connection_ref': nullable(ID),
       'request_at': T, 'response_at': nullable(T), 'direction': direction,
       'request': obj({'method': ID, 'url_raw': ID, 'scheme': ID, 'host_ascii': ID, 'authority': ID,
                       'path_escaped': ID, 'query_raw': S, 'user_agent': nullable(S), 'headers': arr(header),
                       'fields': arr(http_field), 'body_bytes': nullable(U), 'raw_artifact_ref': ID,
                       'body_artifact_ref': nullable(ID), 'completeness': enum('complete', 'partial', 'unknown'),
                       'assembly': enum('complete_message', 'verified_reassembly', 'fragment'),
                       'encoding_summary': nullable(obj({'total_fields': U, 'encoded_fields': U, 'longest_encoded_field': U}))}),
       'response': nullable(obj({'status': U, 'headers': arr(header), 'location': nullable(S), 'raw_artifact_ref': ID,
                                 'body_artifact_ref': nullable(ID), 'completeness': enum('complete', 'partial', 'unknown')})),
       'response_pair_ref': nullable(ID), 'redirect_link_refs': IDS, 'form_action': nullable(S), 'declared_brand': nullable(S)}),
 'connections': obj({'connection_id': ID, 'started_at': T, 'ended_at': nullable(T),
                      'source_ip': ID, 'source_port': U, 'destination': endpoint,
                      'application_protocol': nullable(S), 'protocol_basis': enum('parsed', 'fingerprint', 'unknown'),
                      'direction': direction, 'outcome': enum('success', 'failure', 'pending', 'unknown'),
                      'outcome_basis': nullable(S), 'outcome_verified': B, 'tcp_state': nullable(S),
                      'payload_bytes': nullable(U), 'session_ref': nullable(ID)}),
 'sessions': obj({'session_id': ID, 'started_at': T, 'ended_at': T, 'connection_refs': arr(ID, 1),
                   'contact_refs': IDS, 'up_bytes': nullable(U), 'down_bytes': nullable(U),
                   'volume_basis': nullable(S), 'volume_verified': B}),
 'tls_handshakes': obj({'handshake_id': ID, 'occurred_at': T, 'connection_ref': ID,
                        'sni': nullable(S), 'certificate_names': arr(S), 'certificate_artifact_refs': IDS,
                        'not_before': nullable(T), 'not_after': nullable(T), 'issuer': nullable(S),
                        'chain_verification': enum('valid', 'invalid', 'unknown'),
                        'trust_reference_ref': nullable(ID), 'fingerprint': nullable(S),
                        'fingerprint_type': nullable(enum('ja3', 'ja4', 'other')), 'declared_user_agent': nullable(S)}),
 'history_events': obj({'historical_event_id': ID, 'occurred_at': T, 'last_at': T,
                        'asset_ids': arr(ID), 'device_id': nullable(ID), 'indicator_refs': IDS,
                        'endpoint': nullable(endpoint), 'observation_kind': ID, 'activity_type': ID,
                        'rule_family': nullable(S), 'family': nullable(S), 'snapshot_ref': ID,
                        'binding_refs': IDS, 'group_id': nullable(ID), 'member_asset_ids': IDS,
                        'adjudication': nullable(obj({'id': ID, 'value': enum('malicious', 'false_positive', 'unreviewed'), 'authority': ID, 'source_ids': arr(ID,1)})),
                        'stage_proof_ref': nullable(ID), 'campaign_proof_ref': nullable(ID),
                        'coordination_parameters': {'type':'object','additionalProperties':metric}}),
 'group_memberships': obj({'group_id': ID, 'asset_id': ID, 'device_id': ID,
                           'addresses': arr(ID,1), 'subnet': nullable(S), 'role': nullable(S),
                           'identity_basis': ID, 'nat_proxy_dedup_key': ID, 'membership_verified': B,
                           'observation_refs': arr(ID,1)}),
 'authorizations': obj({'authorization_id': ID, 'effective_start': T, 'effective_end': T,
                       'asset_id': ID, 'endpoint': nullable(endpoint), 'domains': arr(S), 'role': ID,
                       'task_type': ID, 'ports': arr(U), 'protocols': arr(ID), 'targets': arr(ID)}),
 'baselines': obj({'baseline_id': ID, 'version': ID, 'rule_ids': arr(ID,1),
                   'population_definition': ID, 'dimension_key': ID, 'training_window_ref': ID,
                   'sample_count': U, 'metrics': {'type':'object','additionalProperties':metric},
                   'frequencies': {'type':'object','additionalProperties':{'type':'number','minimum':0,'maximum':1}}}),
 'brand_references': obj({'brand_id': ID, 'display_name': ID, 'authorized_domains': arr(ID,1),
                          'effective_start': T, 'effective_end': T, 'normalization_version': ID}),
 'service_references': obj({'service_id': ID, 'transport': enum('tcp','udp'), 'port': U, 'application_protocol': ID}),
 'infrastructure_references': obj({'ip': ID, 'asn': ID, 'country': ID, 'reputation_label': ID, 'as_of': T}),
 'tls_references': obj({'reference_id': ID, 'cdn_exception_patterns': arr(S), 'trusted_issuers': arr(S),
                        'trust_root_artifact_refs': IDS, 'fingerprint_clients': {'type':'object','additionalProperties':ID},
                        'cdn_exceptions_verified': B, 'issuers_verified': B, 'fingerprints_verified': B}),
 'lexical_references': obj({'corpus_id': ID, 'language': ID, 'normalization_version': ID,
                            'bigram_log_probabilities': {'type':'object','additionalProperties':{'type':'number','maximum':0}}}),
 'domain_patterns': obj({'pattern_id': ID, 'expression': ID, 'engine': ID, 'normalization_version': ID}),
 'rule_origins': obj({'rule_id': ID, 'independence_group': ID, 'original_source': ID, 'hit_refs': arr(ID,1)}),
 'intel_origins': obj({'indicator_ref': ID, 'original_source': ID, 'upstream_type_labels': arr(S), 'record_id': ID}),
 'decode_chains': obj({'origin_observation_ref': ID, 'origin_field_path': ID,
                       'origin_slice': nullable(obj({'offset_bytes': U, 'length_bytes': U})),
                       'steps': arr(obj({'encoding': enum('hex','base32','base64','base64url'),
                                        'input_artifact_ref': ID, 'output_artifact_ref': ID,
                                        'decoder_version': ID, 'roundtrip_verified': B}),1)}),
 'semantic_materials': obj({'subject_id': ID, 'proposition_id': ID, 'kind': ID,
                           'artifact_ref': ID, 'field_path': ID, 'observation_ref': nullable(ID),
                           'transaction_id': nullable(ID), 'direction': direction, 'protocol': nullable(S),
                           'method': nullable(S), 'destination': nullable(S), 'related_record_refs': IDS,
                           'decode_chain_ref': nullable(ID), 'adjudication_id': nullable(ID),
                           'field_names': arr(S), 'bytes': nullable(U), 'sequence': nullable(U)}),
 'content_classifications': obj({'transaction_ref': ID, 'artifact_ref': ID,
                                 'category': ID, 'method': enum('code','dlp','human'), 'classifier_version': ID,
                                 'spans': arr(obj({'offset_bytes': U, 'length_bytes': U, 'basis': ID}),1),
                                 'explanation': ID}),
 'transfer_chunks': obj({'transfer_id': ID, 'transaction_ref': ID, 'sequence': U,
                         'bytes': U, 'artifact_ref': ID, 'direction': direction, 'sequence_basis': ID}),
 'transfer_links': obj({'transfer_id': ID, 'chunk_refs': arr(ID,2), 'join_method': ID,
                        'join_key': ID, 'join_verified': B}),
 'business_schedules': obj({'asset_id': ID, 'role': ID, 'timezone': ID,
                            'effective_start': T, 'effective_end': T,
                            'weekly_windows': arr(obj({'weekday': {'type':'integer','minimum':1,'maximum':7},
                                                       'start_minute': U,'end_minute': U})), 'authorization_ref': nullable(ID)}),
 'stage_campaign_proofs': obj({'proof_type': enum('stage','campaign','coordination_parameters'),
                              'asset_ids': IDS, 'indicator_refs': IDS, 'group_id': nullable(ID),
                              'member_asset_ids': IDS, 'stage': nullable(S), 'campaign_id': nullable(ID),
                              'adjudication_id': nullable(ID), 'authority': ID,
                              'parameters': {'type':'object','additionalProperties':metric}}),
}

relations = obj({'meta':ref('meta'), 'data':obj({'kind':enum('dns_answer_connection','http_request_response','http_redirect','session_contact','stratum_request_response'),
                 'from_ref':ID,'to_ref':ID,'method':ID,'verified':B,'attributes':arr(obj({'name':ID,'value':S}))})})
schema = {
 '$schema':'https://json-schema.org/draft/2020-12/schema', '$id':'urn:warningplatform:evidence-input:1.0.0',
 'title':'Evidence algorithm inputs designed from the 59F/23S data requirements',
 **obj({'schema_version':{'const':VERSION}, 'bundle_id':ID,
        'producer':obj({'name':ID,'version':ID}), 'created_at':T,
        'event':obj({'event_id':ID,'occurred_at':T,'indicator_refs':IDS}),
        'snapshots':arr(ref('snapshot'),1),'sources':arr(ref('source')),
        'windows':arr(ref('window'),1),'scopes':arr(ref('scope'),1),
        'indicators':arr(ref('indicator')),'coverage':arr(ref('coverage'),1),
        'artifacts':arr(ref('artifact')), 'relations':arr(relations),
        'datasets':obj({k:arr(obj({'meta':ref('meta'),'data':v})) for k,v in FAMILIES.items()}),
        'diagnostics':arr(obj({'code':ID,'family':nullable(ID),'scope_ref':nullable(ID),
                               'coverage_ref':nullable(ID),'source_ids':IDS,'message':ID}))}),
 '$defs':defs
}

def write(name,value):
    (OUT/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

if __name__ == '__main__':
    write('input.schema.json',schema)
    write('data-dictionary.json',{'schema_version':VERSION,'record_envelope':defs['meta'],
          'coverage':defs['coverage'],'families':FAMILIES,
          'note':'All payload properties must be represented; nullable fields express unknown, not zero or false. Per-rule requirements determine usability.'})
    print('schema families:',len(FAMILIES))
