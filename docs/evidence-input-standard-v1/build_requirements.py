"""Explicit rule-to-field requirements for the proposed input standard."""
from build_standard import OUT, ROOT, FAMILIES, write, VERSION
import csv
import json
import hashlib

R = {}
def rule(name, families, joins='', parameters=(), baselines=(), note=''):
    assert name not in R
    R[name] = {'required_inputs':[{'family':f,'fields':fields.split()} for f,fields in families.items()],
               'association_constraints':joins.split(';') if joins else [],
               'parameter_keys':list(parameters),'baseline_metric_keys':list(baselines), 'special_condition':note}

C = 'contact_id occurred_at kind observation_ref dedup_key'
D = 'transaction_id question_at question_name_raw question_name_ascii registrable_domain psl_version'
H = 'transaction_id request_at request.method request.url_raw request.host_ascii request.path_escaped request.raw_artifact_ref request.completeness request.assembly'
N = 'connection_id started_at destination source_ip source_port'
G = 'group_id asset_id device_id addresses membership_verified nat_proxy_dedup_key observation_refs'
HE = 'historical_event_id occurred_at asset_ids indicator_refs snapshot_ref binding_refs observation_kind'
BASE = 'baseline_id version population_definition dimension_key training_window_ref sample_count metrics frequencies'
AUTH = 'authorization_id effective_start effective_end asset_id endpoint domains role task_type ports protocols targets'
SAME = 'same_asset_and_device;same_transport_endpoint;single_indicator_binding;single_observation_kind;deduplicate_retransmissions_and_multirule_hits'

rule('F_BEACON_PERIODIC',{'contacts':C+' packets_per_contact'},SAME,note='Per-contact packet count must be measured; alert counts or cumulative flow packets cannot substitute.')
rule('F_BEACON_JITTER',{'contacts':C},SAME,('ljung_box_lags','median_relative_tolerance'),note='Independent contact population; existing n>=16 and statistical rules remain authoritative.')
rule('F_FIXED_DAILY_WINDOW',{'contacts':C},SAME,note='Explicit day timezone; separate multi-day coverage from jitter coverage; keep >=3 days and 80%/2h rule.')
rule('F_MULTI_DAY_PERSIST',{'contacts':C},SAME,note='Daily occupancy within a declared covered window, not merely first/last timestamps.')
rule('F_RATE_BURST',{'alert_matches':'hit_id occurred_at rule_id','baselines':BASE},'fixed_equal_time_buckets;include_zero_count_buckets;baseline_population_matches_counted_objects',baselines=('mean_per_5m','burst_ratio_p99'))
rule('F_RATE_RAMP',{'alert_matches':'hit_id occurred_at rule_id'},'fixed_equal_time_buckets;include_zero_count_buckets',('window_seconds',),note='Counts saved matches per current contract; this is deliberately distinct from independent contacts.')
rule('F_DNS_HIGH_ENTROPY',{'dns_transactions':D,'baselines':BASE},'same_asset_device;same_registrable_domain;complete_query_denominator',baselines=('unique_subdomain_ratio_p95','label_length_p95','query_rate_p95'))
rule('F_DNS_ENCODED_LABEL',{'dns_transactions':D,'decode_chains':'origin_observation_ref origin_field_path steps.encoding steps.input_artifact_ref steps.output_artifact_ref steps.roundtrip_verified'},'decode_origin_is_exact_question_label',note='F supports hex/base32; semantic decode support is an independent capability and must not be inferred.')
rule('F_DGA_LEXICAL',{'dns_transactions':D,'lexical_references':'corpus_id language normalization_version bigram_log_probabilities','baselines':BASE},'same_normalization_and_corpus_units',baselines=('bigram_log_probability_p05','vowel_ratio_p05','vowel_ratio_p95','length_p05','length_p95'))
rule('F_NXDOMAIN_CLUSTER',{'dns_transactions':D+' rcode','baselines':BASE},'same_asset_device;include_nonfailed_queries_in_denominator',baselines=('nxdomain_rate_p99',))
rule('F_GROUP_NXDOMAIN_CLUSTER',{'group_memberships':G,'dns_transactions':D+' rcode','domain_patterns':'pattern_id expression engine normalization_version','baselines':BASE},'each_dns_question_belongs_to_verified_member;complete_query_denominator_per_member',baselines=('group_nxdomain_rate_p99',),note='Pattern reference is conditional when a named pattern is used; existing skeleton fallback is not removed.')
rule('F_FAILED_TO_ACTIVE',{'dns_transactions':D+' rcode answers response_at connection_refs','connections':N,'relations':'kind from_ref to_ref method verified'},'same_asset_device;exact_normalized_question;connection_ip_is_answer;verified_dns_answer_connection_link',('min_failures',))
rule('F_SHARED_DOMAIN_CLUSTER',{'group_memberships':G,'dns_transactions':D,'domain_patterns':'pattern_id expression engine normalization_version','baselines':BASE},'verified_dns_ownership;shared_registrable_domain_or_verified_pattern',baselines=('domain_frequency_p01',))
rule('F_HTTP_ENDPOINT_REPEAT',{'http_transactions':H},'same_asset_device;canonical_host_and_escaped_path;distinct_complete_request_transactions;retransmissions_do_not_increase_sample_count',note='Original >=6 requests/CV<=0.3 rule; nonrequests do not pollute HTTP coverage, unknown candidates still do.')
rule('F_HTTP_FIELD_ENCODING',{'http_transactions':H+' request.fields request.encoding_summary','decode_chains':'origin_observation_ref origin_field_path steps','baselines':BASE},'field_values_bound_to_same_request;redacted_values_require_verified_encoding_summary;exclude_JWT_OAuth_as_existing_rule',baselines=('encoded_field_ratio_p95','encoded_field_length_p95'))
rule('F_HTTP_UA_RARITY',{'http_transactions':H+' request.user_agent','baselines':BASE},'same_asset_UA_consistency;platform_baseline_has_declared_denominator',baselines=('ua_frequency','ua_frequency_p01'))
rule('F_HTTP_SIZE_STABILITY',{'http_transactions':H+' request.body_bytes','baselines':BASE},'complete_request_body_lengths_only;distinct_requests',baselines=('size_cv_p05','unique_size_ratio_p05'))
rule('F_LONG_LOW_SESSION',{'sessions':'session_id started_at ended_at connection_refs contact_refs up_bytes down_bytes volume_verified volume_basis','contacts':C+' packets_per_contact application_payload_bytes'},'contacts_bound_to_exact_session;verified_bidirectional_bytes')
rule('F_URL_ODD_AUTHORITY',{'http_transactions':H+' request.authority'},'actual_request_URL_not_IOC_description')
rule('F_URL_HOMOGLYPH',{'http_transactions':H,'brand_references':'brand_id display_name authorized_domains normalization_version effective_start effective_end'},'brand_reference_effective_at_request;original_URL_preserved')
rule('F_URL_BRAND_SUBDOMAIN_TRICK',{'http_transactions':H,'brand_references':'brand_id display_name authorized_domains normalization_version effective_start effective_end'},'PSL_normalization;verified_brand_domains')
rule('F_BRAND_IMPOSTOR',{'http_transactions':H+' declared_brand','brand_references':'brand_id display_name authorized_domains normalization_version effective_start effective_end'},'actual_host_against_verified_brand',('max_edit_distance',))
rule('F_CRED_POST_STRUCTURE',{'http_transactions':H+' request.fields request.body_artifact_ref'},'method_and_credential_field_names_from_same_complete_request;credential_values_not_required')
rule('F_FORM_CROSSSITE',{'http_transactions':H+' form_action'},'page_origin_and_action_bound_to_same_transaction;compare_registrable_domains')
rule('F_REDIRECT_CHAIN',{'http_transactions':H+' form_action redirect_link_refs','relations':'kind from_ref to_ref method verified'},'verified_landing_to_submission_chain;no_cross_event_guessing')
rule('F_MULTI_REDIRECT_CHAIN',{'http_transactions':H+' session_ref response.status response.location redirect_link_refs','relations':'kind from_ref to_ref method verified'},'same_session;verified_HTTP_redirect_edges;status_and_location_from_actual_response')
rule('F_PROTOCOL_PORT_MISMATCH',{'connections':N+' application_protocol protocol_basis','service_references':'service_id transport port application_protocol'},'application_protocol_not_inferred_from_port')
rule('F_RARE_PORT',{'connections':N,'group_memberships':G+' role','baselines':BASE},'baseline_matches_asset_role_and_port',baselines=('port_frequency_p01',))
rule('F_DST_NOVELTY',{'connections':N,'history_events':HE+' endpoint'},'exact_asset_and_transport_endpoint;complete_lookback_denominator',note='Empty but fully queried history is representable; only proves first saved observation.')
rule('F_INFRA_RARITY',{'connections':N,'infrastructure_references':'ip asn country reputation_label as_of','baselines':BASE},'reference_ip_equals_destination;as_of_and_version_fixed',baselines=('infra_frequency_p01',))
rule('F_FANOUT_SINGLE_SRC',{'connections':N,'baselines':BASE},'same_source_asset;distinct_destination_ip_port;hour_aligned_window',baselines=('unique_targets_per_hour_p99',))
rule('F_PORT_SEQUENCE',{'connections':N},'ordered_deduplicated_ports;same_asset_device',('difference_entropy_threshold',))
rule('F_SMALL_PACKET',{'connections':N+' payload_bytes'},'one_payload_measurement_per_independent_connection;unknown_bytes_are_null',('small_payload_bytes',))
rule('F_CONN_FAIL_RATE',{'connections':N+' outcome outcome_basis outcome_verified tcp_state','baselines':BASE},'all_connection_attempts_in_denominator;pending_unknown_do_not_become_failure',baselines=('connection_failure_rate_p95',))
rule('F_INDEPENDENT_RULE_CORROB',{'rule_origins':'rule_id independence_group original_source hit_refs'},'distinct_original_sources_and_independence_groups')
rule('F_INDEPENDENT_INTEL_CORROB',{'intel_origins':'indicator_ref original_source record_id'},'same_indicator;deduplicate_republished_source',note='Upstream owns IOC trust/review/expiry; source independence is evidence lineage, not reputation review.')
rule('F_IOC_TYPE_CORROB',{'intel_origins':'indicator_ref upstream_type_labels original_source'},'same_indicator_and_current_scope',note='Requires generated post-hard-type result; never accept hard_type_scores as a raw L2 fact.')
rule('F_TLS_SNI_MISMATCH',{'tls_handshakes':'handshake_id occurred_at connection_ref sni certificate_names','tls_references':'reference_id cdn_exception_patterns cdn_exceptions_verified'},'same_verified_handshake;exceptions_version_fixed')
rule('F_TLS_CERT_ANOMALY',{'tls_handshakes':'handshake_id occurred_at sni certificate_artifact_refs not_before not_after issuer chain_verification trust_reference_ref','tls_references':'reference_id trust_root_artifact_refs trusted_issuers issuers_verified'},'certificate_chain_and_trust_anchor_proof;verification_time_is_handshake_time',note='DER plus trust roots OR independently verified chain fields; conditional alternatives, not all fields blindly mandatory.')
rule('F_TLS_JA_MISMATCH',{'tls_handshakes':'handshake_id occurred_at fingerprint fingerprint_type declared_user_agent','tls_references':'reference_id fingerprint_clients fingerprints_verified'},'UA_and_fingerprint_bound_to_same_client_connection')
rule('F_MULTI_ASSET_IOC',{'group_memberships':G,'connections':N,'dns_transactions':D,'ioc_bindings':'indicator_ref observation_ref field_path asset_id device_id'},'same_indicator;deduplicate_NAT_proxy_resolver_ownership',('cluster_window_seconds',),note='Connections or DNS observations according to indicator type; do not require both when one is the applicable population.')
rule('F_MULTI_ASSET_DIST',{'group_memberships':G+' subnet role'},'independent_verified_asset_members',('subnet_entropy_min',))
rule('F_TIME_COORDINATION',{'group_memberships':G,'connections':N},'same_full_transport_endpoint;complete_time_buckets_per_member',('bucket_seconds','max_lag_bins'))
rule('F_COORD_FANOUT',{'group_memberships':G,'connections':N},'targets_and_time_order_bound_to_member;no_DNS_as_connection',('handoff_seconds',))
rule('F_INFECTION_CHAIN',{'group_memberships':G,'connections':N},'A_external_endpoint_then_A_to_verified_B_address_then_B_to_same_endpoint',('chain_window_seconds',))
rule('F_SHARED_ENDPOINT',{'group_memberships':G,'connections':N,'baselines':BASE},'same_transport_ip_port;verified_connections_not_DNS',baselines=('endpoint_frequency','endpoint_frequency_p01'))
rule('F_FIRST_VISIT_CLUSTER',{'group_memberships':G,'connections':N,'history_events':HE+' endpoint'},'full_history_per_asset_endpoint;first_saved_visits_only')
rule('F_COORD_PATTERN_RECURRENCE',{'group_memberships':G,'connections':N},'same_verified_members_and_endpoint;multi_day_complete_time_buckets',('bucket_seconds',))
rule('F_HIST_ASSET_IOC_RECURRENCE',{'history_events':HE,'ioc_bindings':'indicator_ref observation_ref field_path asset_id device_id'},'same_asset_device_and_exact_indicator;independent_historical_event_ids;lookback_ends_before_current',note='30-day window; evidence-backed partial positive allowed; partial nonmatch cannot refute.')
rule('F_HIST_GROUP_RECURRENCE',{'history_events':HE+' group_id member_asset_ids endpoint family','group_memberships':G},'same_complete_member_set;exact_infrastructure;distinct_calendar_weeks')
rule('F_HIST_INFRA_PERSISTENCE',{'history_events':HE},'same_indicator;independent_asset_identity;consecutive_natural_days',note='Evidence-backed partial positive allowed; does not prove service uptime.')
rule('F_HIST_SCHEDULE_MATCH',{'history_events':HE,'contacts':C},'same_indicator_asset_and_timezone;current_and_history_time_distributions',('kl_threshold',))
rule('F_HIST_MULTI_IOC_SIEGE',{'history_events':HE+' rule_family','baselines':BASE},'same_asset;distinct_indicator_or_rule_family',baselines=('distinct_ioc_families_p99',))
rule('F_HIST_STAGE_PROGRESSION',{'history_events':HE+' adjudication stage_proof_ref campaign_proof_ref','stage_campaign_proofs':'proof_type asset_ids indicator_refs stage campaign_id authority adjudication_id'},'verified_current_stage;reviewed_history;exact_asset_indicator_or_verified_campaign;no_stage_regression')
rule('F_HIST_COORD_PARAM_MATCH',{'history_events':HE+' adjudication group_id member_asset_ids endpoint coordination_parameters campaign_proof_ref','stage_campaign_proofs':'proof_type asset_ids indicator_refs group_id member_asset_ids campaign_id parameters authority'},'same_infrastructure_campaign_and_complete_membership;verified_current_parameters',('parameter_relative_tolerance',))
rule('F_HIST_EXERCISE',{'authorizations':AUTH,'http_transactions':H},'effective_registration_matches_asset_endpoint_or_actual_domain',note='HTTP/domain context conditional on registration target; does not require a readable HTTP request for every exercise registration.')
rule('F_IOC_NOVELTY',{'history_events':HE},'exact_indicator;complete_history_query_including_empty_result',note='Absence conclusion requires complete declared history, not absence of returned rows alone.')
rule('F_EXCL_SCAN_TASK',{'authorizations':AUTH,'connections':N+' application_protocol protocol_basis'},'effective_task_role_asset_endpoint_ports_protocols_targets_all_match')
rule('F_EXCL_INFRA_ROLE',{'authorizations':AUTH,'connections':N+' application_protocol protocol_basis'},'effective_registered_role_resolver_proxy_or_management;current_activity_matches_registration')

KIND_INPUTS = {
 'protocol_request':('semantic_materials','artifact_ref observation_ref transaction_id direction protocol method destination'),
 'protocol_response':('semantic_materials','artifact_ref observation_ref transaction_id direction protocol'),
 'direction':('ioc_bindings','observation_ref asset_id device_id remote_endpoint direction'),
 'pair':('relations','kind from_ref to_ref method verified'),
 'ua':('http_transactions','request.user_agent'),
 'domain':('dns_transactions',D),
 'decode':('decode_chains','origin_observation_ref origin_field_path steps'),
 'decoded_payload':('semantic_materials','artifact_ref decode_chain_ref related_record_refs'),
 'page':('http_transactions','response.body_artifact_ref response_pair_ref'),
 'host':('http_transactions','request.host_ascii'),
 'brand':('semantic_materials','artifact_ref field_path observation_ref'),
 'brand_authorization':('brand_references','brand_id display_name authorized_domains effective_start effective_end'),
 'credential_fields':('http_transactions','transaction_id request.method request.fields request.completeness'),
 'volume':('semantic_materials','transaction_id bytes observation_ref'),
 'content_classification':('content_classifications','transaction_ref artifact_ref category method classifier_version spans'),
 'chunk':('transfer_chunks','transfer_id transaction_ref sequence bytes artifact_ref direction sequence_basis'),
 'transfer_join':('transfer_links','transfer_id chunk_refs join_method join_key join_verified'),
 'parsed_payload':('semantic_materials','artifact_ref observation_ref transaction_id field_path'),
 'stratum_request':('semantic_materials','artifact_ref observation_ref transaction_id direction protocol method'),
 'stratum_response':('semantic_materials','artifact_ref observation_ref transaction_id direction protocol'),
 'lexical_context':('lexical_references','corpus_id normalization_version bigram_log_probabilities'),
 'operation_context':('semantic_materials','artifact_ref observation_ref related_record_refs'),
 'asset_role':('authorizations','asset_id role effective_start effective_end'),
 'task_context':('authorizations',AUTH),
 'visibility':('coverage','population selection population_completeness content_completeness reason_codes'),
 'gaps':('coverage','missing_fields reason_codes'),
 'group_member':('group_memberships',G+' role'),
 'business_schedule':('business_schedules','asset_id role timezone effective_start effective_end weekly_windows'),
 'time_distribution':('contacts',C),
 'history':('history_events',HE+' adjudication'),
 'current_pattern':('runtime','validated_current_facts measurements source_ids window'),
}

def source_location(rule_id):
    paths = list((ROOT/'vulnscan-backend/evidence').glob('*.go'))
    for p in paths:
        if p.name.endswith('_test.go') or p.name in ('catalog.go','contracts.go','input_contract.go','semantic_catalog.go'):
            continue
        for n,line in enumerate(p.read_text(encoding='utf-8').splitlines(),1):
            if '"'+rule_id+'"' in line:
                return str(p.relative_to(ROOT)).replace('\\','/')+':'+str(n)
    return 'vulnscan-backend/evidence/engine.go'

def field_exists(family,path):
    if family == 'runtime': return True
    if family == 'relations':
        from build_standard import relations
        node = relations['properties']['data']
    elif family == 'coverage':
        from build_standard import defs
        node=defs['coverage']
    else: node=FAMILIES[family]
    for part in path.split('.'):
        if node.get('type')=='array': node=node['items']
        if 'anyOf' in node: node=node['anyOf'][0]
        if part not in node.get('properties',{}): return False
        node=node['properties'][part]
    return True

if __name__ == '__main__':
    catalog=json.loads((ROOT/'docs/evidence-pipeline-v2/catalog-input-contracts.json').read_text(encoding='utf-8-sig'))
    facts={x['definition']['fact_id']:x['definition'] for x in catalog['facts']}
    assert set(facts)==set(R), ('unmapped F', set(facts)-set(R), 'unknown F',set(R)-set(facts))
    rows=[]
    for id,contract in R.items():
        rows.append({'rule_id':id,'kind':'F','name':facts[id]['description'],
                     'sample_and_decision_gate':facts[id]['algorithm'],
                     'existing_gate_source':source_location(id),
                     'common_requirements':['meta.scope_ref','meta.window_ref','meta.source_ids','meta.field_sources','meta.verification','meta.coverage_ref'],
                     'coverage_contract':'Per-family/scope/window/population coverage; verified fields; missing inputs never imply not_observed. Follow existing per-rule positive/negative gates.',
                     'runtime_dependencies':{'stage':'post_hard_type','fields':['hard_type_scores','source_fact_ids','policy_version','verified']} if id=='F_IOC_TYPE_CORROB' else {},
                     'migration_status':'not_migrated_to_new_standard',**contract})
    definitions={x['key']['id']+'/'+x['key']['target']+'/'+x['key'].get('subtype',''):x for x in catalog['slots']}
    for slot in catalog['semantic_input_contracts']:
        key=slot['slot'];id=key['id']+'/'+key['target']+'/'+key.get('subtype','')
        inputs={};runtime=[]
        for kind in slot['material_kinds']:
            family,fields=KIND_INPUTS[kind]
            if family=='runtime': runtime+=fields.split();continue
            inputs.setdefault(family,set()).update(fields.split())
        inputs.setdefault('semantic_materials',set()).update('subject_id proposition_id kind artifact_ref field_path observation_ref related_record_refs'.split())
        rows.append({'rule_id':id,'kind':'S','name':key['target'],
                     'required_material_kinds':slot['material_kinds'],
                     'required_inputs':[{'family':f,'fields':sorted(fields)} for f,fields in inputs.items()],
                     'runtime_dependencies':{'all_facts':slot['all_facts'] or [],'any_facts':slot['any_facts'] or [],'fields':runtime},
                     'common_requirements':['meta.scope_ref','meta.window_ref','meta.source_ids','meta.field_sources','meta.verification','meta.coverage_ref'],
                     'association_constraints':['same_proposition_and_origin_object','exact_transaction_and_direction','verified_decode_step_chain_when_used','source_version_pinned','no_F_or_S_verdicts_in_L2'],
                     'coverage_contract':'Readable applicable artifacts, exact originating object and per-material completeness; incomplete material cannot support stronger claims.',
                     'sample_and_decision_gate':definitions[id]['prerequisite'],
                     'existing_gate_source':'vulnscan-backend/evidence/semantic_prerequisites.go',
                     'parameter_keys':[],'baseline_metric_keys':[],
                     'special_condition':'S07 requires independent content classification; S08 requires >=2 separately identified transactions with distinct chunk sequences and verified transfer linkage.' if key['id'] in ('S07','S08') else '',
                     'migration_status':'not_migrated_to_new_standard'})
    assert len(rows)==82 and len({r['rule_id'] for r in rows})==82
    for r in rows:
        for x in r['required_inputs']:
            for field in x['fields']: assert field_exists(x['family'],field),(r['rule_id'],x['family'],field)
    write('rule-requirements.json',{'schema_version':VERSION,'expected_facts':59,'expected_semantics':23,
       'catalog_source_sha256':{name:hashlib.sha256((ROOT/'vulnscan-backend/evidence'/name).read_bytes()).hexdigest() for name in ('catalog.go','semantic_catalog.go','semantic_prerequisites.go')},
       'input_requirement_rows':82,'note':'Requirements include conditional/alternative branches explained by special_condition and executable gates. This is a design contract, not an implemented provider claim.', 'rules':rows})
    with (OUT/'rule-requirements.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f);w.writerow(['rule_id','kind','name','required_fields','runtime_dependencies','join_constraints','baseline_metrics','parameter_keys','gate_source','migration_status'])
        for r in rows: w.writerow([r['rule_id'],r['kind'],r['name'],'; '.join(x['family']+'.'+','.join(x['fields']) for x in r['required_inputs']),json.dumps(r['runtime_dependencies'],ensure_ascii=False),';'.join(r['association_constraints']),','.join(r['baseline_metric_keys']),','.join(r['parameter_keys']),r['existing_gate_source'],r['migration_status']])
    print('explicit mapped rules:',len(rows),'F=59 S=23; all field paths resolve')
