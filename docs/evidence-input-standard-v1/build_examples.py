"""Small controlled design fixtures. No production data or algorithm verdicts."""
import base64
import hashlib
from build_standard import FAMILIES, VERSION, write

AT='2026-10-15T01:00:00Z'
END='2026-10-16T00:00:00Z'
PRODUCER={'name':'controlled-example','version':'1'}

def make(protocol):
    b={'schema_version':VERSION,'bundle_id':'example-'+protocol,'producer':PRODUCER,
       'created_at':END,'event':{'event_id':'event-1','occurred_at':AT,'indicator_refs':['ioc-1']},
       'snapshots':[{'id':'snap-1','event_id':'event-1','version':1,'watermark':2,'revision_watermark':0,'as_of':END}],
       'sources':[{'id':'src-1','kind':'dns_log' if protocol=='dns' else 'http_log','snapshot_ref':'snap-1',
                   'origin':'controlled-offline-fixture','record_key':'fixture-transactions','version':'1','sha256':None}],
       'windows':[{'id':'window-1','start':'2026-10-15T00:00:00Z','end':END,'timezone':'Asia/Shanghai','boundary':'[start,end)'}],
       'scopes':[{'id':'scope-1','kind':'asset_endpoint','asset_id':'asset-1','device_id':'device-1',
                  'endpoint':{'transport':'udp' if protocol=='dns' else 'tcp','ip':'192.0.2.53' if protocol=='dns' else '192.0.2.80',
                              'port':53 if protocol=='dns' else 80},'group_id':None,'identity_source_ids':['src-1']}],
       'indicators':[{'id':'ioc-1','type':'domain','value':'c2.example.test','upstream_labels':['controlled'], 'source_ids':['src-1']}],
       'coverage':[],'artifacts':[],'relations':[],'datasets':{f:[] for f in FAMILIES},'diagnostics':[]}
    populations={'contacts':'independent_contacts','http_transactions':'http_transactions','dns_transactions':'dns_transactions',
                 'alert_matches':'saved_alert_matches','connections':'connection_attempts','sessions':'sessions','history_events':'historical_events'}
    for f in FAMILIES:
        b['coverage'].append({'id':'cov-'+f,'family':f,'scope_ref':'scope-1','window_ref':'window-1','indicator_ref':'ioc-1',
            'population':populations.get(f,'supplied_materials'),'selection':'controlled fixture: this family, scope-1 and window-1 only',
            'source_snapshot_refs':['snap-1'],'availability':'unavailable','population_completeness':'unknown',
            'content_completeness':'unknown','expected_records':None,'loaded_records':0,'excluded_records':0,'duplicate_records':0,
            'missing_fields':[],'reason_codes':['not_supplied_in_example'],'denominator_description':None})
    return b

def add(b,f,id,data):
    c=next(x for x in b['coverage'] if x['family']==f)
    c.update(availability='available',population_completeness='complete',content_completeness='complete',
             expected_records=c['loaded_records']+1,loaded_records=c['loaded_records']+1,
             reason_codes=[],denominator_description='All explicitly enumerated controlled fixture records; no real-world coverage claim.')
    b['datasets'][f].append({'meta':{'id':id,'scope_ref':'scope-1','window_ref':'window-1','indicator_refs':['ioc-1'],
            'coverage_ref':c['id'],'source_ids':['src-1'],'producer':PRODUCER,'verification':'verified',
            'verification_checks':['controlled_fixture_identity'],'missing_fields':[],
            'field_sources':[{'field':k,'source_id':'src-1','source_field':f+'/'+id+'/'+k} for k,v in data.items() if v is not None]},'data':data})
    if f=='http_transactions':
        c['selection']='All controlled fixture HTTP requests; response population is not supplied or claimed.'

def artifact(b,id,value,field):
    raw=value.encode('utf8')
    b['artifacts'].append({'id':id,'source_ids':['src-1'],'source_field':field,'media_type':'text/plain',
         'visibility':'plaintext','encoding':'utf8','content':value,'byte_length':len(raw),
         'sha256':hashlib.sha256(raw).hexdigest(),'complete':True,'redacted':False})

def http(b,n,body=''):
    id='http-'+str(n);time='2026-10-15T01:%02d:00Z'%n
    artifact(b,'raw-'+id,'POST /upload HTTP/1.1\r\nHost: c2.example.test\r\nContent-Length: '+str(len(body.encode('utf8')))+'\r\n\r\n'+body,'request.raw')
    artifact(b,'body-'+id,body,'request.body')
    add(b,'http_transactions',id,{'transaction_id':'tx-'+str(n),'session_ref':None,'connection_ref':None,
        'request_at':time,'response_at':None,'direction':'outbound',
        'request':{'method':'POST','url_raw':'http://c2.example.test/upload','scheme':'http','host_ascii':'c2.example.test',
                   'authority':'c2.example.test','path_escaped':'/upload','query_raw':'','user_agent':None,
                   'headers':[{'name':'Host','value':'c2.example.test'},{'name':'Content-Length','value':str(len(body.encode('utf8')))}],
                   'fields':[],'body_bytes':len(body.encode('utf8')),'raw_artifact_ref':'raw-'+id,'body_artifact_ref':'body-'+id,
                   'completeness':'complete','assembly':'complete_message','encoding_summary':None},
        'response':None,'response_pair_ref':None,'redirect_link_refs':[],'form_action':None,'declared_brand':None})
    add(b,'contacts','contact-'+str(n),{'contact_id':'independent-tx-'+str(n),'occurred_at':time,'kind':'http_transaction',
          'observation_ref':id,'dedup_key':'HTTP request stream fixture/'+str(n),'duplicate_source_ids':[],
          'packets_per_contact':None,'application_payload_bytes':len(body.encode('utf8'))})
    add(b,'ioc_bindings','binding-'+str(n),{'indicator_ref':'ioc-1','observation_ref':id,'field_path':'request.host_ascii',
          'observed_type':'domain','observed_value':'c2.example.test','asset_id':'asset-1','device_id':'device-1',
          'remote_endpoint':b['scopes'][0]['endpoint'],'direction':'outbound'})
    return id

def examples():
    b=make('http');http(b,1)
    add(b,'alert_matches','alert-1',{'hit_id':'hit-1','occurred_at':AT,'rule_id':'upstream-rule-1','rule_family':None,'observation_ref':'http-1'})
    write('example-http.json',b)
    b=make('transfer')
    for n in (1,2):
        id=http(b,n,'dummy-customer-%d'%n)
        add(b,'transfer_chunks','chunk-'+str(n),{'transfer_id':'transfer-1','transaction_ref':id,'sequence':n,
              'bytes':len('dummy-customer-%d'%n),'artifact_ref':'body-'+id,'direction':'outbound','sequence_basis':'verified application chunk index in controlled fixture'})
    add(b,'transfer_links','link-1',{'transfer_id':'transfer-1','chunk_refs':['chunk-1','chunk-2'],
          'join_method':'application transfer ID and sequence','join_key':'controlled-transfer-1','join_verified':True})
    add(b,'content_classifications','classification-1',{'transaction_ref':'http-1','artifact_ref':'body-http-1',
          'category':'controlled_customer_record','method':'code','classifier_version':'fixture-classifier-1',
          'spans':[{'offset_bytes':0,'length_bytes':len('dummy-customer-1'),'basis':'controlled dummy-data exact match'}],
          'explanation':'Synthetic non-sensitive content; classification fixture only.'})
    write('example-transfer.json',b)
    b=make('dns');encoded=base64.b32encode(b'demo-only!').decode('ascii')
    b['indicators'][0]['value']=encoded+'.example.test'
    artifact(b,'dns-question',encoded+'.example.test','dns.question_name_raw')
    artifact(b,'encoded-label',encoded,'dns.question_name_raw.labels[0]')
    artifact(b,'decoded-label','demo-only!','decode.base32.output')
    add(b,'dns_transactions','dns-1',{'transaction_id':'dns-tx-1','question_at':AT,'response_at':None,
          'question_name_raw':encoded+'.example.test','question_name_ascii':encoded+'.example.test',
          'registrable_domain':'example.test','psl_version':'controlled-fixture-1','qtype':'TXT','rcode':None,'answers':[],
          'request_artifact_ref':'dns-question','response_artifact_ref':None,'connection_refs':[], 'retransmission_key':'dns-query-1'})
    # Exact origin field refers to the recorded label artifact rather than substring inference.
    add(b,'decode_chains','decode-1',{'origin_observation_ref':'dns-1','origin_field_path':'question_name_raw',
        'origin_slice':{'offset_bytes':0,'length_bytes':len(encoded)},
        'steps':[{'encoding':'base32','input_artifact_ref':'encoded-label','output_artifact_ref':'decoded-label',
                  'decoder_version':'python-base64-1','roundtrip_verified':True}]})
    add(b,'semantic_materials','material-1',{'subject_id':'dns-1','proposition_id':'encoded-label-1','kind':'decoded_text',
          'artifact_ref':'decoded-label','field_path':'question_name_raw','observation_ref':'dns-1','transaction_id':'dns-tx-1',
          'direction':'outbound','protocol':'dns','method':None,'destination':encoded+'.example.test',
          'related_record_refs':['dns-1'],'decode_chain_ref':'decode-1','adjudication_id':None,'field_names':['question_name_raw'],
          'bytes':10,'sequence':None})
    add(b,'ioc_bindings','binding-dns',{'indicator_ref':'ioc-1','observation_ref':'dns-1','field_path':'question_name_raw',
          'observed_type':'domain','observed_value':encoded+'.example.test','asset_id':'asset-1','device_id':'device-1',
          'remote_endpoint':b['scopes'][0]['endpoint'],'direction':'outbound'})
    # Query-only completeness: response is explicitly outside this supplied population.
    cov=next(x for x in b['coverage'] if x['family']=='dns_transactions')
    cov['selection']='All controlled DNS questions; response population not supplied.'
    cov.update(content_completeness='partial',missing_fields=['response_at','rcode','answers','response_artifact_ref'],reason_codes=['response_not_supplied'])
    write('example-dns.json',b)

if __name__=='__main__':
    examples()
    print('wrote 3 controlled examples')
