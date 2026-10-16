import copy
import json
import unittest
from pathlib import Path
from build_standard import ROOT, FAMILIES
from build_requirements import R, field_exists
from validate import validate

HERE=Path(__file__).resolve().parent

def load(name):
    return json.loads((HERE/name).read_text(encoding='utf8'))

class ContractTests(unittest.TestCase):
    def assertRejected(self,b,fragment):
        errors=validate(b)
        self.assertTrue(any(fragment in e for e in errors),errors)

    def test_catalogue_82_explicit_mappings_and_paths(self):
        contract=load('rule-requirements.json')
        catalogue=json.loads((ROOT/'docs/evidence-pipeline-v2/catalog-input-contracts.json').read_text(encoding='utf-8-sig'))
        expected={x['definition']['fact_id'] for x in catalogue['facts']}
        self.assertEqual(expected,set(R))
        slots={x['key']['id']+'/'+x['key']['target']+'/'+x['key'].get('subtype','') for x in catalogue['slots']}
        self.assertEqual(59,len(expected));self.assertEqual(23,len(slots))
        self.assertEqual(expected|slots,{x['rule_id'] for x in contract['rules']})
        self.assertEqual(82,len(contract['rules']))
        for rule in contract['rules']:
            self.assertTrue(rule['required_inputs'])
            for group in rule['required_inputs']:
                for field in group['fields']:
                    self.assertTrue(field_exists(group['family'],field),(rule['rule_id'],field))

    def test_examples(self):
        for path in HERE.glob('example-*.json'):
            with self.subTest(path=path.name):
                self.assertEqual([],validate(load(path.name)))

    def test_unknown_field(self):
        b=load('example-http.json');b['algorithm_verdict']='observed'
        self.assertRejected(b,'Additional properties')

    def test_missing_source(self):
        b=load('example-http.json');b['sources']=[]
        self.assertRejected(b,'unresolved')

    def test_wrong_ioc_original_value(self):
        b=load('example-http.json');b['datasets']['ioc_bindings'][0]['data']['observed_value']='other.test'
        self.assertRejected(b,'IOC original field value mismatch')

    def test_wrong_ioc_asset(self):
        b=load('example-http.json');b['datasets']['ioc_bindings'][0]['data']['asset_id']='other'
        self.assertRejected(b,'IOC asset/device/endpoint mismatch')

    def test_packet_is_not_contact(self):
        b=load('example-http.json');b['datasets']['contacts'][0]['data']['observation_ref']='alert-1'
        self.assertRejected(b,'contact is not an independent')

    def test_duplicate_contacts(self):
        b=load('example-http.json');row=copy.deepcopy(b['datasets']['contacts'][0]);row['meta']['id']='another'
        b['datasets']['contacts'].append(row)
        self.assertRejected(b,'duplicate contact')

    def test_artifact_hash(self):
        b=load('example-http.json');b['artifacts'][0]['content']='changed'
        self.assertRejected(b,'artifact hash mismatch')

    def test_invalid_window(self):
        b=load('example-http.json');b['windows'][0]['end']=b['windows'][0]['start']
        self.assertRejected(b,'invalid window')

    def test_incomplete_population_not_complete(self):
        b=load('example-http.json');b['coverage'][0]['expected_records']=100
        self.assertRejected(b,'complete population count mismatch')

    def test_missing_content_not_complete(self):
        b=load('example-dns.json');c=next(c for c in b['coverage'] if c['family']=='dns_transactions');c['content_completeness']='complete'
        self.assertRejected(b,'complete content declares missing fields')

    def test_dns_slice_must_match(self):
        b=load('example-dns.json');b['datasets']['decode_chains'][0]['data']['origin_slice']['offset_bytes']=1
        self.assertRejected(b,'decode origin field mismatch')

    def test_ciphertext_cannot_be_decode_material(self):
        b=load('example-dns.json');b['artifacts'][1]['visibility']='ciphertext'
        self.assertRejected(b,'ciphertext cannot be a plaintext decode')

    def test_transfer_must_use_distinct_transactions(self):
        b=load('example-transfer.json');b['datasets']['transfer_chunks'][1]['data']['transaction_ref']='http-1'
        self.assertRejected(b,'transfer needs distinct transactions')

    def test_classification_span_bounds(self):
        b=load('example-transfer.json');b['datasets']['content_classifications'][0]['data']['spans'][0]['length_bytes']=9999
        self.assertRejected(b,'classification span out of bounds')

    def test_all_families_explicit_even_when_unavailable(self):
        b=load('example-http.json');self.assertEqual(set(FAMILIES),set(b['datasets']))
        del b['datasets']['baselines']
        self.assertRejected(b,'required property')

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ContractTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (HERE/'verification.json').write_text(json.dumps({'scope':'input contract design validation only',
        'command':'python docs/evidence-input-standard-v1/test_contract.py',
        'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
        'successful':result.wasSuccessful(),'examples':3,'mapped_F':59,'mapped_S':23,
        'does_not_prove':['production provider completeness','F/S algorithm acceptance','model validation','backend migration']},ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    raise SystemExit(0 if result.wasSuccessful() else 1)
