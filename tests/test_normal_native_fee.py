"""Wire/accounting negative controls; synthetic Core, no native or money credit."""
import copy
import hashlib
import json
import unittest

from simulator.bundle_audit import decode_transaction
from simulator.model import SIGNET_GENESIS
from simulator.normal_native_fee import verify_native_fee_epoch


def encoded(value):return json.dumps(value,separators=(',',':')).encode()
def transaction(point,value,witness=False):
    txid,vout=point.rsplit(':',1)
    body=b'\x01'+bytes.fromhex(txid)[::-1]+int(vout).to_bytes(4,'little')+b'\x00'+b'\xff'*4
    body+=b'\x01'+value.to_bytes(8,'little')+b'\x01\x51'
    return b'\x02\x00\x00\x00'+(b'\x00\x01' if witness else b'')+body+(b'\x01\x01\x11' if witness else b'')+b'\x00'*4

def identity(raw):return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()

class Chain:
    def __init__(self,transactions):self.transactions=transactions;self.calls=[]
    def call(self,method,*args):
        if method=='getblockhash' and args==(0,):return SIGNET_GENESIS
        raise AssertionError('only independent read source permitted')
    def tx(self,txid):self.calls.append(txid);return {'hex':self.transactions[txid].hex()}

class NativeFeeTests(unittest.TestCase):
    def setUp(self):
        self.fund=transaction('f'*64+':0',20000)
        self.fundid=decode_transaction(self.fund.hex())['txid']
        self.sweep=transaction(self.fundid+':0',19900,True)
        self.policy={'epoch_id':'a'*64,'genesis':SIGNET_GENESIS,'server_pubkey':'02'+'b'*64,
            'ordinary_sat':58000,'urgent_sat':40000,'ordinary_sat_per_kwu':1250,
            'urgent_child_sat_per_kwu':5000,'urgent_package_sat_per_kwu':5000,
            'urgent_max_candidate_sat':20000,'urgent_required_confirmed_sat':40000,
            'watchman_descriptor_sha256':'c'*64,'watchman_admin_address':'127.0.0.1:1'}
        self.policy_bytes=encoded(self.policy)
        self.candidate={'epoch_id':'a'*64,'path':'Sweep','raw':list(self.sweep),
            'input_parents':[list(self.fund)],'package_parents':[],'package_input_parents':[]}
        self.rows=[];self.history={'root_identity':'1:2','identity_bytes':self.policy_bytes,
            'index_bytes':b'','candidates':{}}
        self.add(self.candidate,100,False)
        self.chain=Chain({self.fundid:self.fund,decode_transaction(self.sweep.hex())['txid']:self.sweep})
        self.opening=None
    def add(self,candidate,fee,urgent):
        raw=encoded(candidate);identifier=identity(bytes(candidate['raw']))
        self.rows.append({'id':identifier,'epoch_id':'a'*64,'candidate_bytes_hex':raw.hex(),'urgent':urgent,'fee_sat':fee})
        self.history['index_bytes']+=identifier.encode()+b'\n';self.history['candidates'][identifier]=raw
        return identifier
    def verify(self):
        p=hashlib.sha256(self.policy_bytes).hexdigest()
        return verify_native_fee_epoch(self.policy_bytes,p,[{'id':'active','policy_bytes_hex':self.policy_bytes.hex(),
            'history_identity':'1:2','opening_digest':self.opening}],self.rows,self.chain,
            expected_genesis=SIGNET_GENESIS,expected_server_pubkey=self.policy['server_pubkey'],
            expected_history_identity='1:2',expected_opening_digest=self.opening,expected_epoch_id='a'*64,history=self.history)
    def repolicy(self,**fields):
        self.policy.update(fields);self.policy_bytes=encoded(self.policy);self.history['identity_bytes']=self.policy_bytes
    def test_actual_wire_fee_is_reserved_not_reported_as_miner_payment(self):
        proof=self.verify()
        self.assertEqual((58000,100,57900),(proof['ordinary_total_sat'],proof['ordinary_booked_sat'],proof['ordinary_remaining_sat']))
        self.assertEqual(40000,proof['urgent_remaining_sat'])
        self.assertNotIn('paid_to_miners_sat',proof)
        self.assertEqual([self.fundid],self.chain.calls)
    def test_sql_fee_flag_witness_and_duplicate_cannot_forge_original(self):
        for field,value in [('fee_sat',0),('urgent',True),('id','e'*64),('epoch_id','f'*64)]:
            with self.subTest(field=field):
                old=self.rows[0][field];self.rows[0][field]=value
                with self.assertRaises(ValueError):self.verify()
                self.rows[0][field]=old
        self.rows.append(copy.deepcopy(self.rows[0]))
        with self.assertRaises(ValueError):self.verify()
    def test_private_history_missing_or_torn_or_different_refuses(self):
        old=copy.deepcopy(self.history)
        for key,value in [('root_identity','1:3'),('identity_bytes',b'{}'),('index_bytes',self.history['index_bytes'][:-1]),('candidates',{})]:
            with self.subTest(key=key):
                self.history=copy.deepcopy(old);self.history[key]=value
                with self.assertRaises(ValueError):self.verify()
    def test_independent_parent_witness_or_body_mutation_refuses(self):
        self.chain.transactions[self.fundid]=self.fund[:-1]+b'\x01'
        with self.assertRaisesRegex(ValueError,'parent bytes'):self.verify()
    def test_actual_rate_and_cumulative_exhaustion_refuse(self):
        self.repolicy(ordinary_sat_per_kwu=1)
        with self.assertRaisesRegex(ValueError,'ceiling'):self.verify()
        self.repolicy(ordinary_sat_per_kwu=1250,ordinary_sat=99)
        with self.assertRaisesRegex(ValueError,'cumulative'):self.verify()
    def test_original_parent_in_child_package_is_charged_once(self):
        self.rows=[];self.history['index_bytes']=b'';self.history['candidates']={}
        original={**self.candidate,'path':'Round'};self.add(original,100,False)
        parentid=decode_transaction(self.sweep.hex())['txid']
        child=transaction(parentid+':0',19800,True)
        self.add({'epoch_id':'a'*64,'path':'ProgressChild','raw':list(child),
            'input_parents':[list(self.sweep)],'package_parents':[list(self.sweep)],
            'package_input_parents':[list(self.fund)]},100,True)
        result=self.verify()
        self.assertEqual((100,100),(result['ordinary_booked_sat'],result['urgent_booked_sat']))
        self.assertEqual([parentid+':0'],result['reserved_urgent_prevouts'])
        self.assertEqual(2,len(self.chain.calls))
    def test_original_nonzero_opening_keeps_total_and_debits_once(self):
        opening={'version':1,'policy_sha256':hashlib.sha256(self.policy_bytes).hexdigest(),
            'epoch_id':'a'*64,'genesis':SIGNET_GENESIS,'server_pubkey':self.policy['server_pubkey'],
            'ordinary_total_sat':58000,'urgent_total_sat':40000,'previously_booked_ordinary_sat':0,
            'previously_booked_urgent_sat':0,'import_ordinary_sat':100,'remaining_ordinary_sat':57900,
            'remaining_urgent_sat':40000,'candidates':[self.candidate]}
        raw=encoded(opening);self.opening=hashlib.sha256(raw).hexdigest();self.history.update(
            opening_certificate_bytes=raw,validated_digest_bytes=self.opening.encode())
        self.assertEqual(100,self.verify()['original_opening_import_sat'])
        opening['remaining_ordinary_sat']=58000;raw=encoded(opening)
        self.opening=hashlib.sha256(raw).hexdigest();self.history.update(
            opening_certificate_bytes=raw,validated_digest_bytes=self.opening.encode())
        with self.assertRaisesRegex(ValueError,'import/TOTAL/remainder'):self.verify()
    def test_duplicate_json_policy_field_is_refused(self):
        self.policy_bytes=self.policy_bytes[:-1]+b',"ordinary_sat":58000}'
        with self.assertRaisesRegex(ValueError,'duplicate'):self.verify()
