"""Pure consumer controls with explicit crypto stubs; no live/native credit."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from simulator import normal_ordinary_classifier as classifier
from simulator.normal_pool import authenticate_pool, join_pool_finance, source_originals, CLASSIFIER_SHA256
from simulator.model import SIGNET_GENESIS, canonical
from simulator.bundle_audit import decode_transaction
from tests.test_normal_money_sources import wire


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.key='02'+'11'*32;self.tip='a'*64;self.epoch='e'*64
        self.raw=wire([('f'*64,0)],[(10000,b'\x51')]);self.txid=decode_transaction(self.raw.hex())['txid'];self.point=self.txid+':0'
        self.id='b'*64+':0';self.tool={'sha256':'c'*64}
        self.configuration={'classifier_sha256':CLASSIFIER_SHA256,'pool_pre_expiry_blocks':10,'maximum_exit_depth':12,'minimum_confirmations':3}
        self.tables={name:[]for name in classifier.TABLES}
        coin={k:None for k in classifier.VTXO_FIELDS};coin.update(id=1,vtxo_id=self.id,signed_vtxo_hex='01',expiry=200,
            vtxo_txid=self.id.split(':')[0],exit_delta=12,policy_type='pubkey',policy_hex='00'+self.key,server_pubkey=self.key,
            amount=10000,anchor_point=self.point,spend_state='pool');self.tables['vtxo']=[coin]
        self.tables['vtxo_pool']=[{'id':1,'vtxo_id':self.id,'expiry_height':200,'amount':10000,'created_at':None,'spent_at':None,'signed_vtxo_hex':'01'}]
        self.tables['ephemeral_tweak']=[{'id':1,'pubkey':self.key,'secret_tweak_present':True,'created_at':None,'expires_at':None}]
        self.tables['virtual_transaction']=[{'txid':self.txid,'is_funding':True,'signed_transaction_hex':self.raw.hex()}]
        self.tables['fee_allowance_policy']=[{'policy_bytes_hex':canonical({'epoch_id':self.epoch}).encode().hex()}]
        c={'epoch_id':self.epoch,'path':'Pool','raw':list(self.raw),'input_parents':[],'package_parents':[],'package_input_parents':[]}
        self.tables['fee_allowance_candidate']=[{'id':self.txid,'epoch_id':self.epoch,'candidate_bytes_hex':canonical(c).encode().hex(),'urgent':False,'fee_sat':100}]
        self.native={'schema_version':1,'network':'signet','genesis':SIGNET_GENESIS,'server_pubkey':self.key,'height':100,'tip_hash':self.tip,
            'pool_pre_expiry_blocks':10,'max_exit_depth':12,'candidate_snapshot_complete':True,'complete':False,
            'missing_sources':['independent signed-path and raw Core backing qualification'],'candidates':[{
                'id':self.id,'amount_sat':10000,'expiry_height':200,'exit_depth':1,'runtime_member':True,'pool_spent':False,
                'spend_state':'pool','has_spend_reference':False,'key_present':True,'key_matches':True,'in_flux':False,'signed_vtxo':'01'}]}
        frame={'chain':'signet','blocks':100,'bestblockhash':self.tip,'initialblockdownload':False}
        self.core={'transactions':{self.txid:{'hex':self.raw.hex(),'confirmations':3,'blockhash':'d'*64}},
            'genesis':SIGNET_GENESIS,'before':copy.deepcopy(frame),'after':copy.deepcopy(frame)};self.claims=[]
        self.proof={'id':self.id,'amount_sat':10000,'expiry_height':200,'server_pubkey':self.key,'chain_anchor':self.point,
            'exit_depth':1,'candidate_user_pubkey':self.key,'exit_delta':12,'policy':'pubkey','signed_path_valid':True,
            'chain_contract_verified':True,'tree_padding':False,'anchor_amount_sat':10000,'anchor_script':'51'}
        self.utxo={'bestblock':self.tip,'confirmations':3,'coinbase':False,'value':'0.0001','scriptPubKey':{'hex':'51'}}
        outer=self
        class Chain:
            def identity(inner):return {'chain':'signet','blocks':100,'bestblockhash':outer.tip,'initialblockdownload':False}
            def tx(inner,txid):return {'hex':outer.raw.hex(),'confirmations':3,'blockhash':'d'*64}
            def call(inner,method,*args):
                if method=='getblockhash':return SIGNET_GENESIS if args==(0,)else'd'*64
                if method=='gettxout':
                    assert args[-1]is True
                    return outer.utxo
                raise AssertionError(method)
        self.chain=Chain()
        self.native_mock=patch('simulator.two_step_normal.run_proof',side_effect=lambda tool,req:(canonical(req).encode(),canonical(self.proof).encode()))
        self.native_mock.start();self.addCleanup(self.native_mock.stop)
        self.refresh()
    def refresh(self):
        frame={'read_only':'on','isolation':'repeatable read','tables':{name:{'count':len(rows),'rows':rows}for name,rows in self.tables.items()}}
        self.sql=('BEGIN\nSET\nDO\n'+canonical(frame)+'\nCOMMIT\n').encode();self.pool=canonical(self.native).encode()
        plan=classifier.plan_ordinary(frame['tables'],decode_transaction,self.key,self.epoch)
        result=classifier.finish_ordinary(plan,self.native,self.core['transactions'],network='signet',genesis=SIGNET_GENESIS,
            server_pubkey=self.key,height=100,tip_hash=self.tip,sql_sha256=hashlib.sha256(self.sql).hexdigest(),pool_sha256=hashlib.sha256(self.pool).hexdigest())
        self.originals={'owning_pool_inventory':self.pool,'ordinary_source_classification':canonical(result).encode()}
    def auth(self):return authenticate_pool(self.tables,self.sql,self.originals,canonical(self.core).encode(),self.chain,self.tool,
        configuration=self.configuration,server_pubkey=self.key,height=100,tip_hash=self.tip,customer_claims=self.claims)
    def test_actual_classifier_and_proof_contract_join_without_ready_or_payment_credit(self):
        checked=self.auth();self.assertEqual([self.id],checked['coin_ids']);self.assertEqual(10000,checked['roots'][self.point]['amount_sat'])
        self.assertNotIn('complete',checked);self.assertNotIn('ready',checked);self.assertEqual(0,checked['customer_payment_credit_sat'])
        self.assertNotIn('signed_vtxo',json.dumps(checked))
    def test_independent_crypto_depth_key_and_anchor_mismatch_refuse(self):
        for key,value in [('exit_depth',0),('candidate_user_pubkey','03'+'22'*32),('chain_anchor','f'*64+':0'),
                ('signed_path_valid',False),('tree_padding',True),('anchor_amount_sat',9999)]:
            old=copy.deepcopy(self.proof);self.proof[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.auth()
            self.proof=old
    def test_native_availability_does_not_erase_spent_pruned_flux_or_expired_rows(self):
        for key,value in [('in_flux',True),('key_matches',False),('pool_spent',True),('expiry_height',105)]:
            old=copy.deepcopy(self.native);old_tables=copy.deepcopy(self.tables);self.native['candidates'][0][key]=value
            if key=='pool_spent':self.tables['vtxo_pool'][0]['spent_at']='source-time'
            if key=='expiry_height':
                self.tables['vtxo_pool'][0]['expiry_height']=value;self.tables['vtxo'][0]['expiry']=value
            self.refresh()  # Classifier acceptance cannot grant financial eligibility.
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'eligibility'):self.auth()
            self.native=old;self.tables=old_tables;self.refresh()
        self.native['candidates']=[];self.refresh()
        with self.assertRaisesRegex(ValueError,'durable pool'):self.auth()
    def test_classifier_flag_or_hash_does_not_substitute_for_original_proofs(self):
        self.originals['ordinary_source_classification']=b'{"complete":true}'
        with self.assertRaisesRegex(ValueError,'recomputed'):self.auth()
        self.refresh();self.configuration['classifier_sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'classifier configuration'):self.auth()
    def test_customer_overlap_and_mempool_spend_cannot_be_operator_pool_assets(self):
        self.claims=[{'coin_id':self.id,'chain_anchor':self.point}]
        with self.assertRaisesRegex(ValueError,'customer allocation'):self.auth()
        self.claims=[];self.utxo=None
        with self.assertRaisesRegex(ValueError,'Core backing'):self.auth()
    def test_round_and_unknown_source_domains_remain_hold(self):
        self.tables['round']=[{'id':1}]
        with self.assertRaisesRegex(ValueError,'round allocations'):self.auth()
        self.tables['round']=[];self.tables['htlc_vtxo']=[{'id':1}]
        self.sql=('BEGIN\nSET\n'+canonical({'tables':{n:{'count':len(v),'rows':v}for n,v in self.tables.items()}})+'\nCOMMIT').encode()
        with self.assertRaisesRegex(ValueError,'conditional'):self.auth()
    def test_pool_asset_and_native_fee_payer_sources_must_both_join(self):
        checked=self.auth();fee={'candidate_ids':[self.txid],'epoch_id':self.epoch}
        cost={'source':'rounds','destination':'miners','budget':'ordinary','amount_msat':100000}
        assets={'assets':{self.point:{'member':'backing','amount_msat':10000000}}}
        def join(costs=None,view=None):return join_pool_finance(checked,self.tables,fee,{self.txid:cost}if costs is None else costs,{},assets if view is None else view,rounds_member_id='rounds',backing_member_id='backing')
        self.assertEqual([self.txid],join()['funding_carrier_ids'])
        with self.assertRaisesRegex(ValueError,'payer/cost'):join({})
        for key,value in [('source','watchman'),('destination','operator'),('amount_msat',99000)]:
            old=copy.deepcopy(cost);cost[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):join()
            cost=old
        with self.assertRaisesRegex(ValueError,'backing asset'):join(view={'assets':{}})
        self.tables['fee_allowance_candidate'][0]['fee_sat']=0
        zero={self.txid:{'fee_sat':0,'raw_sha256':hashlib.sha256(self.raw).hexdigest()}}
        result=join_pool_finance(checked,self.tables,fee,{},zero,assets,rounds_member_id='rounds',backing_member_id='backing')
        self.assertEqual(0,result['customer_payment_credit_sat'])
        with self.assertRaisesRegex(ValueError,'zero-fee'):
            join_pool_finance(checked,self.tables,fee,{self.txid:cost},zero,assets,rounds_member_id='rounds',backing_member_id='backing')
    def test_unconfirmed_or_changed_chain_refuses_even_qualified_full(self):
        original=self.chain.tx;self.chain.tx=lambda txid:{**original(txid),'confirmations':0}
        with self.assertRaisesRegex(ValueError,'active confirmed'):self.auth()
        self.chain.tx=original;identity=self.chain.identity;count=[0]
        def changed():
            count[0]+=1
            return {**identity(),'bestblockhash':'f'*64}if count[0]>1 else identity()
        self.chain.identity=changed
        with self.assertRaisesRegex(ValueError,'chain changed'):self.auth()
    def test_saved_core_frame_cannot_supply_wrong_identity_or_detached_anchor(self):
        self.core['after']['blocks']=101
        with self.assertRaisesRegex(ValueError,'captured Core'):self.auth()
        self.core['after']['blocks']=100;self.core['transactions'][self.txid]['hex']='00'
        with self.assertRaisesRegex(ValueError,'active confirmed'):self.auth()
    def test_signed_unbroadcast_spend_still_reserves_pool_physical_backing(self):
        checked=self.auth();raw=wire([(self.txid,0)],[(9900,b'\x51')])
        candidate={'path':'Sweep','raw':list(raw)}
        self.tables['fee_allowance_candidate'].append({'candidate_bytes_hex':canonical(candidate).encode().hex()})
        with self.assertRaisesRegex(ValueError,'signed spend reservation'):
            join_pool_finance(checked,self.tables,{'candidate_ids':[self.txid],'epoch_id':self.epoch},{},{},{'assets':{}},
                rounds_member_id='rounds',backing_member_id='backing')
    def test_named_auxiliary_originals_require_exact_manifest_hashes(self):
        names={'owning_pool_inventory':'native-pool.private.json','ordinary_source_classification':'ordinary-source-classification.private.json'}
        files={names[k]:{'sha256':hashlib.sha256(v).hexdigest(),'size_bytes':len(v)}for k,v in self.originals.items()}
        package={'manifest':{'auxiliary_originals':names,'files':files,'classification_program_sha256':CLASSIFIER_SHA256},
            'auxiliary_originals':{names[k]:v for k,v in self.originals.items()}}
        self.assertEqual(self.originals,source_originals(package,self.configuration))
        files[names['owning_pool_inventory']]['size_bytes']+=1
        with self.assertRaisesRegex(ValueError,'hash/size'):source_originals(package,self.configuration)
