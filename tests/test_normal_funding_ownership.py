"""Synthetic signed-wire/source-journal controls; no live ownership credit."""
import copy
from datetime import datetime,timezone,timedelta
from decimal import Decimal
import tempfile
from pathlib import Path
import unittest

from simulator import normal_funding_ownership as ownership
from simulator.bundle_audit import decode_transaction,rpc_json
from simulator.model import SIGNET_GENESIS,canonical
from simulator.store import Store
from simulator.two_step_normal import digest,module_hash,verified_money
from tests.test_final_campaign import PINS
from tests.test_normal_money_sources import wire


def block(height):return digest(str(height).encode())
def encode(value):return rpc_json(value).encode()


class FundingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'owned-funding',10000)
        self.boundary={'id':'normal','pins':PINS,'genesis':SIGNET_GENESIS,'excluded':[], 'members':[
            {'id':'bank','kind':'wallet','role':'funding_bank','identity':'original-bank','descriptors':['bank-external','bank-change'],'verification_sequence':1},
            {'id':'client','kind':'wallet','role':'customer','identity':'original-client','descriptors':['client-external'],'verification_sequence':2}]}
        for member in self.boundary['members']:
            self.store.event('treasury_member_verified',{'member':{k:v for k,v in member.items()if k!='verification_sequence'},'genesis':SIGNET_GENESIS,'financial_pins':PINS})
            member['verification_sequence']=self.last()
        self.parent=wire([('0'*64,4294967295)],[(1000,b'\x51')]);self.parent_id=decode_transaction(self.parent.hex())['txid']
        self.transfer=wire([(self.parent_id,0)],[(600,b'\x52'),(300,b'\x53')]);self.transfer_id=decode_transaction(self.transfer.hex())['txid']
        self.injection=wire([('e'*64,0)],[(2500000,b'\x51')]);self.injection_id=decode_transaction(self.injection.hex())['txid']
        self.values={}
        for raw,height in ((self.parent,1),(self.transfer,102),(self.injection,99)):
            tx=decode_transaction(raw.hex());self.values[tx['txid']]={'txid':tx['txid'],'hex':raw.hex(),'confirmations':102-height+1,'blockhash':block(height)}
        outer=self
        class Chain:
            def identity(inner):return {'chain':'signet','blocks':102,'bestblockhash':block(102),'initialblockdownload':False}
            def call(inner,method,*args):
                if method=='getblockhash':return SIGNET_GENESIS if args==(0,)else block(args[0])
                if method=='getdescriptorinfo':return {'descriptor':args[0],'hasprivatekeys':False}
                if method=='deriveaddresses':return [{'bank-external':'bank-owned','bank-change':'bank-change-owned','client-external':'client-owned'}[args[0]]]
                if method=='validateaddress':return {'isvalid':True,'scriptPubKey':{'bank-owned':'51','client-owned':'52','bank-change-owned':'53'}[args[0]]}
                raise AssertionError(method)
            def tx(inner,txid):return outer.values[txid]
        self.chain=Chain();self.qualified=None
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def package(self,transfer=False):
        point=self.parent_id if transfer else self.injection_id;amount=1000 if transfer else 2500000
        now=datetime.now(timezone.utc)-timedelta(seconds=2)
        bank={'getwalletinfo':{'scanning':False,'descriptors':True,'txcount':1},'getbalances':{'mine':{'untrusted_pending':0,'immature':0}},
            'listdescriptors':{'descriptors':[{'desc':'bank-external'},{'desc':'bank-change'}]},'listlockunspent':[], 'locked_gettxout':{},
            'listtransactions':[{'txid':point,'confirmations':100 if transfer else 2,'category':'receive'}],
            'listunspent':[{'txid':point,'vout':0,'address':'bank-owned','amount':Decimal(amount)/100000000,'scriptPubKey':'51',
                'confirmations':100 if transfer else 2,'spendable':True,'solvable':True,'safe':True}],
            'getaddressinfo':{'bank-owned':{'ismine':True,'hdkeypath':'m/84h/1h/0h/0/1','scriptPubKey':'51'}}}
        core={'before':{'chain':'signet','blocks':100,'bestblockhash':block(100),'initialblockdownload':False,'verificationprogress':Decimal('0.1234567890123')},'after':{'chain':'signet','blocks':100,'bestblockhash':block(100),'initialblockdownload':False,'verificationprogress':Decimal('0.1234567890123')},'genesis':SIGNET_GENESIS}
        fixture={};runtime={};files={};index=[]
        def rpc(source,method,params,result):
            number=len(index)+1;request=f'rpc/{number}.request';response=f'rpc/{number}.response'
            files[request]=encode({'jsonrpc':'2.0','id':number,'method':method,'params':params})
            files[response]=encode({'jsonrpc':'2.0','id':number,'result':result})
            index.append({'source':source,'method':method,'params':params,'request':request,'response':response,'response_sha256':digest(files[response])})
        rpc('core','getblockchaininfo',[],core['before']);rpc('core','getblockhash',[0],SIGNET_GENESIS)
        for key,args in [('getwalletinfo',[]),('getbalances',[]),('listdescriptors',[False]),('listunspent',[0,9999999,[],True,{'maximumCount':2001,'include_immature_coinbase':True}]),('listlockunspent',[]),('listtransactions',['*',2001,0,True])]:rpc('bank_core',key,args,bank[key])
        rpc('bank_core','getaddressinfo',['bank-owned'],bank['getaddressinfo']['bank-owned']);rpc('core','getblockchaininfo',[],core['after'])
        files['rpc-original-index.private.json']=encode(index)
        for name,value in [('bank',bank),('core',core),('fixture_cln',fixture),('runtime',runtime)]:files[name+'.json']=encode(value)
        manifest={'files':{name:{'sha256':digest(raw),'size_bytes':len(raw)}for name,raw in files.items()},
            'originals_map':{name:name+'.json'for name in ('bank','core','fixture_cln','runtime')},
            'original_sha256':{name:digest(files[name+'.json'])for name in ('bank','core','fixture_cln','runtime')},
            'source_program_sha256':'a'*64,'source_observation_id':'c'*32,'unresolved_sources':[],
            'started_at':now.isoformat(),'completed_at':now.isoformat(),'height':100,'tip_hash':block(100),'rpc_count':len(index)}
        return {'manifest_bytes':encode(manifest),'files':files}
    def injection_doc(self):
        return {'schema':'track-a-supplemental-funding-declaration-v1','track':'A','classification':'EXTERNAL_INJECTION',
            'recycled_principal_sat':0,'txid':self.injection_id,'vout':0,'amount_sat':2500000,'script_pubkey':'51',
            'recipient_address':'bank-owned','recipient_confirmation':False,'batch_fee_sat':999999}
    def transfer_doc(self):
        return {'schema':'track-a-bank-transfer-intent-v1','classification':'INTERNAL_TRANSFER','source_member':'bank',
            'txid':self.transfer_id,'signed_raw_sha256':digest(self.transfer),'input_outpoints':[self.parent_id+':0'],
            'outputs':[{'vout':0,'amount_sat':600,'script':'52','destination_member':'client','descriptor_index':0,'child_index':1,'kind':'transfer'},
                {'vout':1,'amount_sat':300,'script':'53','destination_member':'bank','descriptor_index':1,'child_index':1,'kind':'change'}],
            'maximum_miner_fee_sat':100,'recycled_principal_sat':0}
    def admit(self,doc,package,transfer=False,mutate_source=None):
        raw=encode(doc);sha=digest(raw);package['declaration_bytes']=raw
        entry={'declaration_sha256':sha,'kind':'bank_transfer'if transfer else 'external_injection','bank_manifest_sha256':digest(package['manifest_bytes'])}
        boundary_sha=digest(canonical(self.boundary).encode())
        if transfer:
            manifest=ownership.strict_json(package['manifest_bytes'])
            source={'financial_pins':PINS,'boundary_sha256':boundary_sha,'bank_member_id':'bank',
                'manifest_sha256':entry['bank_manifest_sha256'],'source_program_sha256':'a'*64,
                'height':100,'tip_hash':block(100),'completed_at':manifest['completed_at']}
            if mutate_source:mutate_source(source)
            self.store.event('normal_bank_source_captured',source);entry['source_sequence']=self.last()
            self.store.event('normal_bank_transfer_prepared',{'financial_pins':PINS,'boundary_sha256':boundary_sha,'bank_member_id':'bank',
                'source_sequence':entry['source_sequence'],'declaration_sha256':sha,'txid':doc['txid'],
                'signed_raw_sha256':doc['signed_raw_sha256'],'maximum_miner_fee_sat':doc['maximum_miner_fee_sat']});entry['prepared_sequence']=self.last()
            self.store.event('normal_bank_transfer_broadcast_intent',{'financial_pins':PINS,'prepared_sequence':entry['prepared_sequence'],'txid':doc['txid']});entry['broadcast_sequence']=self.last()
        self.qualified={'financial_pins':PINS,'boundary_sha256':boundary_sha,'module_sha256':digest(Path(ownership.__file__).read_bytes()),
            'bank_ownership_sha256':module_hash(ownership.bank_output_ownership),'bank_source_program_sha256':'a'*64,'bank_member_id':'bank','declarations':[entry]}
        self.store.event('normal_funding_ownership_sources_qualified',self.qualified);self.sequence=self.last()
        return {sha:package}
    def last(self):return self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    def verify(self,packages):return ownership.verify_funding_ownership(self.store,self.chain,qualification_sequence=self.sequence,boundary=self.boundary,packages=packages,height=102,tip_hash=block(102))
    def test_injection_requires_actual_bank_descriptor_and_raw_output_ignores_confirmation_fee_flags(self):
        packages=self.admit(self.injection_doc(),self.package());before=self.last();result=self.verify(packages)
        self.assertEqual(2500000000,result['flow_records'][0]['amount_msat']);self.assertEqual([],result['cost_records'])
        self.assertEqual(before,self.last());self.assertEqual('bank',result['flow_records'][0]['destination'])
    def test_historical_record_is_rejoined_by_actual_verifier_not_a_caller_flag(self):
        packages=self.admit(self.injection_doc(),self.package());record=self.verify(packages)['flow_records'][0]
        self.store.event('treasury_flow_verified',record);sequence=self.last()
        decoded=decode_transaction(self.injection.hex())
        self.values[self.injection_id]['vout']=[{'n':v['vout'],'value':Decimal(v['amount_sat'])/100000000,'scriptPubKey':{'hex':v['script']}}for v in decoded['outputs']]
        source={'financial_pins':PINS,'boundary_id':self.boundary['id'],'height':102,'tip_hash':block(102),
            'flow_sequences':[sequence],'cost_sequences':[],'injection_declaration_hashes':list(packages)}
        with self.assertRaisesRegex(ValueError,'ownership rejoin'):verified_money(self.store,self.chain,source)
        context={'qualification_sequence':self.sequence,'packages':packages}
        flows,costs=verified_money(self.store,self.chain,source,boundary=self.boundary,funding_context=context)
        self.assertEqual(2500000000,flows[0]['amount_msat']);self.assertEqual({},costs)
        with self.assertRaisesRegex(ValueError,'boundary'):
            verified_money(self.store,self.chain,{**source,'boundary_id':'substituted'},boundary=self.boundary,funding_context=context)
    def test_transfer_proves_all_original_inputs_outputs_change_and_full_miner_fee(self):
        packages=self.admit(self.transfer_doc(),self.package(True),True);result=self.verify(packages)
        self.assertEqual(600000,result['flow_records'][0]['amount_msat']);self.assertEqual(100000,result['cost_records'][0]['amount_msat'])
        self.assertEqual(1,len(result['flow_records']));self.assertEqual('bank',result['cost_records'][0]['source'])
    def test_wrong_actual_descriptor_or_core_amount_refuses_despite_admitted_index(self):
        packages=self.admit(self.injection_doc(),self.package())
        original=self.chain.call
        self.chain.call=lambda method,*args: ['foreign']if method=='deriveaddresses'else original(method,*args)
        with self.assertRaisesRegex(ValueError,'ownership differs'):self.verify(packages)
        self.chain.call=original;self.values[self.injection_id]['hex']=self.transfer.hex()
        with self.assertRaisesRegex(ValueError,'identity differs'):self.verify(packages)
    def test_foreign_input_destination_cap_and_signed_body_refuse(self):
        variants=[('input',lambda d:d['input_outpoints'].__setitem__(0,'f'*64+':0')),
            ('destination',lambda d:d['outputs'][0].update(destination_member='bank',descriptor_index=0)),
            ('cap',lambda d:d.update(maximum_miner_fee_sat=99)),('signed',lambda d:d.update(signed_raw_sha256='f'*64)),
            ('missing_output',lambda d:d['outputs'].pop()),('change',lambda d:d['outputs'][1].update(kind='transfer'))]
        for name,change in variants:
            with self.subTest(name=name):
                doc=self.transfer_doc();change(doc);packages=self.admit(doc,self.package(True),True)
                with self.assertRaises(ValueError):self.verify(packages)
    def test_modified_bank_aggregate_rpc_id_and_missing_private_frame_refuse(self):
        packages=self.admit(self.injection_doc(),self.package());p=next(iter(packages.values()))
        for change in ('aggregate','rpcid','missing'):
            altered=copy.deepcopy(packages);package=next(iter(altered.values()))
            if change=='aggregate':package['files']['bank.json']=b'{}'
            elif change=='rpcid':package['files']['rpc/1.response']=encode({'jsonrpc':'2.0','id':999,'result':{}})
            else:package['files'].pop('rpc/1.response')
            with self.subTest(change=change),self.assertRaises(ValueError):self.verify(altered)
        self.assertEqual(2500000000,self.verify(packages)['flow_records'][0]['amount_msat'])
    def test_original_bank_snapshot_must_precede_transfer_and_be_journal_bound(self):
        packages=self.admit(self.transfer_doc(),self.package(True),True,lambda v:v.update(manifest_sha256='f'*64))
        with self.assertRaisesRegex(ValueError,'before publication'):self.verify(packages)
        packages=self.admit(self.transfer_doc(),self.package(True),True)
        self.values[self.transfer_id]['confirmations']=3;self.values[self.transfer_id]['blockhash']=block(100)
        with self.assertRaisesRegex(ValueError,'before publication'):self.verify(packages)
    def test_absent_input_from_authentic_bank_or_wrong_destination_script_holds(self):
        package=self.package(True);doc=self.transfer_doc();packages=self.admit(doc,package,True)
        original=self.chain.call
        self.chain.call=lambda method,*args: {'isvalid':True,'scriptPubKey':'54'}if method=='validateaddress'and args==('client-owned',)else original(method,*args)
        with self.assertRaisesRegex(ValueError,'destination descriptor'):self.verify(packages)
    def test_unconfirmed_reorg_and_wrong_global_tip_hold(self):
        packages=self.admit(self.injection_doc(),self.package())
        self.values[self.injection_id]['confirmations']=0
        with self.assertRaisesRegex(ValueError,'active confirmed'):self.verify(packages)
        self.values[self.injection_id]['confirmations']=4;self.values[self.injection_id]['blockhash']='f'*64
        with self.assertRaisesRegex(ValueError,'active confirmed'):self.verify(packages)
    def test_duplicate_physical_flow_and_changed_existing_record_hold_idempotent_import_preserves_oldpins(self):
        packages=self.admit(self.injection_doc(),self.package());result=self.verify(packages);record=result['flow_records'][0]
        original={**record,'financial_pins':{**PINS,'product_commit':'f'*40}};self.store.event('treasury_flow_verified',original)
        reused=self.verify(packages);self.assertEqual([],reused['flow_records']);self.assertEqual(original,reused['verified_flow_records'][record['monetary_id']])
        self.store.event('treasury_flow_verified',original)
        with self.assertRaisesRegex(ValueError,'duplicated'):self.verify(packages)
    def test_actual_foreign_wire_input_cannot_borrow_original_bank_inventory(self):
        raw=wire([('f'*64,0)],[(600,b'\x52'),(300,b'\x53')]);txid=decode_transaction(raw.hex())['txid']
        self.values[txid]={'txid':txid,'hex':raw.hex(),'confirmations':1,'blockhash':block(102)}
        doc=self.transfer_doc();doc.update(txid=txid,signed_raw_sha256=digest(raw),input_outpoints=['f'*64+':0'])
        packages=self.admit(doc,self.package(True),True)
        with self.assertRaisesRegex(ValueError,'absent/duplicated'):self.verify(packages)
    def test_wrong_qualification_module_manifest_or_member_proof_is_not_ownership(self):
        packages=self.admit(self.injection_doc(),self.package())
        self.qualified['module_sha256']='f'*64;self.store.event('normal_funding_ownership_sources_qualified',self.qualified);self.sequence=self.last()
        with self.assertRaisesRegex(ValueError,'qualification differs'):self.verify(packages)
        packages=self.admit(self.injection_doc(),self.package())
        self.boundary['members'][1]['verification_sequence']=1
        with self.assertRaises(ValueError):self.verify(packages)
    def test_repeated_physical_injection_is_rejected_even_with_two_admitted_originals(self):
        packages=self.admit(self.injection_doc(),self.package())
        doc={**self.injection_doc(),'purpose':'second classification cannot mint capital twice'};raw=encode(doc);sha=digest(raw)
        package=copy.deepcopy(next(iter(packages.values())));package['declaration_bytes']=raw;packages[sha]=package
        self.qualified['declarations'].append({**self.qualified['declarations'][0],'declaration_sha256':sha})
        self.store.event('normal_funding_ownership_sources_qualified',self.qualified);self.sequence=self.last()
        with self.assertRaisesRegex(ValueError,'physical funding output supplied twice'):self.verify(packages)
    def test_existing_source_label_is_not_ownership_and_unsupported_schema_holds(self):
        doc=self.injection_doc();doc['schema']='legacy-funding-label';packages=self.admit(doc,self.package())
        with self.assertRaisesRegex(ValueError,'unsupported historical'):self.verify(packages)
    def test_injection_doc_amount_script_recycling_or_foreign_bank_holds(self):
        for field,value in [('amount_sat',2499999),('script_pubkey','54'),('recipient_address','foreign'),('recycled_principal_sat',1)]:
            doc=self.injection_doc();doc[field]=value;packages=self.admit(doc,self.package())
            with self.subTest(field=field),self.assertRaises(ValueError):self.verify(packages)
