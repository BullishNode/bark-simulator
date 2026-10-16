"""Synthetic ordinary source joins; no signatures/native/financial qualification."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from simulator.b_current_native_liabilities import current_ordinary_liabilities
from simulator.bundle_audit import decode_transaction
from simulator.direct_settlements import initialize
from simulator.model import SIGNET_GENESIS, canonical
from simulator.negative_checks import record_bytes
from simulator.ownership import EvidenceGap
from simulator.public_absence import TABLES
from simulator.store import Store
from tests.account_fixtures import proof as account_proof


def raw_transaction(point, outputs):
    txid,index = point.split(':')
    return ('02000000'+'01'+bytes.fromhex(txid)[::-1].hex()+int(index).to_bytes(4,'little').hex()
        +'00'+'fdffffff'+len(outputs).to_bytes(1,'little').hex()+''.join(
            amount.to_bytes(8,'little').hex()+len(bytes.fromhex(script)).to_bytes(1,'little').hex()+script
            for amount,script in outputs)+'00000000')


class CurrentRightsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name),'synthetic',10000)
        self.addCleanup(self.store.close)
        self.store.actor('actor-01','synthetic ordinary source')
        self.store.register_catalog([{'id':'synthetic','behavior':'synthetic source controls'}],{'synthetic'})
        initialize(self.store)
        self.pub='02'+'55'*32;self.server='03'+'77'*32;self.mb='02'+'66'*32
        self.destination='0014'+'33'*20;self.operator='5120'+'44'*32
        self.source_script='5120'+'88'*32;self.anchor_script='5120'+'99'*32
        self.record={'mailbox_pk':self.mb,'spk':self.destination,'account_xpub':'11'*78,
                     'mailbox_sig':'22'*64,'account_sig':'33'*64}
        self.binding={'mailbox_pk':self.mb,'spk':self.destination,
                      'account_xpub':self.record['account_xpub'],'fallback_record':record_bytes(self.record)}
        bound=account_proof({'user_pubkey':self.pub,'binding':self.binding})['binding']
        self.store.db.execute('INSERT INTO owner_key VALUES(?,?,?,?)',
            (self.pub,'actor-01',self.mb,canonical(bound)))
        self.store.db.execute('INSERT INTO owner_record VALUES(?,?,?,?,?)',
            ('actor-01',self.mb,self.record['account_xpub'],self.destination,canonical(bound)))
        self.store.db.execute('INSERT INTO operator_script VALUES(?,?)',(self.operator,'{}'))
        self.database={'kind':'closed_frontier','database_tables_complete':True,
            'inventory_consistent':True,'read_only':True,'rows':{name:[]for name in TABLES}}
        self.rows=self.database['rows'];link={'user_pubkey':self.pub,'mailbox_pk':self.mb,'child_index':0}
        self.rows.update(records=[self.record],links=[link],journal_records=[self.record],journal_links=[link])
        self.transactions={};self.raw={};self.utxos={};self.height=101;self.tip='e'*64
        self.block='d'*64;self.leaves=[];self.anchors=[]
        for number in (1,2):self.add_root(number)
        outer=self
        class Chain:
            def transaction(self,txid):return copy.deepcopy(outer.transactions[txid])
            def tx(self,txid):return copy.deepcopy(outer.raw[txid])
            def call(self,method,*args,**kwargs):
                if method=='getblockchaininfo':return {'chain':'signet','initialblockdownload':False,'blocks':outer.height,'bestblockhash':outer.tip}
                if method=='getblockhash':return SIGNET_GENESIS if args[0]==0 else outer.tip if args[0]==outer.height else outer.block
                if method=='gettxout':
                    item=outer.utxos.get(args[0]+':'+str(args[1]))
                    if item is None:return None
                    return {'confirmations':2,'value':str(item[0]/100_000_000),
                            'scriptPubKey':{'hex':item[1]}}
                raise AssertionError(method)
        self.chain=Chain()

    def coin(self,point,amount,anchor,kind,policy,spender=None):
        return {'vtxo_id':point,'amount':amount,'expiry':150,'anchor_point':anchor,
            'vtxo_txid':point.split(':')[0],'policy_type':kind,'policy':policy,
            'spend_state':'spent' if spender else 'spendable','oor_spent_txid':spender,
            'spent_in_round':None,'offboarded_in':None,'frontier_at':None,
            'confirmed_height':100 if point==anchor else None,
            'onchain_spent_txid':None,'onchain_spent_height':None}

    def add_root(self,number):
        anchor=f'{number:064x}'+':0'
        raw=raw_transaction(anchor,[(20000,self.source_script),(1000,'51024e73')])
        body=decode_transaction(raw,public_body=True);point=body['txid']+':0'
        outputs=[{'vout':r['vout'],'value_sat':r['amount_sat'],'script_pubkey':r['script']}for r in body['outputs']]
        proof=account_proof({'id':point,'amount_sat':20000,'user_pubkey':self.pub,
            'server_pubkey':self.server,'expiry_height':150,'chain_anchor':anchor,
            'anchor_confirmations':2,'proof_encoding':'ark-public-authorization-v1',
            'authorization_path_valid':True,'signed_path_valid':True,'conditional_steps':0,
            'genesis':SIGNET_GENESIS,'binding':self.binding,'ancestor_ids':[anchor,point],
            'path':[{'txid':body['txid'],'output_index':0,'inputs':[anchor],
                     'transaction':raw,'outputs':outputs}]})
        self.store.db.execute('INSERT INTO owned_coin VALUES(?,?,?,?,?,?)',
            (point,self.pub,20000,'synthetic-public-digest','synthetic-public-encoding',canonical(proof)))
        action='snapshot-'+str(number)
        self.store.queue(action,'actor-01','synthetic','snapshot',{},0)
        self.store.db.execute('INSERT INTO coin_observation VALUES(?,?,?,?)',(point,action,'Spendable',number))
        self.rows['coins'] += [self.coin(anchor,21000,anchor,'expiry','04',body['txid']),
                               self.coin(point,20000,anchor,'pubkey','00'+self.pub)]
        self.transactions[anchor.split(':')[0]]={'txid':anchor.split(':')[0],
            'outputs':[{'vout':0,'amount_sat':21000,'script':self.anchor_script}],
            'confirmations':2,'blockhash':self.block}
        self.utxos[anchor]=(21000,self.anchor_script)
        self.leaves.append(point);self.anchors.append(anchor)

    def collect(self):
        return current_ordinary_liabilities(self.store,self.chain,self.database,
            server_pubkey=self.server,borrower='ark',tip=(self.height,self.tip),
            minimum_confirmations=1,actor_member_ids={'actor-01':'customer-01'})

    def carrier(self,confirmed):
        point,anchor=self.leaves[0],self.anchors[0]
        source=self.store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(point,)).fetchone()
        proof=json.loads(source['proof']);anchor_txid=point.split(':')[0]
        allocations=[{'id':point,'freeze_set':'first-root','owner_pubkey':self.pub,'spk':self.destination,
            'disposition':'pay','gross_sat':20000,'fee_sat':1000,'payout_sat':19000,
            'forfeited_sat':0,'source':'registered','retirement_ids':[anchor],'frozen_at':'synthetic'},
            {'id':anchor_txid+':1','freeze_set':'first-root','owner_pubkey':None,'spk':None,
             'disposition':'operator','gross_sat':1000,'fee_sat':0,'payout_sat':0,
             'forfeited_sat':0,'source':'transition-fee-anchor','retirement_ids':[anchor],'frozen_at':'synthetic'}]
        raw=raw_transaction(anchor,[(19000,self.destination),(1500,self.operator)])
        body=decode_transaction(raw,public_body=True);txid=body['txid']
        self.transactions[txid]={'txid':txid,'confirmations':1 if confirmed else 0,
            'blockhash':self.tip if confirmed else None,'fee_sat':500,
            'inputs':[{'outpoint':anchor,'amount_sat':21000,'script':self.anchor_script}],
            'outputs':body['outputs']}
        self.raw[txid]={'hex':raw,'weight':body['weight'],'vsize':body['vsize']}
        carrier={'txid':txid,'generation':1,'backing_ids':[anchor],'fee_inputs':[],
            'miner_fee_sat':500,'funding_subsidy_sat':0,'created_at':'synthetic',
            'confirmed_height':101 if confirmed else None,'confirmed_block':self.tip if confirmed else None}
        self.rows.update(journal_allocations=allocations,journal_carriers=[carrier],
            journal_mappings=[{'txid':txid,'allocation_id':r['id'],'vout':0 if r['disposition']=='pay' else None}for r in allocations])
        if confirmed:
            self.utxos.pop(anchor)
            next(r for r in self.rows['coins'] if r['vtxo_id']==anchor).update(onchain_spent_txid=txid,onchain_spent_height=101)
        return txid

    def test_two_new_signed_roots_are_both_current_liabilities_no_store_write(self):
        before=self.store.db.total_changes;result=self.collect()
        self.assertEqual(self.store.db.total_changes,before)
        self.assertEqual(40000,result['outstanding_liability_sat'])
        self.assertEqual(2,len(result['liabilities']))
        self.assertEqual(4,len(result['signed_graph_coin_ids']))

    def test_terminal_old_root_and_new_unsettled_right_coexist(self):
        self.carrier(True);result=self.collect()
        self.assertEqual(20000,result['outstanding_liability_sat'])
        self.assertEqual(['coin:'+self.leaves[1]],[r['id']for r in result['liabilities']])
        self.assertEqual({'confirmed_pay','unsettled'},{r['state']for r in result['dispositions']})

    def test_mempool_allocation_never_debits_original_gross(self):
        self.carrier(False);result=self.collect()
        self.assertEqual(40000,result['outstanding_liability_sat'])
        self.assertEqual([],result['groups'])

    def test_frozen_without_carrier_never_debits_original_gross(self):
        self.carrier(False);self.rows['journal_carriers']=[];self.rows['journal_mappings']=[]
        self.assertEqual(40000,self.collect()['outstanding_liability_sat'])

    def test_unknown_new_native_coin_cannot_disappear_from_liabilities(self):
        self.rows['coins'].append(self.coin('f'*64+':0',20000,self.anchors[0],'pubkey','00'+self.pub))
        with self.assertRaisesRegex(EvidenceGap,'missing/extra signed source'):self.collect()

    def test_missing_historical_parent_is_not_complete_current_graph(self):
        self.rows['coins'].pop(0)
        with self.assertRaisesRegex(EvidenceGap,'missing/extra signed source'):self.collect()

    def test_wrong_native_value_or_owner_policy_refuses(self):
        self.rows['coins'][1]['amount']+=1
        with self.assertRaisesRegex(EvidenceGap,'source/value/anchor'):self.collect()
        self.rows['coins'][1]['amount']-=1;self.rows['coins'][1]['policy']='00'+'02'+'a'*64
        with self.assertRaisesRegex(EvidenceGap,'recipient policy'):self.collect()

    def test_unknown_virtual_spend_refuses(self):
        self.rows['coins'][0]['oor_spent_txid']='f'*64
        with self.assertRaisesRegex(EvidenceGap,'exact signed path'):self.collect()

    def test_unknown_physical_retirement_refuses(self):
        self.rows['coins'][0]['onchain_spent_txid']='f'*64
        with self.assertRaisesRegex(EvidenceGap,'physical retirement'):self.collect()

    def test_retired_backing_without_exact_group_cannot_cover_remaining_right(self):
        self.utxos.pop(self.anchors[0])
        with self.assertRaisesRegex(EvidenceGap,'current unspent original backing'):self.collect()

    def test_unknown_replacement_does_not_credit_visible_winner(self):
        self.carrier(True)
        carrier=copy.deepcopy(self.rows['journal_carriers'][0]);carrier.update(txid='f'*64,generation=2,confirmed_height=None,confirmed_block=None)
        self.rows['journal_carriers'].append(carrier)
        self.rows['journal_mappings'] += [{**r,'txid':'f'*64}for r in list(self.rows['journal_mappings'])]
        with self.assertRaisesRegex(EvidenceGap,'outcome unavailable'):self.collect()

    def test_unsupported_conditional_pool_round_domain_is_not_empty_claims(self):
        for table in ('receives','htlcs','pool','rounds','participation_inputs'):
            with self.subTest(table=table):
                self.rows[table]=[{'id':'synthetic'}]
                with self.assertRaisesRegex(EvidenceGap,'unsupported native table '+table):self.collect()
                self.rows[table]=[]

    def test_conditional_stored_authority_is_not_ordinary_right(self):
        point=self.leaves[0];row=self.store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(point,)).fetchone()
        proof=json.loads(row['proof']);proof['conditional_steps']=1
        self.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),point))
        with self.assertRaisesRegex(EvidenceGap,'unsupported/mismatched signed authority'):self.collect()

    def test_unregistered_or_unknown_state_refuses(self):
        self.rows['coins'][1]['spend_state']='unregistered'
        with self.assertRaisesRegex(EvidenceGap,'native virtual spend'):self.collect()

    def test_current_owner_must_be_declared(self):
        with self.assertRaisesRegex(EvidenceGap,'declared customer membership'):
            current_ordinary_liabilities(self.store,self.chain,self.database,server_pubkey=self.server,
                borrower='ark',tip=(self.height,self.tip),minimum_confirmations=1,actor_member_ids={})

    def test_exact_original_binding_is_required_for_new_source(self):
        self.rows['links'][0]['child_index']=1
        with self.assertRaisesRegex(EvidenceGap,'account/record binding differs'):self.collect()

    def test_recorded_expiry_spent_without_successor_keeps_liability(self):
        self.store.db.execute("UPDATE coin_observation SET state='Spent'")
        self.assertEqual(40000,self.collect()['outstanding_liability_sat'])

    def test_missing_pending_board_source_refuses(self):
        self.rows['pending_boards']=[{'vtxo_id':'f'*64+':0','expiry':150}]
        with self.assertRaisesRegex(EvidenceGap,'pending Board lacks signed'):self.collect()

    def test_unrelated_nursery_needs_separate_publication_proof(self):
        self.rows['nursery']=[{'txid':'f'*64}]
        with self.assertRaisesRegex(EvidenceGap,'unclassified nursery'):self.collect()

    def test_no_caller_completion_or_new_native_field_can_override_missing_source(self):
        self.database['complete']=True;self.rows['coins'][1]['new_urgent_state']=True
        with self.assertRaisesRegex(EvidenceGap,'unknown/missing native coin field'):self.collect()

    def test_frozen_operator_principal_requires_exact_signed_p2a(self):
        self.carrier(False);self.rows['journal_allocations'][1]['gross_sat']+=1
        with self.assertRaisesRegex(EvidenceGap,'signed P2A source'):self.collect()

    def test_frozen_operator_cannot_claim_an_unrelated_signed_root(self):
        self.carrier(False);self.rows['journal_allocations'][1]['retirement_ids']=[self.anchors[1]]
        with self.assertRaisesRegex(EvidenceGap,'signed P2A source'):self.collect()

    def test_frozen_customer_principal_and_retirement_are_not_just_labels(self):
        self.carrier(False);self.rows['journal_allocations'][0]['retirement_ids']=[self.anchors[1]]
        with self.assertRaisesRegex(EvidenceGap,'principal/retirement source'):self.collect()

    def test_canonical_root_creation_height_is_independent_of_native_marker(self):
        self.rows['coins'][0]['confirmed_height']=99
        with self.assertRaisesRegex(EvidenceGap,'canonical creation height'):self.collect()

    def test_required_depth_is_not_bypassed_by_one_confirmed_carrier(self):
        self.carrier(True)
        with self.assertRaisesRegex(EvidenceGap,'required confirmation depth'):
            current_ordinary_liabilities(self.store,self.chain,self.database,
                server_pubkey=self.server,borrower='ark',tip=(self.height,self.tip),
                minimum_confirmations=2,actor_member_ids={'actor-01':'customer-01'})

    def test_missing_public_signed_transaction_bytes_hold_not_synthetic_authority(self):
        point=self.leaves[0];row=self.store.db.execute('SELECT proof FROM owned_coin WHERE id=?',(point,)).fetchone()
        proof=json.loads(row['proof']);del proof['path'][0]['transaction']
        self.store.db.execute('UPDATE owned_coin SET proof=? WHERE id=?',(canonical(proof),point))
        with self.assertRaisesRegex(EvidenceGap,'public path body absent'):self.collect()

    def test_same_tip_required_after_current_backing_observation(self):
        original=self.chain.call
        def changed(method,*args,**kwargs):
            result=original(method,*args,**kwargs)
            if method=='gettxout':self.height+=1;self.tip='f'*64
            return result
        self.chain.call=changed
        with self.assertRaisesRegex(ValueError,'tip'):self.collect()
