"""Real journal/consumer plumbing with explicit native-proof stubs; no crypto credit."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from simulator import normal_lineage_join as join
from simulator.model import SIGNET_GENESIS, canonical
from simulator.normal_pending_board import verify_pending_boards
from tests import test_normal_pending_board as pending_tests


class LineageIntegrationTests(unittest.TestCase):
    def setUp(self):
        pending_tests.PendingTests.setUp(self)
        self.native.stop()
        self.store.queue('archived-snapshot','actor-01','H01','snapshot',{},0);self.store.claim({'snapshot'});self.store.finish('archived-snapshot','completed',{'status':'ok','data':{}},0)
        self.original=self.coin;self.ids=[self.original,'e'*64+':0','e'*64+':1','f'*64+':0','f'*64+':1']
        amounts=[670,400,270,200,200];actors=['actor-01','actor-01','actor-02','actor-01','actor-04']
        self.store.db.execute('DELETE FROM owned_coin');self.store.db.execute('DELETE FROM owner_key')
        self.tables['vtxo']=self.tables['vtxo'][1:];self.tables.update(round=[],round_participation=[],round_part_input=[],round_part_output=[],key_link=[],fallback_record=[])
        self.coins={};self.paths={};self.reply_by_full={}
        for n,(ident,sat,actor)in enumerate(zip(self.ids,amounts,actors),1):
            key='02'+format(n,'064x');mailbox='02'+format(n+10,'064x');raw=format(n,'02x');spk='0014'+'1'*40
            binding={'mailbox_pk':mailbox,'spk':spk,'seq':0}
            proof={'id':ident,'user_pubkey':key,'amount_sat':sat,'chain_anchor':self.root,'expiry_height':148,'server_pubkey':self.server,'binding':binding}
            self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,actor,mailbox,'{}'))
            self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',(ident,key,sat,hashlib.sha256(bytes.fromhex(raw)).hexdigest(),raw,canonical(proof)))
            self.store.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',(ident,'archived-snapshot','Spent'if n in(1,2)else'Spendable',n))
            path=[{'txid':ident.split(':')[0],'output_index':int(ident.split(':')[1]),'inputs':[self.root]if n==1 else[self.original if n in(2,3)else self.ids[1]],'output_amount_sat':sat}]
            row={'vtxo_id':ident,'anchor_point':self.root,'signed_vtxo_hex':raw,'amount':sat,'expiry':148,'exit_delta':12,'policy_type':'pubkey','server_pubkey':self.server,'spend_state':'spent'if n in(1,2)else'spendable','oor_spent_txid':'e'*64 if n==1 else'f'*64 if n==2 else None,'onchain_spent_txid':None,'spent_in_round':None,'offboarded_in':None}
            self.tables['vtxo'].append(row);self.tables['key_link'].append({'user_pubkey':key,'mailbox_pk':mailbox,'sig':'key-signature'})
            self.tables['fallback_record'].append({'mailbox_pk':mailbox,'spk':spk,'seq':0,'sig':'record-signature'})
            self.reply_by_full[raw]={**proof,'genesis':SIGNET_GENESIS,'signed_path_valid':True,'authorization_path_valid':True,'conditional_steps':0,'path':path,'binding':{**binding,'record_signature_valid':True,'key_link_signature_valid':True}}
        # Root rows precede registered leaves in the source, without semantic ordering.
        root=self.tables['vtxo'][0];self.tables['vtxo'][0]=self.tables['vtxo'][1];self.tables['vtxo'][1]=root
        self.send('split-one',self.ids[0],self.ids[1],self.ids[2],270,'actor-02')
        self.send('split-two',self.ids[1],self.ids[3],self.ids[4],200,'actor-04')
        self.executed=[]
        def native(tool,request):
            self.executed.append(copy.deepcopy(request))
            if 'pending_vtxo'in request:
                proof={**self.proof,'user_pubkey':'02'+format(1,'064x'),'anchor_spender_txid':self.original.split(':')[0]}
            elif 'anchor_raw'in request:
                row=self.reply_by_full[request['signed_vtxo']]
                proof={**row,'chain_contract_verified':True,'tree_padding':False,'policy':'pubkey','candidate_user_pubkey':row['user_pubkey'],'unlock_hash':None}
            else:proof=self.reply_by_full[request['signed_vtxo']]
            return canonical(request).encode(),canonical(proof).encode()
        self.proof_patch=patch('simulator.two_step_normal.run_proof',side_effect=native);self.proof_patch.start();self.addCleanup(self.proof_patch.stop)
        self.tools={'binding':{'sha256':'1'*64},'policy':{'sha256':'2'*64}}
    def tearDown(self):pending_tests.PendingTests.tearDown(self)
    def send(self,name,parent,change,receipt,sat,recipient):
        args={'destination':'public-'+name,'amount_sat':sat,'recipient_actor':recipient}
        movement={'id':name+'-sender','subsystem':'bark.arkoor','status':'successful','input_vtxos':[parent],'output_vtxos':[change],'offchain_fee_sat':0,'effective_balance_sat':-sat}
        self.store.queue(name,'actor-01','H02','send_arkoor',args,0);self.store.claim({'send_arkoor'})
        self.store.finish(name,'completed',{'status':'ok','data':{'amount_sat':sat,'submitted':'send_arkoor','evidence':{'movements':[movement]}}},0)
        self.store.event('driver_evidence',{'action_id':name,'event':'arkoor_request','data':{'input_vtxo_ids':[parent],'destination':args['destination'],'amount_sat':sat}})
        received={'subsystem':'bark.arkoor','status':'successful','input_vtxos':[],'output_vtxos':[receipt],'effective_balance_sat':sat,'offchain_fee_sat':0}
        self.store.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',(recipient,name+'-receipt',canonical(received)))
        self.store.event('ark_transfer_verified',{'action_id':name,'recipient_actor':recipient,'sender_actor':'actor-01','input_coin_ids':[parent],'amount_sat':sat,'destination':args['destination'],'sender_movement_id':movement['id'],'receipt_movement_id':name+'-receipt','receipts':[{'coin_id':receipt}]})
    def frontier(self,**changes):
        options={'server_pubkey':self.server,'genesis':SIGNET_GENESIS,'native_source_sha256':'a'*64,'observation_id':'b'*32,'configuration':join.CONFIGURATION};options.update(changes)
        return join.authenticate_frontier(self.store,self.tables,self.tools,**options)
    def test_real_two_split_journal_frontier_then_pending_join_preserves_all_rights(self):
        before=self.store.db.execute('SELECT count(*)FROM event').fetchone()[0];value=self.frontier()
        self.assertEqual([self.ids[n]for n in(2,3,4)],value['current_claim_ids'])
        self.assertEqual(670,sum(row['amount_sat']for row in value['claims']))
        self.assertEqual(10,len(self.executed)) # Every original/intermediate/current coin, two supplied-byte tools.
        self.assertEqual(5,len(join.public_frontier(value)['coin_proof_hashes']))
        authenticated=[{**claim,'chain_anchor':self.root}for claim in value['claims']]
        result=verify_pending_boards(self.store,self.tables,authenticated,self.chain,self.tool,server_pubkey=self.server,height=100,tip_hash=self.tip,fresh_backing=self.fresh,recovered=None,lineage_context=value)
        self.assertEqual(value['current_claim_ids'],result['resolved_registered_boards'][0]['current_claim_ids'])
        self.assertEqual(0,result['customer_payment_credit_sat']);self.assertEqual(before,self.store.db.execute('SELECT count(*)FROM event').fetchone()[0])
    def test_missing_intermediate_full_and_foreign_branch_cannot_retire_principal(self):
        self.tables['vtxo']=[row for row in self.tables['vtxo']if row['vtxo_id']!=self.ids[1]]
        with self.assertRaisesRegex(ValueError,'Full missing'):self.frontier()
    def test_native_spender_mismatch_refuses_even_with_same_amounts_and_journal(self):
        next(row for row in self.tables['vtxo']if row['vtxo_id']==self.original)['oor_spent_txid']='d'*64
        with self.assertRaisesRegex(ValueError,'disposition'):self.frontier()
    def test_source_configuration_nonce_and_unresolved_rounds_hold_before_proof(self):
        for kw in [{'observation_id':'foreign'},{'configuration':{**join.CONFIGURATION,'source_sha256':'0'*64}},
                {'configuration':{**join.CONFIGURATION,'schema_version':True}}]:
            with self.subTest(kw=kw),self.assertRaisesRegex(ValueError,'source/observation'):self.frontier(**kw)
        self.tables['round']=[{'signed_tree_bytes':123}]
        with self.assertRaisesRegex(ValueError,'exhaustive signed-tree'):self.frontier()
        self.assertEqual([],self.executed)
    def test_missing_original_recipient_movement_stays_hold(self):
        self.store.db.execute("DELETE FROM movement_evidence WHERE movement_id='split-two-receipt'")
        with self.assertRaisesRegex(ValueError,'recipient movement'):self.frontier()
    def test_unknown_current_spend_does_not_remove_right(self):
        next(row for row in self.tables['vtxo']if row['vtxo_id']==self.ids[4])['offboarded_in']='unproven'
        with self.assertRaisesRegex(ValueError,'unexplained native spend'):self.frontier()
    def test_group_omission_mixed_origins_or_foreign_backing_refuse(self):
        value=self.frontier();claims={row['coin_id']:row for row in value['claims']};rows={row['vtxo_id']:row for row in self.tables['vtxo']}
        cases=[]
        missing=copy.deepcopy(value);missing['obligation_groups'][0]['current_claim_ids'].append('9'*64+':0');cases.append((missing,rows))
        mixed=copy.deepcopy(value);mixed['obligation_groups'][0]['original_claim_ids'].append('8'*64+':0');cases.append((mixed,rows))
        foreign=copy.deepcopy(rows);foreign[self.ids[4]]['anchor_point']='7'*64+':0';cases.append((value,foreign))
        for v,native in cases:
            with self.subTest(v=v['current_claim_ids']),self.assertRaises(ValueError):join.board_descendants(v,self.original,claims,native)
    def test_discovery_keeps_consumed_original_and_intermediate_roots(self):
        self.assertEqual(set(self.ids),{row['coin_id']for row in join.original_claims(self.store)})


class LineageAdmissionTests(unittest.TestCase):
    def setUp(self):
        from tests import test_two_step_capture_admission as admission_tests
        admission_tests.AdmissionTests.setUp(self)
        from simulator.two_step_capture import SourceCapture
        self.tools={'binding':{'command':['/exact/binding'],'sha256':'a'*64},'policy':{'command':['/exact/policy'],'sha256':'b'*64}}
        self.capture=SourceCapture(self.target.read,self.member.read,self.sequence,self.boundary,self.config,lineage_tools=self.tools)
        self.value['ordinary_lineage']=join.CONFIGURATION
        self.value['proof_tool_sha256']={name:tool['sha256']for name,tool in self.tools.items()}
        from simulator.two_step_normal import digest
        self.value['proof_commands_sha256']={name:digest(canonical(tool['command']).encode())for name,tool in self.tools.items()}
    def tearDown(self):
        from tests import test_two_step_capture_admission as admission_tests
        admission_tests.AdmissionTests.tearDown(self)
    def event(self):
        self.store.event('normal_financial_collector_qualified',self.value)
        self.capture.admission_sequence=self.store.db.execute('SELECT max(sequence)FROM event').fetchone()[0]
    def test_both_actual_lineage_sources_and_exact_tools_must_be_admitted(self):
        from simulator.two_step_normal import module_hash
        from simulator.normal_lineage import bind_coin
        from tests.test_final_campaign import PINS
        self.event()
        with self.assertRaisesRegex(ValueError,'qualification'):self.capture.admission(self.store,{'financial_pins':PINS})
        self.value['capture_dependencies_sha256'].update(ordinary_lineage=module_hash(join.authenticate_frontier),typed_lineage=module_hash(bind_coin))
        self.event();self.capture.admission(self.store,{'financial_pins':PINS})
        self.tools['binding']['command']=['/other/binding']
        with self.assertRaisesRegex(ValueError,'tools differ'):self.capture.admission(self.store,{'financial_pins':PINS})


if __name__=='__main__':unittest.main()
