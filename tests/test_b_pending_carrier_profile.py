"""Synthetic pending→confirmed source controls; not financial qualification."""
import copy
import json
import unittest
from decimal import Decimal
from simulator.b_native_signed_versions import retained_ordinary_versions
from simulator.b_continuing_profile import ContinuingDirectProfile,continuing_profile
from simulator.b_normal_profile_adapter import require_profile
from simulator.owned_mempool import decode_reply,decode_activity_reply
from simulator.ownership import EvidenceGap
from tests import test_b_current_native_liabilities as fixtures


def activity(versions,scripts):
    rows=[]
    for txid,tx in versions.items():
        if tx.get('confirmations',0):continue
        for index,coin in enumerate(tx['inputs']):
            if coin['script']in scripts:
                parent,vout=coin['outpoint'].split(':')
                rows.append({'type':'spend','amount':str(Decimal(coin['amount_sat'])/100000000),
                    'spend_txid':txid,'spend_vin':index,'prevout_txid':parent,'prevout_vout':int(vout),
                    'prevout_spk':{'hex':coin['script'],'asm':'public','type':'witness_v1_taproot'}})
        for coin in tx['outputs']:
            if coin['script']in scripts:
                rows.append({'type':'receive','amount':str(Decimal(coin['amount_sat'])/100000000),
                    'txid':txid,'vout':coin['vout'],
                    'output_spk':{'hex':coin['script'],'asm':'public','type':'witness_v1_taproot'}})
    return {'activity':rows}


class PendingCarrierControls(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.CurrentRightsTests();self.addCleanup(self.f.doCleanups);self.f.setUp()
        self.txid=self.f.carrier(False)
        self.scripts={self.f.operator:{'member_id':'watchman'},self.f.destination:{'member_id':'customer'}}
        self.override=None
        def read(scripts):
            value=activity({self.txid:self.f.transactions[self.txid]},scripts)
            return self.override(value)if self.override else value
        self.f.chain.owned_activity=read

    def collect(self):
        return retained_ordinary_versions(self.f.store,self.f.chain,self.f.database,self.f.collect(),
            scripts=self.scripts,tip=(self.f.height,self.f.tip))

    def test_pending_then_confirmed_preserves_gross_until_exact_terminal_once(self):
        before=self.f.store.db.total_changes
        rights=self.f.collect();pending=self.collect()
        self.assertEqual(40000,rights['outstanding_liability_sat'])
        self.assertEqual([],rights['groups'])
        self.assertEqual('mempool',pending['states'][self.txid])
        self.assertIn('no payment or retirement credit',pending['checked_candidates'][self.txid]['scope'])
        self.f.carrier(True)
        confirmed=self.collect();terminal=self.f.collect()
        self.assertEqual(20000,terminal['outstanding_liability_sat'])
        self.assertEqual('confirmed',confirmed['states'][self.txid])
        self.assertEqual([],confirmed['pending_txids'])
        self.assertEqual(confirmed,self.collect())
        self.assertEqual(before,self.f.store.db.total_changes)

    def test_missing_core_version_is_unknown_not_assumed_pending(self):
        del self.f.transactions[self.txid]
        with self.assertRaisesRegex(EvidenceGap,'outcome unavailable|missing current Core'):self.collect()

    def test_missing_one_owned_input_activity_holds(self):
        self.override=lambda value:{'activity':[r for r in value['activity']if r['type']!='spend']}
        with self.assertRaisesRegex(EvidenceGap,'complete current mempool'):self.collect()

    def test_unknown_additional_owned_receive_holds(self):
        def extra(value):
            row=copy.deepcopy(next(r for r in value['activity']if r['type']=='receive'))
            row['txid']='f'*64;value['activity'].append(row);return value
        self.override=extra
        with self.assertRaisesRegex(EvidenceGap,'complete current mempool'):self.collect()

    def test_pending_version_wrong_output_or_fee_does_not_borrow_source(self):
        self.f.transactions[self.txid]['outputs'][0]['amount_sat']-=1
        with self.assertRaisesRegex(EvidenceGap,'body/fee'):self.collect()

    def test_candidate_exact_mapping_cannot_be_partial(self):
        self.f.rows['journal_mappings'].pop()
        with self.assertRaisesRegex(EvidenceGap,'complete frozen group'):self.collect()

    def test_pending_does_not_accept_retirement_marker(self):
        self.f.rows['journal_carriers'][0]['confirmed_height']=101
        with self.assertRaisesRegex(EvidenceGap,'not exact unconfirmed'):self.collect()

    def test_activity_change_between_two_current_observations_holds(self):
        count=[0]
        def change(value):
            count[0]+=1
            return value if count[0]==1 else {'activity':[]}
        self.override=change
        with self.assertRaisesRegex(EvidenceGap,'state changed'):self.collect()

    def test_pending_unknown_additional_physical_input_cannot_use_backing_proof(self):
        self.f.rows['journal_carriers'][0]['backing_ids']=['f'*64+':0']
        with self.assertRaisesRegex(EvidenceGap,'backing root lacks'):self.collect()

    def test_fixed_profile_is_explicit_and_subclass_spoof_rejected(self):
        value=continuing_profile(self.f.store,'direct_xpub');self.assertIs(type(value),ContinuingDirectProfile)
        require_profile(value)
        class Spoof(ContinuingDirectProfile):pass
        with self.assertRaisesRegex(EvidenceGap,'arbitrary reducers'):require_profile(Spoof())
        with self.assertRaisesRegex(EvidenceGap,'matching continuing'):continuing_profile(self.f.store,'direct_per_key')

    def replacement(self,confirmed):
        from simulator.bundle_audit import decode_transaction
        anchor=self.f.anchors[0]
        raw=fixtures.raw_transaction(anchor,[(19000,self.f.destination),(1400,self.f.operator)])
        body=decode_transaction(raw,public_body=True);txid=body['txid']
        old=copy.deepcopy(self.f.transactions[self.txid]);old.update(txid=txid,outputs=body['outputs'],
            fee_sat=600,confirmations=1 if confirmed else 0,blockhash=self.f.tip if confirmed else None)
        self.f.transactions[txid]=old;self.f.raw[txid]={'hex':raw,'weight':body['weight'],'vsize':body['vsize']}
        carrier=copy.deepcopy(self.f.rows['journal_carriers'][0]);carrier.update(txid=txid,generation=2,
            miner_fee_sat=600,confirmed_height=101 if confirmed else None,confirmed_block=self.f.tip if confirmed else None)
        self.f.rows['journal_carriers'].append(carrier)
        self.f.rows['journal_mappings'] +=[{**m,'txid':txid}for m in self.f.rows['journal_mappings']]
        if confirmed:
            self.f.utxos.pop(anchor)
            next(r for r in self.f.rows['coins']if r['vtxo_id']==anchor).update(onchain_spent_txid=txid,onchain_spent_height=101)
        return txid

    def test_known_confirmed_replacement_retains_old_version_without_duplicate_debit(self):
        replacement=self.replacement(True)
        self.f.chain.owned_activity=lambda scripts:{'activity':[]}
        result=self.collect()
        self.assertEqual({self.txid,replacement},set(result['versions']))
        self.assertEqual('replaced',result['states'][self.txid])
        self.assertEqual('confirmed',result['states'][replacement])
        self.assertEqual(20000,self.f.collect()['outstanding_liability_sat'])

    def test_missing_old_replaced_body_is_not_omitted_from_history(self):
        self.replacement(True);self.f.chain.owned_activity=lambda scripts:{'activity':[]}
        del self.f.raw[self.txid]
        with self.assertRaisesRegex(EvidenceGap,'outcome unavailable|missing current Core'):self.collect()

    def test_retained_operator_script_cannot_replace_current_descriptor_ownership(self):
        self.f.store.db.execute('INSERT INTO operator_script VALUES(?,?)',('5120'+'f'*64,'{}'))
        with self.assertRaisesRegex(EvidenceGap,'operator script lacks current'):self.collect()


class ActivityDecoderControls(unittest.TestCase):
    def raw(self,value):return json.dumps({'jsonrpc':'2.0','id':1,'result':value,'error':None}).encode()
    def one(self):
        return activity({'a'*64:{'confirmations':0,'inputs':[],
            'outputs':[{'vout':0,'amount_sat':1000,'script':'0014'+'b'*40}]}},{'0014'+'b'*40})

    def test_default_empty_only_contract_stays_unchanged(self):
        raw=self.raw(self.one())
        with self.assertRaisesRegex(ValueError,'unconfirmed assets'):decode_reply(raw)
        self.assertEqual(self.one(),decode_activity_reply(raw,{'0014'+'b'*40})['result'])

    def test_wrong_script_is_not_dropped(self):
        with self.assertRaisesRegex(ValueError,'requested script'):decode_activity_reply(self.raw(self.one()),{'0014'+'c'*40})

    def test_unknown_fields_or_duplicate_activity_refuse(self):
        value=self.one();value['activity'][0]['blockhash']='f'*64
        with self.assertRaisesRegex(ValueError,'unknown/confirmed'):decode_activity_reply(self.raw(value))
        value=self.one();value['activity']*=2
        with self.assertRaisesRegex(ValueError,'duplicated'):decode_activity_reply(self.raw(value))


class PendingWalletControls(unittest.TestCase):
    def setUp(self):
        from simulator.bundle_audit import decode_transaction
        self.parent_script='5120'+'11'*32;self.urgent_script='5120'+'22'*32
        self.change_script='5120'+'33'*32;self.customer='0014'+'44'*20
        parent=fixtures.raw_transaction('e'*64+':0',[(35000,self.parent_script),(15000,self.urgent_script)])
        pb=decode_transaction(parent,public_body=True);self.parent=pb['txid']
        raw=fixtures.raw_transaction(self.parent+':0',[(25000,self.change_script),(9500,self.customer)])
        body=decode_transaction(raw,public_body=True);self.txid=body['txid']
        self.actual={'txid':self.txid,'confirmations':0,'blockhash':None,'fee_sat':500,
            'inputs':[{'outpoint':self.parent+':0','amount_sat':35000,'script':self.parent_script}],
            'outputs':body['outputs']}
        self.raw={self.parent:{'hex':parent,'weight':pb['weight']},self.txid:{'hex':raw,'weight':body['weight']}}
        self.versions={'versions':{self.txid:self.actual},'states':{self.txid:'mempool'},
            'pending_txids':[self.txid],'selected_fee_outpoints':[self.parent+':0']}
        self.scripts={script:{'member_id':'watchman','descriptor_index':0,'child_index':i}
            for i,script in enumerate((self.parent_script,self.urgent_script,self.change_script))}
        self.scan=[{'txid':self.parent,'vout':index,'amount_sat':amount,'script':script}
            for index,amount,script in ((0,35000,self.parent_script),(1,15000,self.urgent_script))]
        def public(txid):return {'txid':txid,'transaction_body':self.raw[txid]['hex'],
            'signed_weight_wu':self.raw[txid]['weight'],'encoding':'bitcoin-stripped-body-v1'}
        self.native={'wallet':'watchman','network':'signet','tip_height':101,'tip_hash':'a'*64,
            'public_descriptor':'synthetic-public','last_revealed_index':2,'min_trusted_confirmations':1,
            'pending_transactions':[public(self.txid)],'pending_parents':[public(self.parent)],
            'reserved_outpoints':[self.parent+':0'],'unavailable_parent_txids':[],
            'utxos':[self.coin(self.parent+':1',15000,self.urgent_script,1,2),
                     self.coin(self.txid+':0',25000,self.change_script,2,0)]}
        outer=self
        class Chain:
            def tx(self,txid):return copy.deepcopy(outer.raw[txid])
            def call(self,method,*args):
                if method=='gettxout':
                    if args[:2]==(outer.parent,0):
                        return None if args[2]else {'confirmations':2,'value':'0.00035000','scriptPubKey':{'hex':outer.parent_script}}
                    if args[:2]==(outer.parent,1):return {'confirmations':2,'value':'0.00015000','scriptPubKey':{'hex':outer.urgent_script}}
                raise AssertionError((method,args))
        self.chain=Chain();self.member={'id':'watchman','descriptors':['synthetic-public']}

    def coin(self,point,amount,script,child,confirmations):
        return {'outpoint':point,'value_sat':amount,'script_pubkey':script,'keychain':'external',
            'derivation_index':child,'confirmations':confirmations,'coinbase':False,'reserved':False,
            'trusted':True,'mature':True,'confirmed_fee_eligible':confirmations>0}

    def project(self):
        from simulator.b_pending_wallet import owning_projection
        return owning_projection(self.member,self.native,scripts=self.scripts,scan=self.scan,
            versions=self.versions,chain=self.chain,tip=(101,'a'*64))

    def test_complete_same_byte_graph_preserves_pending_and_confirmed_input_reservation(self):
        report,coins=self.project()
        self.assertEqual(self.native['pending_transactions'],report['pending_transactions'])
        self.assertEqual(self.native['pending_parents'],report['pending_parents'])
        self.assertEqual(50000,sum(c['amount_sat']for c in coins))
        self.assertEqual([self.parent+':0'],report['reserved_outpoints'])
        self.assertNotIn(self.txid+':0',[c['outpoint']for c in coins])

    def test_whole_selected_input_and_unconfirmed_change_cannot_supply_urgent_cash(self):
        from simulator.b_native_normal_verifier import urgent_reserve
        self.project()
        physical={r['txid']+':'+str(r['vout']):{'member_id':'watchman','amount_sat':r['amount_sat'],'script':r['script']}for r in self.scan}
        result=urgent_reserve(self.native,physical,{self.parent+':0'},self.chain,
            minimum_sat=15000,retained_versions=self.versions)
        self.assertEqual({self.parent+':1':15000},result)
        self.versions['selected_fee_outpoints'].append(self.parent+':1')
        with self.assertRaisesRegex(EvidenceGap,'below policy'):
            urgent_reserve(self.native,physical,set(self.versions['selected_fee_outpoints']),self.chain,
                minimum_sat=15000,retained_versions=self.versions)

    def test_missing_parent_is_not_empty_pending_source(self):
        self.native['pending_parents']=[]
        with self.assertRaisesRegex(EvidenceGap,'complete pending parent'):self.project()

    def test_changed_public_parent_body_or_pending_signed_weight_holds(self):
        self.native['pending_transactions'][0]['signed_weight_wu']+=1
        with self.assertRaisesRegex(EvidenceGap,'signed weight'):self.project()

    def test_unknown_pending_wallet_transaction_cannot_be_dropped(self):
        self.native['pending_transactions'].append({**self.native['pending_transactions'][0],'txid':'f'*64})
        with self.assertRaisesRegex(EvidenceGap,'whole pending identity'):self.project()

    def test_partial_native_utxo_graph_holds(self):
        self.native['utxos'].pop()
        with self.assertRaisesRegex(EvidenceGap,'whole native unspent graph'):self.project()

    def test_unconfirmed_change_fee_eligibility_cannot_be_promoted(self):
        self.native['utxos'][1]['confirmed_fee_eligible']=True
        with self.assertRaisesRegex(EvidenceGap,'pending change cannot'):self.project()

    def test_wrong_pending_output_derivation_or_reservation_union_holds(self):
        self.native['utxos'][1]['derivation_index']=77
        with self.assertRaisesRegex(EvidenceGap,'owning derivation'):self.project()
        self.native['utxos'][1]['derivation_index']=2
        self.native['reserved_outpoints'].append('f'*64+':0')
        with self.assertRaisesRegex(EvidenceGap,'unknown/duplicate native reservation'):self.project()


class CeilingControls(unittest.TestCase):
    def setUp(self):
        self.old='a'*64;self.new='b'*64
        self.runtime={'native_budget':{'history':{'txids':[self.old,self.new]},
            'disk_budget':{'history_prefix_bytes':65}}}
        self.partition={'ordinary_attempts':[{'ceiling_sat':10000},{'ceiling_sat':10000}],
            'ordinary_reserved_sat':20000}
        self.versions={'versions':{self.old:{'fee_sat':4985},self.new:{'fee_sat':500}},
            'states':{self.old:'confirmed',self.new:'mempool'}}
    def exposure(self):
        from simulator.b_continuing_native_fees import retained_ceiling_exposure
        return retained_ceiling_exposure(self.runtime,self.partition,self.versions,10000)
    def test_failed_reservation_stays_charged_pending_then_confirmed(self):
        self.assertEqual(20000000,self.exposure())
        self.versions['states'][self.new]='confirmed'
        self.assertEqual(19500000,self.exposure())
    def test_partial_reservation_cannot_cover_signed_version(self):
        self.partition['ordinary_attempts']=[]
        with self.assertRaisesRegex(EvidenceGap,'whole prepare ceilings'):self.exposure()
    def test_missing_history_version_or_partial_ceiling_holds(self):
        del self.versions['versions'][self.new]
        with self.assertRaisesRegex(EvidenceGap,'complete retained set'):self.exposure()
    def test_weaker_prepare_ceiling_cannot_borrow_loaded_maximum(self):
        self.partition['ordinary_attempts'][0]['ceiling_sat']=500
        with self.assertRaisesRegex(EvidenceGap,'whole prepare ceilings'):self.exposure()
    def test_fee_above_bound_or_unknown_disposition_holds(self):
        self.versions['versions'][self.new]['fee_sat']=10001
        with self.assertRaisesRegex(EvidenceGap,'exceeds exact prepare'):self.exposure()
        self.versions['versions'][self.new]['fee_sat']=500;self.versions['states'][self.new]='unknown'
        with self.assertRaisesRegex(EvidenceGap,'unknown retained'):self.exposure()


class TypedBoundaryControls(unittest.TestCase):
    def test_existing_aggregate_deadline_bounds_new_activity_rpc(self):
        from simulator.normal_source_deadline import DeadlineChain
        class Deadline:
            def limit(self,seconds):return 0.25
            def remaining(self):return 0.25
        class Chain:
            def owned_activity(self,scripts,*,timeout):
                self.seen=(scripts,timeout);return {'activity':[]}
        chain=Chain();wrapper=DeadlineChain(chain,Deadline())
        self.assertEqual({'activity':[]},wrapper.owned_activity({'0014'+'1'*40}))
        self.assertEqual(0.25,chain.seen[1])
        class Expired(Deadline):
            def remaining(self):raise TimeoutError('aggregate expired')
        with self.assertRaisesRegex(TimeoutError,'aggregate expired'):
            DeadlineChain(chain,Expired()).owned_activity({'0014'+'1'*40})

    def test_actual_continuing_callbacks_bind_all_new_dependency_sources(self):
        profile=ContinuingDirectProfile();hashes=profile.component_hashes()
        for name in ('b_candidate_accounting','b_owned_activity_decoder','b_chain_transport',
            'b_source_deadline','b_pending_wallet','b_continuing_profile','b_current_rights',
            'b_signed_versions','b_continuing_fees','b_ordinary_money','b_fee_partition'):
            self.assertRegex(hashes[name],'^[0-9a-f]{64}$')
        self.assertIsNot(ContinuingDirectProfile.backing,ContinuingDirectProfile.__bases__[0].backing)
        self.assertIsNot(ContinuingDirectProfile.money_projection,ContinuingDirectProfile.__bases__[0].money_projection)

    def test_public_pending_wallet_projection_does_not_accept_different_graph(self):
        from simulator.two_step_capture import public_wallet_projection
        member={'role':'customer','descriptors':['public']}
        frame={'source_kind':'core_descriptor_scan','network':'signet','height':1,'tip_hash':'a'*64,
            'pending_transactions':[{'txid':'b'*64}],'discovery_gaps':[],'public_descriptors':['public'],
            'source_records':['c'*64],'utxos':[]}
        with self.assertRaisesRegex(ValueError,'unresolved'):
            public_wallet_projection(member,frame,height=1,tip_hash='a'*64)
        with self.assertRaisesRegex(ValueError,'unresolved'):
            public_wallet_projection(member,frame,height=1,tip_hash='a'*64,checked_pending=[])
        self.assertEqual([],public_wallet_projection(member,frame,height=1,tip_hash='a'*64,
            checked_pending=frame['pending_transactions']))


class ContinuingCallbackControls(unittest.TestCase):
    def test_actual_wallet_callback_retains_complete_literal_pending_graph(self):
        wallet=PendingWalletControls();wallet.setUp()
        context={'scripts':wallet.scripts,'normalized_scan':wallet.scan,'versions':wallet.versions}
        report,assets=ContinuingDirectProfile().wallet_projection(wallet.member,wallet.native,
            height=101,tip_hash='a'*64,context=context,chain=wallet.chain)
        self.assertEqual(wallet.native['pending_transactions'],report['pending_transactions'])
        self.assertEqual(wallet.native['pending_parents'],report['pending_parents'])
        self.assertEqual(50000,sum(row['amount_sat']for row in assets))
        wallet.native['utxos'][0]['confirmations']=1
        with self.assertRaisesRegex(EvidenceGap,'owning UTXO position'):
            ContinuingDirectProfile().wallet_projection(wallet.member,wallet.native,
                height=101,tip_hash='a'*64,context=context,chain=wallet.chain)

    def test_actual_backing_and_claim_callbacks_advance_only_confirmed_group(self):
        f=fixtures.CurrentRightsTests();self.addCleanup(f.doCleanups);f.setUp();profile=ContinuingDirectProfile()
        def check():
            rights=f.collect();context={'direct':rights,'pending_liabilities':rights['liabilities'],
                'backing_member_id':'ark','actor_member_ids':{'actor-01':'customer'},
                'boundary':{'pins':{}},'native_source_sha256':'a'*64}
            source={'pending_liabilities':[{**r,'source_sequence':1}for r in rights['liabilities']],
                'cost_sequences':[],'flow_sequences':[]}
            claims=profile.checked_claims(f.store,source,context,{'cost_sequences':[],'flow_sequences':[]},{})
            roots,sources=profile.backing({'id':'ark','kind':'ark_backing','identity':f.server},context)
            self.assertEqual(sum(c['amount_sat']for c in claims),rights['outstanding_liability_sat'])
            self.assertEqual(len(roots),len(sources))
            return len(claims),sum(row['amount_sat']for row in roots.values())
        before=f.store.db.total_changes
        f.carrier(False);self.assertEqual((2,42000),check())
        f.carrier(True);self.assertEqual((1,21000),check())
        self.assertEqual((1,21000),check());self.assertEqual(before,f.store.db.total_changes)

    def test_fixed_existing_factory_builds_real_B_continuing_callbacks_without_reading(self):
        from simulator.two_step_normal_factory import build_collector
        f=fixtures.CurrentRightsTests();self.addCleanup(f.doCleanups);f.setUp()
        collector=build_collector(f.store,admission_sequence=1,boundary={},capture_configuration={},
            target_configuration={'command':['/bin/false'],'evidence_directory':f.tmp.name,'timeout':5},
            member_configuration={'pending_board_proof_sha256':None},tools={},architecture_profile='direct_xpub')
        self.assertIs(type(collector.native_profile),ContinuingDirectProfile)
        self.assertIs(collector.capture.__self__.native_profile,collector.native_profile)

    def test_changed_continuing_dependency_invalidates_existing_admission(self):
        from tests import test_two_step_normal as normal
        f=normal.AdmissionTests();f.setUp();self.addCleanup(f.tearDown)
        f.collector.native_profile=ContinuingDirectProfile()
        hashes=f.collector.native_profile.component_hashes();f.value['component_sha256'].update(hashes)
        f.admit();self.assertEqual(f.value,f.collector.admission(f.store,f.value['financial_pins']))
        from unittest.mock import patch
        from simulator import b_continuing_profile as module
        original=module.module_hash
        with patch.object(module,'module_hash',side_effect=lambda fn:'0'*64 if fn is module.owning_projection else original(fn)):
            with self.assertRaisesRegex(ValueError,'qualification'):
                f.collector.admission(f.store,f.value['financial_pins'])
