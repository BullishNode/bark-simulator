"""Synthetic fixed-profile admission/original replay, no native/live credit."""
import copy
import json
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from test_b_native_owner_snapshot import fixture
from simulator.b_final_native_profile import FinalNativeDirectProfile, checked_owner, PRODUCT, PRIVATE
from simulator.b_normal_profile_adapter import InitialDirectProfile, require_profile
from simulator.two_step_normal import Collector,digest
from simulator.model import canonical
from simulator.ownership import EvidenceGap


def tool():
    return {'command':['/private/admitted-captaind','native-fee-source-proof'],
        'sha256':'1'*64,'evidence_directory':'/private/evidence','sdk_commit':'2'*40}


def captured():
    raw=b'{"whole":"synthetic"}'
    target={'raw_runtime':b'{}','raw_watchman_inventory':b'{}','raw_sql':raw,
        'manifest':{'original_sha256':{'native_sql':digest(raw)}},
        'auxiliary_originals':{'b-native-fee-originals.json':b'private fixture only',
            'b-native-fee-snapshot.json':b'public fixture only'},
        PRIVATE:{'request_raw':canonical({'source_observation':{'id':'3'*32,'height':100,'tip_hash':'4'*64}}).encode(),
                 'reply_raw':b'public synthetic reply'}}
    profile=FinalNativeDirectProfile(tool())
    saved=profile.originals(target,{'b_public_context':{}})
    original={'native_sql':raw,'rounds_inventory':b'{}'}
    source={'original_sha256':{'native_sql':digest(raw)},'source_observation':{
        'id':'3'*32,'height':100,'tip_hash':'4'*64},'b_native_fee_tool_commit':'2'*40,
        'b_native_fee_original_sha256':profile.proof_hashes(target)}
    return profile,saved,original,source


class FinalProfileControls(unittest.TestCase):
    def test_shared_factory_selects_only_explicit_final_B_without_running_sources(self):
        from simulator import two_step_normal_factory as factory
        from simulator import b_continuing_profile as continuing
        sources=SimpleNamespace(read=lambda *args:None)
        tools={'native_fee':tool()}
        with patch.object(continuing,'profile',return_value='direct_xpub'), \
                patch.object(factory,'TargetTarReader',return_value=sources), \
                patch.object(factory,'MemberReader',return_value=sources):
            collector=factory.build_collector(object(),admission_sequence=1,boundary={},
                capture_configuration={},target_configuration={'command':[],
                    'evidence_directory':'/synthetic','timeout':1},
                member_configuration={},tools=tools,architecture_profile='direct_xpub')
        self.assertIs(type(collector.native_profile),FinalNativeDirectProfile)
        self.assertIs(collector.capture.__self__.native_profile,collector.native_profile)
        self.assertIsNone(collector.funding_reader)

    def test_final_B_tool_cannot_route_C_through_shared_B_factory(self):
        from simulator import two_step_normal_factory as factory
        with patch.object(factory,'TargetTarReader')as target:
            with self.assertRaisesRegex(EvidenceGap,'matching installed normal collector'):
                factory.build_collector(object(),admission_sequence=1,boundary={},
                    capture_configuration={},target_configuration={},member_configuration={},
                    tools={'native_fee':tool()},architecture_profile='direct_per_key')
            target.assert_not_called()

    def test_explicit_tool_pin_can_differ_from_runtime_product(self):
        p=FinalNativeDirectProfile(tool()); tools={k:{}for k in ('policy','binding','pending')}
        tools['native_fee']=tool()
        self.assertNotEqual(tool()['sdk_commit'],PRODUCT)
        self.assertTrue(p.validate_proof_tools(tools,{'b_native_fee_tool_commit':'2'*40}))
        require_profile(p)
    def test_extra_or_missing_tool_never_selects_generic_plugin(self):
        p=FinalNativeDirectProfile(tool())
        for names in [('policy','binding','pending'),('policy','binding','pending','native_fee','plugin')]:
            tools={k:tool()if k=='native_fee'else{}for k in names}
            with self.assertRaises(EvidenceGap):p.validate_proof_tools(tools,{'b_native_fee_tool_commit':'2'*40})
    def test_wrong_command_or_independent_tool_source_refuses(self):
        for key,value in [('command',['/private/admitted-captaind','rpc']),('sdk_commit','5'*40)]:
            tools={k:{}for k in ('policy','binding','pending')};tools['native_fee']=tool();tools['native_fee'][key]=value
            p=FinalNativeDirectProfile(tools['native_fee'])
            with self.assertRaises(EvidenceGap):p.validate_proof_tools(tools,{'b_native_fee_tool_commit':'2'*40})
    def test_constructor_tool_configuration_is_not_mutable_alias(self):
        original=tool();p=FinalNativeDirectProfile(original);original['command'][1]='rpc'
        self.assertEqual(p.native_fee_tool['command'][1],'native-fee-source-proof')
    def test_default_a_tool_sets_remain_exact(self):
        for profile in (None,InitialDirectProfile()):
            c=SimpleNamespace(native_profile=profile,tools={'policy':{},'binding':{}})
            self.assertTrue(Collector._proof_tools(c,admitted={}))
            c.tools['pending']={};self.assertTrue(Collector._proof_tools(c,admitted={}))
            c.tools['native_fee']=tool();self.assertFalse(Collector._proof_tools(c,admitted={}))
    def test_actual_cli_raw_lf_hash_and_separate_product_pin(self):
        snap,runtime=fixture();runtime['product_commit']=runtime['execution_release']['product_commit']=PRODUCT
        raw=canonical(snap)+'\n';runtime['native_budget'].update(owner_snapshot_raw=raw,
            owner_snapshot_raw_sha256=digest(raw.encode()),owner_snapshot=copy.deepcopy(snap))
        self.assertEqual(checked_owner(runtime)['server_pubkey'],snap['opening']['server_pubkey'])
        runtime['native_budget']['owner_snapshot_raw_sha256']='0'*64
        with self.assertRaises(EvidenceGap):checked_owner(runtime)
    def test_canonical_object_cannot_replace_exact_cli_hash_or_boolean_alias(self):
        snap,runtime=fixture();runtime['product_commit']=runtime['execution_release']['product_commit']=PRODUCT
        raw=canonical(snap);runtime['native_budget'].update(owner_snapshot_raw=raw,
            owner_snapshot_raw_sha256=digest(raw.encode()),owner_snapshot=copy.deepcopy(snap))
        runtime['native_budget']['owner_snapshot']['direct_attempt_count']=True
        with self.assertRaises(EvidenceGap):checked_owner(runtime)
    def test_same_private_buffers_and_source_nonce_survive_reduction(self):
        p,s,o,event=captured();replayed=p.replay_target(s,o,event)
        self.assertEqual(replayed[PRIVATE],s[PRIVATE]['proof'])
        self.assertEqual(replayed['auxiliary_originals'],s[PRIVATE]['auxiliary_originals'])
        self.assertNotIn('private fixture only',canonical(event))
    def test_missing_or_changed_private_original_refuses_before_reduction(self):
        for which in ('missing','request','reply','snapshot','sql','nonce','tool'):
            p,s,o,event=captured()
            if which=='missing':s.pop(PRIVATE)
            elif which in {'request','reply'}:s[PRIVATE]['proof'][which+'_raw']+=b' '
            elif which=='snapshot':s[PRIVATE]['auxiliary_originals']['b-native-fee-snapshot.json']+=b' '
            elif which=='sql':o['native_sql']+=b' '
            elif which=='nonce':event['source_observation']['id']='5'*32
            else:event['b_native_fee_tool_commit']='5'*40
            with self.subTest(which=which),self.assertRaises((EvidenceGap,ValueError)):p.replay_target(s,o,event)
    def test_private_manifest_copy_cannot_alias_target(self):
        p,s,o,event=captured();saved=copy.deepcopy(s[PRIVATE]['manifest'])
        s[PRIVATE]['manifest']['original_sha256']['native_sql']='0'*64
        self.assertNotEqual(s[PRIVATE]['manifest'],saved)
        with self.assertRaises(EvidenceGap):p.replay_target(s,o,event)
    def test_final_profile_does_not_fallback_to_old_disk_budget(self):
        p=FinalNativeDirectProfile(tool())
        with self.assertRaisesRegex(EvidenceGap,'actual owner CLI'):
            p.loaded_fee_policy({'native_budget':{'disk_budget':{'complete':True}}},network='signet')


class FinalRetainedAccountingControls(unittest.TestCase):
    def inputs(self):
        from test_b_native_normal_verifier import MonetaryControls
        from test_b_native_fee_policy import fixture as legacy_policy
        from test_b_pending_carrier_profile import PendingWalletControls
        from simulator.model import SIGNET_GENESIS
        runtime,costs,groups=MonetaryControls().budget();costs[-1]['sequence']=4447
        snap,owner=fixture()
        snap.update(direct_attempt_count=0,direct_reserved_sat=0,funding=[],urgent=[],resolutions=[],
            funding_reserved_sat=0,round_reserved_sat=0,pool_reserved_sat=0,urgent_reserved_sat=0,
            charged_sat=25864,remaining_total_sat=34136,urgent_remaining_sat=15000,
            discretionary_remaining_sat=19136,journal_bytes=0)
        owner['native_budget']['files']['ordinary-fee-budget']['bytes']=0
        opening=snap['opening'];disk=runtime['native_budget']['disk_budget']
        opening.update(genesis=SIGNET_GENESIS,server_pubkey=disk['server_pubkey'],
            history_prefix_bytes=65,history_prefix_sha256=disk['history_prefix_sha256'],
            accounting_receipt_sha256='e'*64,native_spent_sat=4985,external_spent_sat=3257)
        owner['native_budget'].update(history=runtime['native_budget']['history'],
            accounting_receipt_sha256='e'*64)
        owner['product_commit']=owner['execution_release']['product_commit']=PRODUCT
        public=legacy_policy()['public_configuration'];public['product_commit']=PRODUCT
        public['policy_source_sha256']['server/src/config.rs']='b5880d6210721f4ee080000cbb6e2187b1173c6e190f24e427cbc8b3fc70f344'
        public['policy_source_sha256']['server/src/vtxopool.rs']='93374601830777ce15ed8a10e86ac11f9a06f0c2ad085d78cbd7801fa3e63bed'
        for name in ('captaind','watchmand'):public[name]['network']='signet'
        public['captaind']['ordinary_fee_policy']=copy.deepcopy(snap['policy'])
        public['watchmand']['direct_expiry']['ordinary_fee_policy']=copy.deepcopy(snap['policy'])
        owner['public_configuration']=public
        owner['daemons']={n:{'config_sha256':public['config_sha256'][n],
            'public_configuration':copy.deepcopy(public[n])}for n in ('captaind','watchmand')}
        def refresh():
            raw=canonical(snap)+'\n';owner['native_budget'].update(owner_snapshot=copy.deepcopy(snap),
                owner_snapshot_raw=raw,owner_snapshot_raw_sha256=digest(raw.encode()))
        refresh()
        w=PendingWalletControls();w.setUp();w.native.update(pending_transactions=[],pending_parents=[],reserved_outpoints=[],
            utxos=[w.coin(w.parent+':0',35000,w.parent_script,0,2),w.coin(w.parent+':1',15000,w.urgent_script,1,2)])
        coins={r['outpoint']:r for r in w.native['utxos']}
        class Chain:
            def call(self,method,*args):
                assert method=='gettxout'
                row=coins.get(args[0]+':'+str(args[1]))
                return None if row is None else {'confirmations':row['confirmations'],
                    'value':format(row['value_sat']/100000000,'.8f'),'scriptPubKey':{'hex':row['script_pubkey']}}
        versions={'versions':copy.deepcopy(groups[0]['versions']),'states':{k:'confirmed'for k in groups[0]['versions']},
            'selected_fee_outpoints':[],'pending_txids':[],'signed_weight_wu':{}}
        proof={'direct_reservations':[],'funding_rows':[],'urgent_rows':[],'nursery_inventory':[],'unrelated_nursery_txids':[]}
        context={'member':w.member,'scripts':w.scripts,'scan':w.scan,'tip':(101,'a'*64)}
        args={'versions':versions,'costs':costs,'groups':groups,'accounting_receipt_sha256':'e'*64,
            'watchman_raw':json.dumps({'watchman':w.native}).encode(),'physical':{
                k:{'amount_sat':r['value_sat'],'script':r['script_pubkey'],'member_id':'watchman'}for k,r in coins.items()},
            'chain':Chain(),'server_pubkey':opening['server_pubkey'],'wallet_context':context}
        return snap,owner,proof,args,refresh
    def run_fees(self,owner,proof,args):
        from simulator.b_final_native_fees import final_ordinary_fee_facts
        return final_ordinary_fee_facts(owner,native_fee_source={
            'partition':checked_owner(owner),'reply':proof},**args)
    def test_final_owner_preserves_original_four_costs_and_urgent_whole_inputs(self):
        snap,owner,proof,args,refresh=self.inputs();before=copy.deepcopy(owner)
        result=self.run_fees(owner,proof,args)
        self.assertEqual(result['native_budget']['external_opening_spent_sat'],3257)
        self.assertEqual(result['native_budget']['native_opening_spent_sat'],4985)
        self.assertEqual(result['native_budget']['external_future_partition_remaining_sat'],17622)
        self.assertEqual(result['native_budget']['native_remaining_allowance_sat'],34136)
        self.assertEqual(sum(result['confirmed_whole_input_urgent_reserve'].values()),50000)
        self.assertEqual(result['pending_native_fee_exposure_msat'],{'ordinary':0,'urgent':0})
        self.assertNotIn('disk_budget',owner['native_budget']);self.assertEqual(owner,before)
    def pending_inputs(self):
        from test_b_pending_carrier_profile import PendingWalletControls
        snap,owner,proof,args,refresh=self.inputs();w=PendingWalletControls();w.setUp()
        snap.update(direct_attempt_count=1,direct_reserved_sat=10000,charged_sat=35864,
            remaining_total_sat=24136,discretionary_remaining_sat=9136,journal_bytes=6)
        owner['native_budget']['files']['ordinary-fee-budget']['bytes']=6
        history=owner['native_budget']['history'];history['txids'].append(w.txid)
        raw=''.join(t+'\n'for t in history['txids']).encode();history.update(bytes=len(raw),sha256=digest(raw))
        proof['direct_reservations']=[{'line':1,'ceiling_sat':10000}]
        args['versions']['versions'][w.txid]=w.actual
        args['versions']['states'][w.txid]='mempool'
        args['versions']['signed_weight_wu'][w.txid]=w.raw[w.txid]['weight']
        args['versions'].update(pending_txids=[w.txid],selected_fee_outpoints=[w.parent+':0'])
        args.update(chain=w.chain,watchman_raw=json.dumps({'watchman':w.native}).encode(),
            physical={c['txid']+':'+str(c['vout']):{'amount_sat':c['amount_sat'],
                'script':c['script'],'member_id':'watchman'}for c in w.scan},
            wallet_context={'member':w.member,'scripts':w.scripts,'scan':w.scan,'tip':(101,'a'*64)})
        refresh();return snap,owner,proof,args,refresh,w
    def test_pending_to_confirmed_preserves_full_reservation_and_excludes_pending_change(self):
        snap,owner,proof,args,refresh,w=self.pending_inputs()
        pending=self.run_fees(owner,proof,args)
        self.assertEqual(pending['pending_native_fee_exposure_msat']['ordinary'],10000000)
        self.assertEqual(sum(pending['confirmed_whole_input_urgent_reserve'].values()),15000)
        self.assertEqual(pending['native_budget']['native_reserved_ceiling_sat'],10000)
        args['versions']['states'][w.txid]='confirmed';args['versions']['pending_txids']=[]
        w.actual.update(confirmations=1,blockhash='a'*64)
        args['costs'].append({'sequence':5000,'txid':w.txid,'amount_msat':500000,
            'budget':'ordinary','direct_payment_sequence':4999})
        w.native.update(pending_transactions=[],pending_parents=[],reserved_outpoints=[])
        w.native['utxos'][1].update(confirmations=1,confirmed_fee_eligible=True)
        args['watchman_raw']=json.dumps({'watchman':w.native}).encode()
        scan=[{'txid':w.parent,'vout':1,'amount_sat':15000,'script':w.urgent_script},
              {'txid':w.txid,'vout':0,'amount_sat':25000,'script':w.change_script}]
        args['wallet_context']['scan']=scan
        args['physical']={c['txid']+':'+str(c['vout']):{'amount_sat':c['amount_sat'],
            'script':c['script'],'member_id':'watchman'}for c in scan}
        class ConfirmedChain:
            def call(self,method,*values):
                assert method=='gettxout'
                point=values[0]+':'+str(values[1]);row=args['physical'].get(point)
                if row is None:return None
                return {'confirmations':2 if point.startswith(w.parent)else 1,
                    'value':format(row['amount_sat']/100000000,'.8f'),'scriptPubKey':{'hex':row['script']}}
        args['chain']=ConfirmedChain()
        confirmed=self.run_fees(owner,proof,args)
        self.assertEqual(confirmed['pending_native_fee_exposure_msat']['ordinary'],9500000)
        self.assertEqual(confirmed['native_budget']['native_reserved_ceiling_sat'],10000)
        self.assertEqual(confirmed['native_budget']['native_remaining_allowance_sat'],24136)
        self.assertEqual(sum(confirmed['confirmed_whole_input_urgent_reserve'].values()),40000)
        self.assertEqual(owner['native_budget']['owner_snapshot']['charged_sat'],35864)
    def test_unequal_native_decimal_rows_with_same_aggregate_do_not_fake_uniform_policy(self):
        snap,owner,proof,args,refresh,w=self.pending_inputs()
        snap.update(direct_attempt_count=2,direct_reserved_sat=20000,charged_sat=45864,
            remaining_total_sat=14136,discretionary_remaining_sat=-864,journal_bytes=12)
        # Keep fixture within lifetime+urgent constraints with a larger declared
        # allowance in BOTH genuinely supplied native/public policy projections.
        snap['policy']['ordinary_budget_sat']=70000
        for name in ('captaind','watchmand'):
            row=owner['public_configuration'][name]
            selected=row['ordinary_fee_policy']if name=='captaind'else row['direct_expiry']['ordinary_fee_policy']
            selected['ordinary_budget_sat']=70000
            owner['daemons'][name]['public_configuration']=copy.deepcopy(row)
        snap.update(remaining_total_sat=24136,discretionary_remaining_sat=9136)
        owner['native_budget']['files']['ordinary-fee-budget']['bytes']=12;refresh()
        proof['direct_reservations']=[{'line':1,'ceiling_sat':9999},{'line':2,'ceiling_sat':10001}]
        with self.assertRaisesRegex(EvidenceGap,'whole prepare ceilings'):self.run_fees(owner,proof,args)
    def test_original_cost_loss_or_refill_is_not_fixed_by_owner_snapshot(self):
        for which in ('cost','refill','history','reserve'):
            snap,owner,proof,args,refresh=self.inputs()
            if which=='cost':args['costs']=args['costs'][:-1]
            elif which=='refill':snap['opening']['external_spent_sat']=879;refresh()
            elif which=='history':owner['native_budget']['history']['txids']=[]
            else:args['physical']={}
            with self.subTest(which=which),self.assertRaises(EvidenceGap):self.run_fees(owner,proof,args)
    def test_aggregate_direct_count_is_not_individual_native_reservation_proof(self):
        snap,owner,proof,args,refresh=self.inputs()
        snap.update(direct_attempt_count=1,direct_reserved_sat=10000,charged_sat=35864,
            remaining_total_sat=24136,discretionary_remaining_sat=9136,journal_bytes=6)
        owner['native_budget']['files']['ordinary-fee-budget']['bytes']=6;refresh()
        with self.assertRaisesRegex(EvidenceGap,'individual direct reservations'):self.run_fees(owner,proof,args)
    def test_typed_native_fee_proof_does_not_erase_unclassified_publication(self):
        snap,owner,proof,args,refresh=self.inputs();proof['unrelated_nursery_txids']=['f'*64]
        with self.assertRaisesRegex(EvidenceGap,'whole nursery'):self.run_fees(owner,proof,args)
    def test_final_loaded_policy_cannot_reuse_old_semantic_source_map(self):
        snap,owner,proof,args,refresh=self.inputs()
        owner['public_configuration']['policy_source_sha256']['server/src/config.rs']='0'*64
        with self.assertRaisesRegex(EvidenceGap,'semantics source'):self.run_fees(owner,proof,args)
