"""Synthetic fixed-profile admission/original replay, no native/live credit."""
import copy
import json
import unittest
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
        with self.assertRaisesRegex(EvidenceGap,'independent retained fee/Core/wallet'):
            p.fee_projection({'native_budget':{'disk_budget':{'complete':True}}},context={})
