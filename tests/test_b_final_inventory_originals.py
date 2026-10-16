"""Synthetic actual CLI-byte identity joins, not a live inventory proof."""
import copy
import json
import unittest
from unittest.mock import patch

from simulator.b_final_native_profile import FinalNativeDirectProfile,checked_inventory_originals
from simulator.b_continuing_profile import ContinuingDirectProfile
from simulator.ownership import EvidenceGap
from simulator.two_step_normal import digest
import test_b_final_native_profile as fixtures


def inputs():
    target={'raw_rounds_inventory':b'{"rounds":{"wallet":"rounds","synthetic":1}}\n',
        'raw_watchman_inventory':b'{"watchman":{"wallet":"watchman","synthetic":2}} \n'}
    runtime={'daemons':{name:{'admin_response_sha256':digest(target[key])}for name,key in
        [('captaind','raw_rounds_inventory'),('watchmand','raw_watchman_inventory')]}}
    return target,runtime


class FinalInventoryOriginalControls(unittest.TestCase):
    def test_distinct_exact_cli_originals_match_each_protected_named_response(self):
        target,runtime=inputs();before=copy.deepcopy((target,runtime))
        frames=checked_inventory_originals(target,runtime)
        self.assertEqual(frames['rounds']['wallet'],'rounds')
        self.assertEqual(frames['watchman']['wallet'],'watchman')
        self.assertEqual((target,runtime),before)

    def test_equivalent_json_reencoding_cannot_replace_either_cli_original(self):
        for key in ('raw_rounds_inventory','raw_watchman_inventory'):
            target,runtime=inputs();target[key]=json.dumps(json.loads(target[key]),indent=2).encode()
            with self.subTest(key=key),self.assertRaisesRegex(EvidenceGap,'original/hash'):
                checked_inventory_originals(target,runtime)

    def test_missing_or_nonbytes_or_changed_protected_hash_refuses(self):
        for key in ('raw_rounds_inventory','raw_watchman_inventory'):
            for change in ('missing','text','hash'):
                target,runtime=inputs()
                if change=='missing':target.pop(key)
                elif change=='text':target[key]=target[key].decode()
                else:runtime['daemons']['captaind'if'rounds'in key else'watchmand']['admin_response_sha256']='0'*64
                with self.subTest(key=key,change=change),self.assertRaises(EvidenceGap):
                    checked_inventory_originals(target,runtime)

    def test_swapped_role_and_matching_hash_cannot_invent_correct_native_frame(self):
        target,runtime=inputs()
        target['raw_rounds_inventory']=target['raw_watchman_inventory']
        runtime['daemons']['captaind']['admin_response_sha256']=digest(target['raw_rounds_inventory'])
        with self.assertRaisesRegex(ValueError,'owning wallet frame'):checked_inventory_originals(target,runtime)

    def test_malformed_cli_with_matching_hash_refuses_before_projection(self):
        target,runtime=inputs();target['raw_watchman_inventory']=b'not-json'
        runtime['daemons']['watchmand']['admin_response_sha256']=digest(target['raw_watchman_inventory'])
        with self.assertRaises(ValueError):checked_inventory_originals(target,runtime)

    def test_capture_member_hook_checks_before_parent_scan_and_preserves_arguments(self):
        target,runtime=inputs();profile=FinalNativeDirectProfile(fixtures.tool())
        args=(None,None,None,{'b_runtime_admission':{}},{},{},target,{},{},[])
        with patch('simulator.b_final_native_profile.runtime_from_target',return_value=runtime),\
             patch.object(ContinuingDirectProfile,'member_frames',return_value='parent-result')as parent:
            self.assertEqual(profile.member_frames(*args),'parent-result')
            parent.assert_called_once_with(*args)
            target['raw_watchman_inventory']+=b' '
            with self.assertRaisesRegex(EvidenceGap,'original/hash'):profile.member_frames(*args)
            self.assertEqual(parent.call_count,1)

    def test_reduction_native_hook_rechecks_before_owner_or_sql_projection(self):
        target,runtime=inputs();target['raw_rounds_inventory']+=b' '
        profile=FinalNativeDirectProfile(fixtures.tool())
        with patch('simulator.b_final_native_profile.runtime_from_target',return_value=runtime),\
             patch('simulator.b_final_native_profile.checked_owner_original')as owner:
            with self.assertRaisesRegex(EvidenceGap,'original/hash'):
                profile.native_projection(None,None,target,{},(1,'a'*64),{},{},{})
            owner.assert_not_called()
