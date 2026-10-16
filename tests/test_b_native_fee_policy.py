"""Pure B policy/ABI controls; authentic clone fields are NOT runtime proof.

Public fixture source: AUTHENTIC-CLONE-PUBLIC-PROJECTION.json SHA256
cea9d4c6130f3aa9b01927546c70c3b15a92fb229b7b0d88db96a15f8d804316.
It was regtest same-byte config projection only/current_process_loaded=false.
The surrounding capsule below is synthetic, never a loaded-process claim.
"""
import copy
import json
import unittest

from simulator.b_native_fee_policy import loaded_native_fee_policy, PRODUCT
from simulator.ownership import EvidenceGap

PUBLIC_CLONE = json.loads('{"captaind": {"device": 64769, "inode": 31476617, "bytes": 3212, "mtime_ns": 1792142303522052396, "ctime_ns": 1792142303522052396, "sha256": "bb91d1d444ab91d9b2e6ad646fe927cff528b86e996010a9b048575a3373b28a", "public_configuration": {"network": "regtest", "fee_estimator_max_sat_kwu": null, "vtxo_lifetime": 128, "vtxo_exit_delta": 12, "htlc_expiry_delta": 6, "htlc_send_expiry_delta": 258, "direct_expiry": {"enabled": true, "grace_blocks": 0}, "legacy_expiry_payout_enabled": false, "ln_max_fee_ppm": 900000, "ordinary_fee_policy": {"urgent_reserve_sat": 15000, "ordinary_budget_sat": 60000, "external_future_reserved_sat": 20000, "opening_sha256": "4bfff1379d173dfebb29b69f2b312d7fdc1bd0143df6146fea8089e7847af6a3"}, "vtxopool": {"targets": [], "vtxo_lifetime": 432, "vtxo_pre_expiry": 12, "vtxo_target_issue_threshold": 50, "max_vtxo_exit_depth": 6}}}, "watchmand": {"device": 64769, "inode": 31476627, "bytes": 1984, "mtime_ns": 1792142303520052388, "ctime_ns": 1792142303520052388, "sha256": "0a922708e2791f0b5e957c137a90067897d23dd16eb17dda833b7563f1bcc19d", "public_configuration": {"network": "regtest", "fee_estimator_max_sat_kwu": 12500, "direct_expiry": {"max_miner_fee_sat": 10000, "ordinary_fee_policy": {"urgent_reserve_sat": 15000, "ordinary_budget_sat": 60000, "external_future_reserved_sat": 20000, "opening_sha256": "4bfff1379d173dfebb29b69f2b312d7fdc1bd0143df6146fea8089e7847af6a3"}}}}}')
SOURCE_MAP = json.loads('{"server/src/config.rs": "0d8882088ea192403025bc58297811963c82381c3de133bfe308d6df5541993f", "server/src/watchman/config.rs": "c1737bfeb783cbcc7eccecf525491953a5ccc635ddec3f2b38812e24ecb38bdd", "server/src/utils/serde.rs": "1a47258d50814a23914321e689ff8283e58c34bf71500babf0f8fb1a0ea944ee", "server/src/fee_estimator.rs": "7c4dc5dd37aa046048388555b53baced74d1009e167c7854b822653f36179cfe", "server/src/vtxopool.rs": "201035455969c724f3953f680af98ccb4596677fb32f082d94fd8f331a44ee57", "server/src/expiry_dispatch.rs": "b76668ade7329a3d00d9a68570bf42448174cd9f46ad4131bdddee2234ba0604", "server/src/expiry_payout.rs": "9481d1745718232985592fd0b1ed2e5725dd15b0f7e113a9ea31bcbdee3bf05b", "server/src/wallet/mod.rs": "0481a86aff6a7cfa2c9d1a46b47c35b8236f4d486194522f5364dad61171d4a7", "server/src/watchman/carrier.rs": "5ed4ce9606ba16ec69870d6ea17f8d3891e1d6d5aae3e196c63dba4193fb4843", "server/src/watchman/urgent.rs": "41bb64748f73806785342975cb1537287b1de202b7334db56ba15e8a37c5f68e", "server/src/ln/mod.rs": "b71f1d4297b66305ee88d75f9f28bdfb02f4f173588dc90252699e812f0a49b6"}')


def fixture():
    clone=copy.deepcopy(PUBLIC_CLONE)
    policy=clone['captaind']['public_configuration']['ordinary_fee_policy']
    configuration={'schema_version':1,'product_commit':PRODUCT,'policy_source_sha256':dict(SOURCE_MAP),
        'config_sha256':{name:row['sha256']for name,row in clone.items()},
        **{name:row['public_configuration']for name,row in clone.items()}}
    return {'product_commit':PRODUCT,'execution_release':{'product_commit':PRODUCT},
        'public_configuration':configuration,'daemons':{name:{'config_sha256':row['sha256'],
            'public_configuration':row['public_configuration']}for name,row in clone.items()},
        'native_budget':{'disk_budget':{'schema_version':2,**policy}}}


class LiteralPolicyTests(unittest.TestCase):
    def setUp(self):
        self.runtime=fixture();self.public=self.runtime['public_configuration']
        self.cap=self.public['captaind'];self.watch=self.public['watchmand']

    def derive(self):return loaded_native_fee_policy(self.runtime,network='regtest')

    def reject(self,reason):
        with self.assertRaisesRegex(EvidenceGap,reason):self.derive()

    def test_authentic_regtest_literal_fields_preserve_absent_cap_rate(self):
        before=copy.deepcopy(self.runtime);result=self.derive()
        self.assertEqual({'captaind':None,'watchmand':50000},result['configured_estimator_ceilings_sat_kvb'])
        self.assertEqual({'round':None,'pool':None,'sweep':50000,'payout':50000,
                          'claim':None,'progression':None},result['fee_ceilings_sat_kvb'])
        self.assertEqual(10000,result['direct_carrier_max_miner_fee_sat'])
        self.assertEqual([],result['configured_pool_targets'])
        self.assertEqual(before,self.runtime)
        self.assertFalse({'complete','qualified','ready','available_cash'}&set(result))

    def test_configured_round_pool_rate_is_not_cumulative_first_promise_authority(self):
        self.cap['fee_estimator_max_sat_kwu']=5000
        result=self.derive();self.assertEqual(20000,result['configured_estimator_ceilings_sat_kvb']['captaind'])
        self.assertIsNone(result['fee_ceilings_sat_kvb']['round'])
        self.assertIsNone(result['fee_ceilings_sat_kvb']['pool'])

    def test_cln_proportional_policy_cannot_invent_fixed_sat_or_urgent_caps(self):
        result=self.derive();self.assertEqual(900000,result['ln_max_fee_ppm'])
        self.assertIsNone(result['fee_ceilings_sat_kvb']['claim'])
        self.assertIsNone(result['fee_ceilings_sat_kvb']['progression'])
        self.assertNotIn('ln_max_fee_sat',result)

    def test_fixture_cannot_be_credited_to_signet(self):
        with self.assertRaisesRegex(EvidenceGap,'networks differ'):
            loaded_native_fee_policy(self.runtime,network='signet')

    def test_actual_config_hash_and_same_projection_both_required(self):
        self.runtime['daemons']['captaind']['config_sha256']='f'*64
        self.reject('same loaded config')

    def test_derived_policy_cannot_replace_running_same_byte_projection(self):
        self.public['captaind']=copy.deepcopy(self.cap)
        self.public['captaind']['ln_max_fee_ppm']=1
        self.reject('same loaded config')

    def test_wrong_product_or_new_funding_grammar_build_needs_source_port(self):
        self.runtime['product_commit']='1'*40
        self.reject('exact reviewed5a')

    def test_wrong_native_source_map_is_not_just_a_label(self):
        self.public['policy_source_sha256']['server/src/vtxopool.rs']='f'*64
        self.reject('semantics source differs')

    def test_legacy_invented_fee_ceilings_map_is_not_native_public_schema(self):
        self.public['fee_ceilings_sat_kvb']={path:20000 for path in ('round','pool','sweep','payout','claim','progression')}
        self.reject('literal protected policy schema')

    def test_missing_configured_rate_field_is_not_implicit_none(self):
        del self.cap['fee_estimator_max_sat_kwu']
        self.reject('policy fields differ')

    def test_bool_float_zero_or_overflow_rate_refuses(self):
        for rate in (True,1.5,0,2**64):
            with self.subTest(rate=rate):
                self.watch['fee_estimator_max_sat_kwu']=rate
                self.reject('configured rate')

    def test_enabled_direct_cannot_use_unbounded_watch_estimator(self):
        self.watch['fee_estimator_max_sat_kwu']=None
        self.reject('requires configured watch fee cap')

    def test_disabled_direct_does_not_receive_positive_fee_path_limits(self):
        self.cap['direct_expiry']['enabled']=False
        self.watch['fee_estimator_max_sat_kwu']=None
        self.assertTrue(all(value is None for value in self.derive()['fee_ceilings_sat_kvb'].values()))

    def test_parallel_legacy_direct_producers_are_refused(self):
        self.cap['legacy_expiry_payout_enabled']=True
        self.reject('legacy producers both enabled')

    def test_paired_policy_cannot_differ_from_held_native_budget(self):
        self.runtime['native_budget']['disk_budget']['urgent_reserve_sat']=1
        self.reject('paired loaded/locked')

    def test_zero_or_boolean_direct_hard_ceiling_is_not_defaulted(self):
        for value in (0,True,None):
            with self.subTest(value=value):
                self.watch['direct_expiry']['max_miner_fee_sat']=value
                self.reject('direct miner ceiling')

    def test_pool_targets_do_not_qualify_missing_first_promise_reservation(self):
        self.cap['vtxopool']['targets']=[{'amount_sat':100000,'count':1}]
        result=self.derive();self.assertEqual([{'amount_sat':100000,'count':1}],result['configured_pool_targets'])
        self.assertIsNone(result['fee_ceilings_sat_kvb']['pool'])

    def test_boolean_projection_schema_refuses(self):
        self.public['schema_version']=True
        self.reject('literal protected policy schema')
