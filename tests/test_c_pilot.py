"""Synthetic policy/source controls; none are native signature or live money proof."""
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from simulator import c_pilot
from simulator.architecture import DIRECT_PER_KEY
from simulator.model import SIGNET_GENESIS
from simulator.store import Store
from simulator.per_key import initial_origins,link_bytes
from simulator.finite_funding import funding_policy
from simulator.first_board_readiness import _validate_plan
from simulator.finite_funding_readiness import _c_records_links
from simulator.ownership import record_verified
from tests.test_direct_per_key import public_objects


PINS={'product_commit':'1'*40,'sdk_commit':'2'*40,'driver_sha256':'3'*64,
      'configuration_sha256':'4'*64,'schema_sha256':'5'*64}


def pilot():
    return {**copy.deepcopy(c_pilot.FIXED),'id':'c-first','pins':PINS,'boundary_id':'c-treasury',
        'bank_opening_sat':150000,'board_action_id':'c-board-original','arkoor_action_id':'c-send-original'}


def initial_data(offset=0):
    record,link,binding,_=public_objects()
    if offset:
        from simulator.per_key import record_bytes
        record={**record,'mailbox_pk':'02'+format(1000+offset,'064x'),'spk':'0014'+format(offset,'040x')}
        binding={'mailbox_pk':record['mailbox_pk'],'spk':record['spk'],'fallback_record':record_bytes(record)}
    rows=[];proofs=[]
    for index in range(51):
        key='03'+format(offset+index+1,'064x')
        encoded=link_bytes({**link,'user_pubkey':key,'mailbox_pk':binding['mailbox_pk'],'recovery_index':index})
        origin={'user_pubkey':key,'key_link_attestation':encoded,'binding':binding}
        rows.append({'native_index':index,'origin':origin})
        proofs.append({'user_pubkey':key,'financial_pins':PINS,'binding':{**binding,
            'record_version':4,'key_link_version':1,'key_link_attestation':encoded,
            'recovery_index':index,'policy_pubkey_full':key,'record_signature_valid':True,'key_link_signature_valid':True}})
    return {'binding':binding,'initial_key_links':rows},proofs


class CPilotControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)
        self.store=Store(self.path/'c','synthetic',60000,architecture_profile=DIRECT_PER_KEY)
        self.store.actor('actor-01','synthetic sender');self.store.actor('actor-02','synthetic recipient')
        self.store.db.execute("INSERT OR REPLACE INTO meta VALUES ('paused','true')")
        c_pilot.declare(self.store,pilot())
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def test_c_uses_one_sender_output_and_exact_ids_while_b_policy_is_unchanged(self):
        policy=funding_policy(self.store)
        self.assertEqual({'actor-01':25000},policy['amounts']);self.assertEqual(1000,policy['maximum_fee_sat'])
        self.assertEqual(150000,policy['opening_sat']);self.assertEqual(40000,policy['urgent_budget_sat'])
        b=Store(self.path/'b','synthetic',60000)
        try:
            original=funding_policy(b)
            self.assertEqual(325000,original['principal_sat']);self.assertEqual(5,len(original['amounts']))
            with self.assertRaisesRegex(ValueError,'direct_per_key'):c_pilot.declare(b,pilot())
        finally:b.close()
        board={'id':'c-first-board','pins':PINS,'boundary_id':'c-treasury',
            'board_actions':{'actor-01':'c-board-original'},'amount_sat':20000,'maximum_fee_sat':1000}
        self.assertEqual(board,_validate_plan(board,self.store))
        for change in ({'board_actions':{'actor-02':'c-board-original'}},{'maximum_fee_sat':4000},
                       {'board_actions':{'actor-01':'replacement'}}):
            with self.subTest(change=change),self.assertRaises(ValueError):_validate_plan({**board,**change},self.store)
    def test_budget_principal_confirmation_lifetime_and_mutability_controls(self):
        for field,value in [('bank_opening_sat',125999),('bank_opening_sat',900001),
                            ('grants_sat',{'actor-01':25000,'actor-02':25000}),
                            ('board_confirmations',2),('ordinary_lifetime_blocks',12),
                            ('pool_lifetime_blocks',12),('urgent_fee_budget_sat',15000),
                            ('funding_max_miner_fee_sat',10000),('schema_version',True)]:
            with self.subTest(field=field),self.assertRaises(ValueError):c_pilot.validate({**pilot(),field:value})
        self.assertFalse(c_pilot.declare(self.store,pilot()))
        with self.assertRaisesRegex(ValueError,'immutable'):c_pilot.declare(self.store,{**pilot(),'bank_opening_sat':160000})
    def test_original_51_link_frame_requires_unique_exact_order_and_signed_metadata(self):
        data,_=initial_data();self.assertEqual(51,len(initial_origins(data)))
        for case in ('missing','duplicate','reorder','wrong-index','old-profile'):
            value=copy.deepcopy(data)
            if case=='missing':value['initial_key_links'].pop()
            if case=='duplicate':value['initial_key_links'][50]['origin']=copy.deepcopy(value['initial_key_links'][0]['origin'])
            if case=='reorder':value['initial_key_links'].reverse()
            if case=='wrong-index':value['initial_key_links'][50]['native_index']=25
            if case=='old-profile':value['initial_key_links'][0]['origin']['binding']['account_xpub']='old'
            with self.subTest(case=case),self.assertRaises(ValueError):initial_origins(value)
    def test_initial_frontier_rejects_missing_independent_signature_receipts(self):
        data,_=initial_data()
        with self.assertRaisesRegex(ValueError,'independently verified'):_c_records_links(self.store,{'actor-01':data},PINS)
    def test_initial_frontier_matches_all_102_original_proofs_and_refuses_changed_context(self):
        values={}
        for actor,offset in (('actor-01',0),('actor-02',100)):
            data,proofs=initial_data(offset);values[actor]=data
            objects=[{'kind':'key','proof':proof,'request_origin':row['origin']}
                for row,proof in zip(data['initial_key_links'],proofs)]
            record_verified(self.store,actor,'synthetic-create',{'objects':objects,'movements':[]})
        records,links=_c_records_links(self.store,values,PINS)
        self.assertEqual(2,len(records));self.assertEqual(102,len(links))
        self.assertEqual(set(range(51)),{row['recovery_index'] for row in links})
        with self.assertRaisesRegex(ValueError,'independently verified'):
            _c_records_links(self.store,values,{**PINS,'driver_sha256':'9'*64})


class NativeStartupControls(CPilotControls):
    def frames(self):
        now=datetime.datetime.now(datetime.timezone.utc)
        started=(now-datetime.timedelta(seconds=30)).isoformat();prior=int((now-datetime.timedelta(seconds=60)).timestamp()*10**9)
        expected={'architecture_profile':DIRECT_PER_KEY,'product_commit':PINS['product_commit'],
            'schema_sha256':PINS['schema_sha256'],'database':'trackc','services':{}}
        current={'kind':'owned_native_startup_source','architecture_profile':DIRECT_PER_KEY,'runtime_transport':'systemd',
            'product_commit':PINS['product_commit'],'schema_sha256':PINS['schema_sha256'],'observed_at':now.isoformat(),'daemons':{}}
        for index,service in enumerate(('captaind','watchmand')):
            spec={'unit':'track-c-'+service+'.service','executable_path':'/opt/track-c/runtime/'+service,
                'executable_sha256':'a'*64,'config_path':'/etc/track-c/'+service+'.toml',
                'config_sha256':'b'*64,'admin_address':'127.0.0.1:'+str(3536+index*2)}
            expected['services'][service]=spec
            cfg={'network':'signet','postgres_database':'trackc','fee_estimator':{'max_fee_rate':'20 sat/vb'}}
            if service=='captaind':cfg.update(vtxo_lifetime=48,pool_lifetime_blocks=48,required_board_confirmations=3,
                direct_expiry={'enabled':True},expiry_payout={'enabled':False},lightning_configured=False,vtxopool={'vtxo_targets':[]})
            row={'unit':spec['unit'],'pid':100+index,'boot_id':'a'*8+'-'+'b'*4+'-'+'c'*4+'-'+'d'*4+'-'+'e'*12,
                'start_ticks':200+index,'invocation_id':'c'*32,'started_at':started,'running':True,'restart_count':0,
                'binary_sha256':'a'*64,'process_exe_sha256':'a'*64,'process_exe_path':spec['executable_path'],
                'config_path':spec['config_path'],'config_sha256':'b'*64,'config_device':1,'config_inode':10+index,
                'config_mtime_ns':prior,'config_ctime_ns':prior,'process_cmdline':[spec['executable_path'],'--config',spec['config_path'],'start'],
                'version':service+' '+PINS['product_commit'],'environment_names':['PATH'],'config_overrides':{},
                'public_loaded_config_provenance':cfg,
                'pre_exec_config':{'path':spec['config_path'],'sha256':'b'*64,'device':1,'inode':10+index,
                    'mtime_ns':prior,'ctime_ns':prior,'captured_at_ns':prior+1,'invocation_id':'c'*32}}
            current['daemons'][service]=row
        return expected,copy.deepcopy(current),current
    def verify(self,expected,original,current):
        from simulator.runtime_startup import verify_owned_startup_sources
        a=self.path/'startup.json';b=self.path/'current.json';a.write_text(json.dumps(original));b.write_text(json.dumps(current))
        return verify_owned_startup_sources(self.store,a,b,expected=expected)
    def test_native_same_invocation_receipt_stays_scoped_and_rejects_process_or_config_changes(self):
        expected,original,current=self.frames()
        receipt=self.verify(expected,original,current)
        self.assertTrue(receipt['loaded_configuration_identity_verified']);self.assertFalse(receipt['complete']);self.assertFalse(receipt['qualified'])
        for field,value in [('pid',999),('start_ticks',999),('invocation_id','d'*32),('process_exe_sha256','f'*64),
                            ('config_inode',900),('config_ctime_ns',time_ns())]:
            changed=copy.deepcopy(current);changed['daemons']['captaind'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.verify(expected,original,changed)
    def test_missing_preexec_base_version_and_shortened_policy_hold(self):
        expected,original,current=self.frames()
        old=copy.deepcopy(original);old['daemons']['captaind'].pop('pre_exec_config')
        with self.assertRaisesRegex(ValueError,'pre-exec'):self.verify(expected,old,current)
        for key,value in [('required_board_confirmations',2),('vtxo_lifetime',12),('pool_lifetime_blocks',12)]:
            changed=copy.deepcopy(current);changed['daemons']['captaind']['public_loaded_config_provenance'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify(expected,original,changed)
        current['daemons']['captaind']['version']='c0 base'
        with self.assertRaisesRegex(ValueError,'release'):self.verify(expected,original,current)


def time_ns():
    import time
    return time.time_ns()


if __name__=='__main__':unittest.main()
