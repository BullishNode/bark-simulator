"""Real controller/SQLite faults with stub native/Core responses, not Signet proof."""
import hashlib
import fcntl
import json
import os
from pathlib import Path
from decimal import Decimal
from unittest.mock import patch
import unittest

from simulator.signet import Campaign
from simulator.signet_load import Load, RSSSamples, funding_batches
from simulator.signet_load_phase import import_load_window
from simulator.model import canonical
from tests import test_signet
from tests.test_signet_load import LoadCore


class FundedScaleTests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown

    def test_explicit_larger_schedules_and_hard_limits(self):
        for count, concurrency, transfers, seconds in [(50,5,600,1200),(200,10,1800,1800),(500,20,7200,3600)]:
            with self.subTest(count=count):
                c=Campaign(self.root / str(count), self.config)
                try:
                    p=Load(c,wallets=count,concurrency=concurrency,transfers=transfers,
                           funding_sat_per_actor=40000,window_seconds=seconds)
                    self.assertEqual(len(p.actors),count)
                    self.assertEqual(p.parameters['funding_sat_per_actor']*count,40000*count)
                    with self.assertRaises(ValueError):
                        Load(c,wallets=count,concurrency=concurrency+1,transfers=transfers)
                finally:c.close()
        for args in [{'wallets':1000},{'wallets':500,'transfers':7201},
                     {'wallets':200,'concurrency':10,'transfers':1800,'window_seconds':1799},
                     {'funding_sat_per_actor':30000},{'window_seconds':7201}]:
            with self.subTest(args=args),self.assertRaises(ValueError):Load(self.campaign,**args)

    def test_batch_fee_budget_counts_only_new_funding_and_bounds_output_count(self):
        for n, batches in [(50,1),(150,2),(300,4)]:
            actors=[{'actor':f'old-{i}','amount_sat':0} for i in range(50)]
            actors += [{'actor':f'new-{i}','amount_sat':40000} for i in range(n)]
            proposal=funding_batches(actors)
            self.assertEqual(len(proposal),batches)
            self.assertEqual(sum(v['principal_sat'] for v in proposal),n*40000)
            self.assertTrue(all(len(v['actors'])<=90 and v['maximum_miner_fee_sat']==10000 for v in proposal))
            self.assertTrue(all(a.startswith('new-') for v in proposal for a in v['actors']))
            self.assertEqual(len({a for v in proposal for a in v['actors']}),n)

    def test_elapsed_window_holds_new_dispatch_without_replaying_completed_work(self):
        p=Load(self.campaign, transfers=3,window_seconds=10)
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted','{}')")
        self.campaign.db.execute("INSERT INTO result VALUES ('original-batch',100,?)",(canonical({'kind':'load_batch_started'}),))
        with patch('simulator.signet_load.time.time',return_value=111),patch('simulator.signet_load._transfer') as worker:
            self.assertEqual(p.advance_batch()['stage'],'LOAD_WINDOW_LIMIT_REACHED')
            with self.assertRaisesRegex(ValueError,'held'):p.advance_batch()
        worker.assert_not_called()
        with self.assertRaisesRegex(ValueError,'unreconciled'):p.finish()

    def test_five_hundred_wallet_batch_wrap_keeps_twenty_disjoint_pairs(self):
        p=Load(self.campaign,wallets=500,concurrency=20,transfers=7200,
               funding_sat_per_actor=40000,window_seconds=3600)
        self.campaign.db.execute("INSERT INTO meta VALUES ('load_admitted','{}')")
        for i in range(240):
            self.campaign.db.execute('INSERT INTO result VALUES (?,0,?)',(f'load-transfer-{i:06d}-complete','{}'))
        with patch('simulator.signet_load._transfer',side_effect=lambda directory,config,params,i:{'index':i}) as worker:
            result=p.advance_batch()
        self.assertEqual(result['indices'],list(range(240,260)))
        self.assertEqual(len({i%250 for i in result['indices']}),20)
        self.assertEqual(worker.call_count,20)
        self.assertEqual(result['stage'],'LOAD_BATCH_RECONCILED')

    def test_restarted_pid_is_not_reported_as_same_process_cpu(self):
        with patch.object(RSSSamples,'cpu',side_effect=[{'start_ticks':1,'cpu_seconds':10},
                                                      {'start_ticks':2,'cpu_seconds':12}]):
            with RSSSamples({}) as samples:pass
        self.assertEqual(samples.result['cpu_identity_missing_or_changed'],['controller'])
        self.assertNotIn('controller',samples.result['process_cpu_seconds'])
        self.assertGreaterEqual(samples.result['observed_wall_seconds'],0)
        self.assertGreaterEqual(samples.result['reaped_child_cpu_seconds']['user'],0)

    def test_cpu_parser_uses_kernel_tick_units_and_handles_spaces_in_comm(self):
        fields=['S']+['0']*19
        fields[11]='40';fields[12]='10';fields[19]='12345'
        with patch('simulator.signet_load.Path.read_text',return_value='123 (native worker (test)) '+' '.join(fields)), \
             patch('simulator.signet_load.os.sysconf',return_value=100):
            self.assertEqual(RSSSamples.cpu(123),{'start_ticks':12345,'cpu_seconds':.5})

    def funding_fixture(self):
        p=Load(self.campaign,funding_sat_per_actor=40000)
        self.campaign.core=LoadCore()
        tid='12'*32; script='0014'+'34'*20
        self.campaign.db.execute("INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)",('load-000-funding-address','load-000','onchain_address','{}','acknowledged',0,0,'{}',canonical({'address':'tb1q'+'34'*20}),None))
        self.campaign.core.funding[tid]={'value':Decimal('.0004'),'confirmations':3,
             'bestblock':self.campaign.core.info['bestblockhash'],'scriptPubKey':{'hex':script}}
        funding=[{'outpoint':tid+':0','actor':'load-000','amount_sat':40000}]
        owned=[{'outpoint':tid+':0','amount_sat':40000,'confirmation_height':120}]
        self.campaign.core.transactions[tid]={'txid':tid,'vout':[{'n':0,'value':Decimal('.0004')}]}
        return p,funding,owned

    def test_preflight_rejects_misdirection_spent_and_extra_wallet_assets_before_board(self):
        for fault in ['wrongscript','spent','extracoin','wrongamount','unconfirmed','tipdrift']:
            with self.subTest(fault=fault):
                # Each preflight uses the same retained receipt, with independently
                # changed live Core/native inventory; no money function is called.
                if not hasattr(self,'fixture'):self.fixture=self.funding_fixture()
                p,funding,owned=self.fixture
                core=LoadCore();self.campaign.core=core
                core.funding['12'*32]={'value':Decimal('.0004'),'confirmations':3,
                    'bestblock':core.info['bestblockhash'],'scriptPubKey':{'hex':'0014'+'34'*20}}
                inventory=list(owned)
                output=core.funding['12'*32]
                if fault=='wrongscript':output['scriptPubKey']['hex']='0014'+'56'*20
                if fault=='spent':core.funding['12'*32]=None
                if fault=='extracoin':inventory=owned+[{'outpoint':'77'*32+':0','amount_sat':1,'confirmation_height':120}]
                if fault=='wrongamount':output['value']=Decimal('.00039999')
                if fault=='unconfirmed':output['confirmations']=0
                if fault=='tipdrift':output['bestblock']='ee'*32
                with patch.object(p,'native',return_value=inventory) as native,self.assertRaises(ValueError):
                    p.preflight_actor('load-000',funding)
                self.assertEqual(native.call_args.args[2],'onchain_utxos')
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action WHERE operation='board'").fetchone()[0],0)

    def test_real_fee_is_inside_allocation_warning_is_not_an_invented_cap(self):
        p,funding,owned=self.funding_fixture()
        self.campaign.db.execute("INSERT INTO result VALUES ('fund',0,?)",(canonical({'kind':'external_funding',**funding[0]}),))
        with patch.object(p,'native',return_value=owned):
            result=p.preflight_actor('load-000',funding)
        self.assertEqual(result['combined_fee_and_reserve_capacity_sat'],10000)
        self.assertFalse(result['fee_quote_available'])
        board='ab'*32
        self.campaign.core.transactions[board]={'txid':board,'vin':[{'txid':'12'*32,'vout':0}],
             'vout':[{'n':0,'value':Decimal('.0003')},{'n':1,'value':Decimal('.00008')}]}
        cost=p.board_cost('load-000',board)
        self.assertEqual((cost['miner_fee_sat'],cost['other_outputs_sat']),(2000,8000))
        self.assertTrue(cost['fee_warning_above_1000_sat'])
        self.assertEqual(cost['allocated_sat'],cost['board_principal_sat']+cost['miner_fee_sat']+cost['other_outputs_sat'])
        self.campaign.core.transactions[board]['vin'].append({'txid':'12'*32,'vout':0})
        with self.assertRaisesRegex(ValueError,'outside'):p.board_cost('load-000',board)

    def completed_fixture(self, new_count=200):
        old=self.campaign
        p=Load(old,wallets=50,concurrency=5,transfers=200)
        result={'stage':'LOAD_WORKLOAD_FINANCIALLY_RECONCILED','parameters':p.parameters,
          'successful_reconciled_transfers':200,'failed_or_unknown_transfers':0,
          'opening_coin_sat':500000,'closing_coin_sat':500000,'observed_offchain_fee_sat':0}
        result_file=self.root/'previous-result.json';result_file.write_text(canonical(result))
        stop=self.root/'STOP';stop.touch();lock=self.root/'runner.lock';lock.touch();pid=self.root/'runner.pid';pid.write_text('99999999')
        chain=canonical({'height':123})
        def action(intent,actor,operation,reply):
            old.db.execute('INSERT INTO action VALUES (?,?,?,?,?,?,?,?,?,?)',(intent,actor,operation,'{}','acknowledged',0,0,chain,canonical(reply),None))
        for i in range(50):
            actor=f'load-{i:03d}';path=old.actor_path(actor);path.mkdir(parents=True)
            (path/'config.toml').write_text('server_address = "'+self.config['ark_url']+'"\nbitcoind_address = "'+self.config['core_url']+'"\nbitcoind_cookiefile = "'+self.config['core_credential']+'"\n')
            (path/'mnemonic').write_text('private synthetic test seed, not live money')
            action(actor+'-create',actor,'create',{})
            key=hashlib.sha256(actor.encode()).hexdigest()
            action(actor+'-registration',actor,'fallback_record',{'record_hex':str(i),
                'payout_address':'tb1q'+key[:40],'record':{'spk':'0014'+key[:40]}})
            action('load-final-'+actor,actor,'sync_vtxos',[{'id':str(i),'state':'spendable','amount_sat':10000}])
        action('load-native-target-info','load-000','ark_info',{'server_pubkey':'02'+'11'*32})
        for i in range(200):old.db.execute('INSERT INTO result VALUES (?,0,?)',(f'load-transfer-{i:06d}-complete','{}'))
        new=Campaign(self.root/'new-phase',self.config)
        Load(new,wallets=new_count,concurrency=10 if new_count==200 else 5,
             transfers=1800 if new_count==200 else 600,funding_sat_per_actor=40000,
             window_seconds=1800 if new_count==200 else 1200)
        args=dict(stop_file=stop,lock_file=lock,pid_file=pid,result_file=result_file,archive=self.root/'archive')
        return old,new,args

    def test_cold_cumulative_handoff_copies_seeds_without_create_ack_or_funding_credit(self):
        old,new,args=self.completed_fixture()
        try:
            result=import_load_window(old,new,**args)
            self.assertEqual(result['reused_wallets'],50)
            self.assertEqual(new.db.execute('SELECT count(*) FROM action').fetchone()[0],0)
            self.assertEqual(new.db.execute("SELECT count(*) FROM meta WHERE key LIKE 'load_existing:%'").fetchone()[0],50)
            self.assertEqual((new.actor_path('load-000')/'mnemonic').read_text(),'private synthetic test seed, not live money')
            self.assertEqual((new.actor_path('load-000')/'mnemonic').stat().st_mode & 0o777,0o600)
            self.assertTrue((args['archive']/'signet.sqlite').exists())
            with self.assertRaises(ValueError):import_load_window(old,new,**args)
        finally:new.close()

    def test_live_or_unknown_or_absent_predecessor_is_never_copied(self):
        old,new,args=self.completed_fixture()
        try:
            args['pid_file'].write_text(str(os.getpid()))
            with self.assertRaisesRegex(ValueError,'still alive'):import_load_window(old,new,**args)
            args['pid_file'].write_text('99999999')
            with args['lock_file'].open('r+') as held:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):import_load_window(old,new,**args)
            old.db.execute("INSERT INTO actor VALUES ('load-000',1)")
            with self.assertRaisesRegex(ValueError,'absent'):import_load_window(old,new,**args)
            old.db.execute('UPDATE actor SET absent=0')
            old.db.execute("UPDATE action SET state='unknown' WHERE id='load-000-create'")
            with self.assertRaisesRegex(ValueError,'unknown'):import_load_window(old,new,**args)
            self.assertFalse(args['archive'].exists())
            self.assertFalse((new.root/'wallets').exists())
        finally:new.close()

    def test_reused_fifty_request_zero_new_funding_and_never_run_create(self):
        old,new,args=self.completed_fixture(new_count=50)
        try:
            import_load_window(old,new,**args)
            new.core=LoadCore()
            phase=Load(new,wallets=50,concurrency=5,transfers=600,
                       funding_sat_per_actor=40000,window_seconds=1200)
            def native(intent,actor,operation,args=None):
                key=hashlib.sha256(actor.encode()).hexdigest()
                if operation=='fallback_record':
                    return json.loads(new.db.execute('SELECT value FROM meta WHERE key=?',('load_existing:'+actor,)).fetchone()[0])['registration']
                if operation=='onchain_address':return {'address':'tb1q'+'ff'+key[:38]}
                if operation=='address':return {'address':'tark1'+key}
                if operation=='ark_info':return {'network':'signet','vtxo_lifetime':4320,'vtxo_exit_delta':144,
                    'required_board_confirmations':3,'min_board_amount_sat':20000,'server_pubkey':'02'+'11'*32}
                raise AssertionError('no create or monetary action allowed for imported cohort')
            with patch.object(phase,'native',side_effect=native) as run:
                result=phase.prepare()
            self.assertEqual(result['total_actor_principal_sat'],0)
            self.assertEqual(result['funding_batches'],[])
            self.assertTrue(all(a['existing_native_inventory'] and a['amount_sat']==0 for a in result['actors']))
            self.assertFalse(any(c.args[2]=='create' for c in run.call_args_list))
            def wrong_server(intent,actor,operation,args=None):
                value=native(intent,actor,operation,args)
                if operation=='ark_info':value['server_pubkey']='02'+'22'*32
                return value
            with patch.object(phase,'native',side_effect=wrong_server),self.assertRaisesRegex(ValueError,'different server'):
                phase.prepare()
        finally:new.close()


if __name__=='__main__':unittest.main()
