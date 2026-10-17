"""Stopped-cohort repair tests with native/Core stubs, not Signet credit."""
from decimal import Decimal
import fcntl
import hashlib
import io
import json
import subprocess
import time
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet import Campaign
from simulator.signet_repair import stage, advance, FIRST_PAYOUT, BIRTHDAY
from tests import test_signet_s02 as fixture
from tests import test_signet_phase as phase_fixture

FIRST = FIRST_PAYOUT.split(':')[0]
SECOND, CHILD1, CHILD2, RECOVERY, FEEWALLET, ROOT2 = [c * 64 for c in 'cde789']


class Core(fixture.LifecycleCore):
    def __init__(self):
        super().__init__()
        self.info['blocks'] = 326800
        self.info['bestblockhash'] = self.blockhash(326800)
        self.heights = {fixture.ANCHOR:326700, ROOT2:326700, FEEWALLET:326700,
                        FIRST:326715, SECOND:326780, CHILD1:326715, CHILD2:326780, RECOVERY:326800}
        self.transactions = {
            fixture.ANCHOR:{'vin':[],'vout':[fixture.output(30000)]},
            ROOT2:{'vin':[],'vout':[fixture.output(30000)]},
            FEEWALLET:{'vin':[],'vout':[fixture.output(10000), fixture.output(10000,index=1)]},
            FIRST:{'vin':[{'txid':fixture.ANCHOR,'vout':0}], 'vout':[
                fixture.output(28670),fixture.output(1330,fixture.DESTINATION,1),fixture.output(0,'51024e73',2)]},
            SECOND:{'vin':[{'txid':ROOT2,'vout':0}], 'vout':[
                fixture.output(9000),fixture.output(21000,fixture.DESTINATION,1),fixture.output(0,'51024e73',2)]},
            CHILD1:{'vin':[{'txid':FIRST,'vout':2},{'txid':FEEWALLET,'vout':0}], 'vout':[fixture.output(9000,fixture.DESTINATION)]},
            CHILD2:{'vin':[{'txid':SECOND,'vout':2},{'txid':FEEWALLET,'vout':1}], 'vout':[fixture.output(9200,fixture.DESTINATION)]},
            RECOVERY:{'vin':[{'txid':FIRST,'vout':0},{'txid':SECOND,'vout':0}], 'vout':[fixture.output(37492,fixture.DESTINATION)]}}
        for txid, tx in self.transactions.items():
            tx.update(txid=txid,version=3,confirmations=self.info['blocks']-self.heights[txid]+1,
                      blockhash=self.blockhash(self.heights[txid]))

    @staticmethod
    def blockhash(height):return f'{height:064x}'

    def coinbase(self,height):
        return {'txid':f'f{height:063x}','blockhash':self.blockhash(height),'vin':[{'coinbase':'00'}],
                'vout':[fixture.output(0,'6a')],'confirmations':self.info['blocks']-height+1}

    def call(self, method, *args):
        if method == 'getblockhash' and args[0] != 0:return self.blockhash(args[0])
        if method == 'getblock':
            if len(args) != 2 or args[1] != 1:
                raise ValueError('public block transaction-id inventory required')
            height=int(args[0],16)
            txs = [self.coinbase(height)] + [tx for k,tx in self.transactions.items() if tx['blockhash']==args[0] and tx['confirmations']>0]
            return {'hash':args[0],'height':height,'tx':[tx['txid'] for tx in txs]}
        if method=='getrawtransaction' and args[0].startswith('f') and args[0] not in self.transactions:
            return self.coinbase(int(args[0][1:],16))
        return super().call(method,*args)


class RepairTests(unittest.TestCase):
    setUp, tearDown = fixture.S02Tests.setUp, fixture.S02Tests.tearDown
    source, receipt = fixture.S02Tests.source, fixture.S02Tests.receipt

    def prepare(self):
        self.core = Core();self.campaign.core=self.core
        phase_fixture.PhaseTests.fixture(self)
        self.source()
        from simulator.signet_s02 import _backup_recovery_source
        _backup_recovery_source(self.campaign,'absent')
        coins=[{'id':c*64+':0','amount_sat':amount,'chain_anchor':root+':0','expiry_height':326714,
                'user_pubkey':'02'+'1'*64,'state':'spendable'}
               for c,amount,root in [('1',29670,fixture.ANCHOR),('2',10000,ROOT2)]]
        self.frozen={'kind':'S02_absent_cohort','actor':'absent','coins':coins,
                     'registration':{'payout_address':'tb1qpayout','record':{'spk':fixture.SCRIPT}},
                     'signature_proofs':[{'coin_id':c['id'],'status':'PASS','path_outpoints':[c['chain_anchor'],c['id']]} for c in coins],
                     'chain':{'height':326706}}
        encoded=canonical(self.frozen);self.freeze_hash=hashlib.sha256(encoded.encode()).hexdigest()
        self.campaign.db.execute("INSERT INTO actor VALUES ('absent',1)")
        self.campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)",(encoded,))
        self.receipt('s02-absent-create','create',{},actor='absent')
        self.campaign.db.execute("UPDATE action SET chain=? WHERE id='s02-absent-create'",(canonical({'height':BIRTHDAY}),))

    def stage(self):
        with patch('simulator.signet.ChainReader',return_value=self.core):
            return stage(self.campaign.root,self.new_directory,self.new_config,self.runtime_pins,
                         stop_file=self.stop,lock_file=self.lock,frozen_sha256=self.freeze_hash,
                         destination='tb1qrecovered')

    def open_new(self):
        phase=Campaign(self.new_directory,self.new_config);phase.core=self.core
        self.addCleanup(phase.close);return phase

    def native(self, argv, **kwargs):
        from pathlib import Path
        path=Path(argv[argv.index('--datadir')+1]);self.assertEqual(path.name,'restored')
        if 'create' in argv:
            self.assertEqual(argv[argv.index('--birthday-height')+1],str(BIRTHDAY))
            self.assertIn('--mnemonic-file',argv)
            self.assertNotIn('--mnemonic',argv)
            self.assertFalse((path/'wallet.sqlite').exists())
            self.assertNotIn(FIRST,argv);self.assertNotIn(SECOND,argv)
            result=None
        elif 'utxos' in argv:
            result=[{'outpoint':txid+':0','amount_sat':amount,'confirmation_height':self.core.heights[txid]}
                    for txid,amount in [(FIRST,28670),(SECOND,9000)]]
        else:
            self.assertIn('drain',argv);result={'txid':RECOVERY}
        if result is not None:kwargs['stdout'].write(json.dumps(result).encode())
        return subprocess.CompletedProcess(argv,0)

    def test_stage_imports_only_public_frozen_proofs_and_protected_phrase(self):
        self.prepare();old_actions=self.campaign.db.execute('SELECT count(*) FROM action').fetchone()[0]
        with patch('simulator.signet.subprocess.run') as native:self.stage()
        native.assert_not_called();phase=self.open_new()
        self.assertEqual(phase.db.execute('SELECT count(*) FROM action').fetchone()[0],0)
        self.assertEqual(phase.db.execute("SELECT absent FROM actor WHERE id='absent'").fetchone()[0],1)
        self.assertFalse((self.new_directory/'wallets').exists())
        self.assertEqual((self.new_directory/'private/s02-recovery-source-absent.source').read_bytes(),self.source())
        self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM action').fetchone()[0],old_actions)
        self.assertEqual(json.loads(phase.db.execute("SELECT value FROM meta WHERE key='s03_repair_origin'").fetchone()[0])['original_config']['source_commit'],'a'*40)
        with self.assertRaisesRegex(ValueError,'new disjoint'):self.stage()

    def test_stop_live_lock_wrong_freeze_or_source_tampering_prevents_staging(self):
        self.prepare();self.stop.unlink()
        with self.assertRaisesRegex(ValueError,'STOP'):self.stage()
        self.stop.touch()
        with self.lock.open('r+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.stage()
        original=self.freeze_hash;self.freeze_hash='0'*64
        with self.assertRaisesRegex(ValueError,'digest'):self.stage()
        self.freeze_hash=original
        (self.campaign.root/'private/s02-recovery-source-absent.source').write_text('tampered')
        with self.assertRaisesRegex(ValueError,'source changed'):self.stage()
        self.assertFalse(self.new_directory.exists())

    def test_one_missing_wrong_payee_or_wrong_path_payout_never_opens_wallet(self):
        self.prepare();self.stage();phase=self.open_new()
        self.core.transactions[SECOND]['confirmations']=0
        with patch('simulator.signet.subprocess.run') as native:
            self.assertEqual(advance(phase)['stage'],'WAITING_FOR_BOTH_EXACT_PAYOUTS')
        native.assert_not_called()
        self.core.transactions[SECOND]['confirmations']=21
        # Rewind public inventory after a new canonical block observation.
        phase.db.execute("DELETE FROM meta WHERE key='s02_discovery:absent'")
        self.core.transactions[SECOND]['vout'][0]['scriptPubKey']['hex']=fixture.DESTINATION
        with patch('simulator.signet.subprocess.run') as native:
            self.assertEqual(advance(phase)['stage'],'WAITING_FOR_BOTH_EXACT_PAYOUTS')
        native.assert_not_called()
        self.core.transactions[SECOND]['vout'][0]['scriptPubKey']['hex']=fixture.SCRIPT
        phase.db.execute("DELETE FROM meta WHERE key='s02_discovery:absent'")
        self.core.transactions[SECOND]['vin'][0]['txid']=fixture.ANCHOR
        with patch('simulator.signet.subprocess.run') as native:
            self.assertEqual(advance(phase)['stage'],'WAITING_FOR_BOTH_EXACT_PAYOUTS')
        native.assert_not_called()

    def test_real_store_restore_drains_once_requires_both_confirmed_inputs_and_preserves_non_grouping(self):
        self.prepare();self.stage();phase=self.open_new();self.core.transactions[RECOVERY]['confirmations']=0
        with patch('simulator.signet.subprocess.run',side_effect=self.native) as native:
            waiting=advance(phase)
            self.assertEqual(waiting['stage'],'WAITING_FOR_CONFIRMED_RECOVERY')
            self.core.transactions[RECOVERY]['confirmations']=1
            result=advance(phase);again=advance(phase)
        self.assertEqual(native.call_count,3) # create, UTXOs, drain; never repeat native dispatch
        self.assertEqual(result['case_verdict'],'PASS');self.assertEqual(again['case_verdict'],'PASS')
        self.assertEqual(result['historical_grouping_verdict'],'NOT_QUALIFIED')
        self.assertEqual(result['confirmed_payout_sat'],37670)
        self.assertEqual(result['actual_payout_output_fees_sat'],2000)
        self.assertEqual(sorted(r['consumed_payout_outpoint'] for r in result['recovery']),sorted([FIRST_PAYOUT,SECOND+':0']))
        self.assertEqual(sorted(f['child_miner_fee_sat'] for f in result['fee_children']),[800,1000])
        self.assertEqual({r['miner_fee_sat'] for r in result['recovery']},{178})
        self.assertEqual(result['recovery_spend']['miner_fee_sat'],178)
        self.assertEqual(result['recovery_spend']['ordinary_other_inputs'],[])
        self.core.transactions[RECOVERY]['vin'].pop()
        with patch('simulator.signet.subprocess.run') as native:
            self.assertNotEqual(advance(phase)['case_verdict'],'PASS')
        native.assert_not_called()

    def test_unknown_drain_cannot_be_replayed_or_ignored(self):
        self.prepare();self.stage();phase=self.open_new()
        def native(argv,**kwargs):
            if 'drain' in argv:raise subprocess.TimeoutExpired('native drain',120)
            return self.native(argv,**kwargs)
        with patch('simulator.signet.subprocess.run',side_effect=native):
            with self.assertRaisesRegex(ValueError,'requires reconciliation'):advance(phase)
        with patch('simulator.signet.subprocess.run') as replay:
            with self.assertRaisesRegex(ValueError,'unknown action'):advance(phase)
        replay.assert_not_called()
        self.assertEqual(phase.db.execute("SELECT state FROM action WHERE id='s03-repair-drain'").fetchone()[0],'unknown')

    def test_tip_change_between_per_payout_recovery_checks_needs_coherent_rerun(self):
        self.prepare();self.stage();phase=self.open_new()
        from simulator.signet_s02 import check_recovery
        count=0
        def changing_tip(*args):
            nonlocal count
            result=check_recovery(*args)
            count+=1
            if count==1:
                self.core.info['blocks']+=1
                self.core.info['bestblockhash']=self.core.blockhash(self.core.info['blocks'])
                for tx in self.core.transactions.values():tx['confirmations']+=1
            return result
        with patch('simulator.signet.subprocess.run',side_effect=self.native), \
             patch('simulator.signet_repair.check_recovery',side_effect=changing_tip):
            result=advance(phase)
        self.assertEqual([r['recovery_check'] for r in result['recovery']],['PASS','PASS'])
        self.assertEqual(result['case_verdict'],'INCOMPLETE')
        with patch('simulator.signet.subprocess.run') as native:
            self.assertEqual(advance(phase)['case_verdict'],'PASS')
        native.assert_not_called()

    def test_unconfirmed_fee_child_or_reorged_payout_never_starts_seed_recovery(self):
        self.prepare();self.stage();phase=self.open_new()
        self.core.transactions[CHILD1]['confirmations']=0
        with patch('simulator.signet.subprocess.run') as native:
            self.assertEqual(advance(phase)['stage'],'WAITING_FOR_CONFIRMED_FEE_CHILDREN')
        native.assert_not_called()
        self.core.transactions[FIRST]['confirmations']=0
        with patch('simulator.signet.subprocess.run') as native:
            self.assertEqual(advance(phase)['stage'],'WAITING_FOR_BOTH_EXACT_PAYOUTS')
        native.assert_not_called()

    def test_both_payout_and_fee_child_need_six_real_confirmations_before_restore(self):
        self.prepare();self.stage();phase=self.open_new()
        def tip(height):
            self.core.info['blocks']=height
            self.core.info['bestblockhash']=self.core.blockhash(height)
            for txid,tx in self.core.transactions.items():
                tx['confirmations']=max(0,height-self.core.heights[txid]+1)
        tip(326784)
        with patch('simulator.signet.subprocess.run') as native:
            first=advance(phase)
        self.assertEqual(first['stage'],'WAITING_FOR_SIX_CONFIRMATIONS')
        self.assertEqual(first['payout_confirmations'][SECOND+':0'],5)
        native.assert_not_called()
        self.core.heights[CHILD2]=326784
        self.core.transactions[CHILD2]['blockhash']=self.core.blockhash(326784)
        tip(326788)
        with patch('simulator.signet.subprocess.run') as native:
            child=advance(phase)
        self.assertEqual(child['stage'],'WAITING_FOR_SIX_CONFIRMATIONS')
        self.assertTrue(all(c>=6 for c in child['payout_confirmations'].values()))
        self.assertEqual(min(f['confirmations'] for f in child['fee_children']),5)
        native.assert_not_called()
        tip(326789)
        with patch('simulator.signet.subprocess.run',side_effect=self.native) as native:
            self.assertEqual(advance(phase)['stage'],'WAITING_FOR_CONFIRMED_RECOVERY')
        self.assertEqual(native.call_count,3)

    def test_fee_child_uses_real_chainreader_allowlist_and_bounded_resumable_inventory(self):
        from simulator.chain import ChainReader
        from simulator.signet_repair import _fee_child
        self.prepare();self.stage();phase=self.open_new()
        cookie=self.new_directory/'core-cookie';cookie.write_text('test:test')
        reader=ChainReader('http://127.0.0.1:1234',cookie,'unused')
        calls=[]
        # Exercise the actual _call argument validation and JSON transport path;
        # only the network response is mocked, not ChainReader.call/_call.
        def transport(request, **kwargs):
            body=json.loads(request.data);method=body['method'];args=body['params']
            calls.append((method,args))
            result=self.core.call(method,*args)
            if method=='getblock' and result['height']==326715:
                # More than one bounded batch before the actual child.
                result={**result,'tx':[self.core.coinbase(326715)['txid']]*130+result['tx'][1:]}
            return io.BytesIO(json.dumps({'jsonrpc':'2.0','id':1,'result':result,'error':None},default=str).encode())
        phase.core=reader
        chain={'height':326800}
        with patch('urllib.request.urlopen',side_effect=transport):
            first=_fee_child(phase,{'outpoint':FIRST_PAYOUT},chain)
            self.assertIsNone(first)
            cursor=json.loads(phase.db.execute('SELECT value FROM meta WHERE key=?',('s03_repair_child:'+FIRST,)).fetchone()[0])
            self.assertEqual(cursor['offset'],128)
            self.assertEqual(cursor['height'],326715)
            child=_fee_child(phase,{'outpoint':FIRST_PAYOUT},chain)
            self.assertEqual(child['child_txid'],CHILD1)
            self.assertEqual(child['child_miner_fee_sat'],1000)
        self.assertTrue(all(args[1]==1 for method,args in calls if method=='getblock'))
        self.assertEqual(sum(method=='getrawtransaction' and args[0].startswith('f') for method,args in calls),130)
        with self.assertRaisesRegex(ValueError,'transaction-id inventory'):
            reader.call('getblock',self.core.blockhash(326715),2)

    def test_fee_child_rewinds_reorg_and_legacy_cursor_without_native_actions(self):
        from simulator.signet_repair import _fee_child
        self.prepare();self.stage();phase=self.open_new()
        key='s03_repair_child:'+FIRST
        phase.db.execute('INSERT INTO meta VALUES (?,?)',(key,canonical({'height':326799,'blockhash':'0'*64})))
        chain={'height':326800}
        with patch('simulator.signet.subprocess.run') as native:
            self.assertEqual(_fee_child(phase,{'outpoint':FIRST_PAYOUT},chain)['child_txid'],CHILD1)
            original=self.core.blockhash
            self.core.blockhash=lambda height: 'a'*64 if height==326715 else original(height)
            for txid in [FIRST,CHILD1]:self.core.transactions[txid]['blockhash']='a'*64
            # Core fixture maps the synthetic new hash back to its actual height.
            original_call=self.core.call
            def call(method,*args):
                if method=='getblock' and args[0]=='a'*64:
                    return {'hash':'a'*64,'height':326715,'tx':[FIRST,CHILD1]}
                return original_call(method,*args)
            self.core.call=call
            child=_fee_child(phase,{'outpoint':FIRST_PAYOUT},chain)
            self.assertEqual(child['child_txid'],CHILD1)
            cursor=json.loads(phase.db.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone()[0])
            self.assertEqual(cursor['block_hash'],'a'*64)
        native.assert_not_called()

    def test_changed_runtime_or_missing_stop_prevents_all_recovery_actions(self):
        self.prepare();self.stage();phase=self.open_new();self.stop.unlink()
        with patch('simulator.signet.subprocess.run') as native:
            with self.assertRaisesRegex(ValueError,'STOP'):advance(phase)
        native.assert_not_called();self.stop.touch()
        from pathlib import Path
        Path(self.runtime_pins['binary_directory'],'watchmand').write_bytes(b'changed')
        with patch('simulator.signet.subprocess.run') as native:
            with self.assertRaisesRegex(ValueError,'runtime executable changed'):advance(phase)
        native.assert_not_called()


if __name__=='__main__':unittest.main()
