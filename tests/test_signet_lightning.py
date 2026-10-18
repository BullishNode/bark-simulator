"""Native-receive controller fault tests; no live Signet/Lightning credit."""
import hashlib
import io
import json
import os
import sqlite3
import struct
import subprocess
import time
import unittest
from unittest.mock import patch

from simulator.model import canonical
from simulator.signet import Campaign
from simulator.signet_lightning import (PROFILE, PRODUCTION_PROFILE, stage, issue_invoice, pay_invoice,
    validate_invoice, public_vtxo, _once, _private_call, _attempt, freeze_claim,
    observe_receive, advance_recovery, signed_public_coin, _loopback_open, _NoRedirect)
from tests import test_signet, test_signet_phase, test_signet_s02


HASH=hashlib.sha256(bytes.fromhex('12'*32)).hexdigest()
GRANT='1'*64+':0'
CLAIM='2'*64+':0'
PUB='02'+'3'*64


class ReceiveTests(unittest.TestCase):
    setUp=test_signet.SignetTests.setUp
    tearDown=test_signet.SignetTests.tearDown

    def prepare(self, profile=PROFILE, *, config_profile=None, bind_pins=True, pool_targets=True):
        self.invoice_created_at = int(time.time())
        test_signet_phase.PhaseTests.fixture(self)
        self.campaign.close()
        config_path=self.root/'service-config/captaind.toml'
        config_path.write_text('''vtxo_lifetime=32
vtxo_exit_delta=12
htlc_expiry_delta=6
[vtxopool]
vtxo_lifetime=32
vtxo_pre_expiry=12
vtxo_targets=["10000sat:1"]
[fees.lightning_receive]
base_fee_sat=100
ppm=2000
''')
        actual=profile if config_profile is None else config_profile
        if profile==PRODUCTION_PROFILE:
            config_path.write_text('''network="signet"
vtxo_lifetime={vtxo_lifetime}
vtxo_exit_delta={vtxo_exit_delta}
htlc_expiry_delta={htlc_expiry_delta}
htlc_send_expiry_delta=258
max_htlc_expiry_delta=288
required_board_confirmations=3
[postgres]
name="fresh_signet_native_ln"
[vtxopool]
vtxo_lifetime={pool_lifetime}
vtxo_pre_expiry={pool_pre_expiry}
vtxo_targets={targets}
[fees.lightning_receive]
base_fee_sat=100
ppm=2000
'''.format(**actual, targets='["10000sat:1"]' if pool_targets else '[]'))
        self.runtime_pins['config_hashes']['captaind']=hashlib.sha256(config_path.read_bytes()).hexdigest()
        self.new_config['product_config_sha256']=hashlib.sha256(canonical(self.runtime_pins['config_hashes']).encode()).hexdigest()
        self.campaign=Campaign(self.new_directory,self.new_config)
        self.campaign.core=test_signet_s02.LifecycleCore()
        self.registration={'network':'signet','payout_address':'tb1qpayout','record':{'spk':test_signet_s02.SCRIPT}}
        self.source=self.root/'original-phrase';self.source.write_text('abandon '*11+'about');self.source.chmod(0o600)
        self.token=self.root/'auth_token';self.token.write_text('private-fixture-bearer');self.token.chmod(0o600)
        self.admission=self.root/'coordinator-admission.json'
        admission={'network':'signet','server_pubkey':PUB}
        if profile==PRODUCTION_PROFILE and bind_pins:
            admission['runtime_pins_sha256']=hashlib.sha256(canonical(self.runtime_pins).encode()).hexdigest()
        self.admission.write_text(canonical(admission))
        self.spec={'profile':profile,'amount_sat':5000,'max_payment_fee_msat':1000,
            'provider_url':'http://127.0.0.1:3000','provider_token_file':str(self.token),
            'cln_binary':str(self.root/'cln'),'cln_binary_sha256':hashlib.sha256(b'cln fixture').hexdigest(),
            'cln_directory':str(self.root/'payer'),'payer_pubkey':'03'+'4'*64,'invoice_payee':PUB,
            'recipient_address':'tark1recipient','recipient_registration_sha256':hashlib.sha256(canonical(self.registration).encode()).hexdigest(),
            'birthday_height':100,'recovery_destination':'tb1qrecovered',
            'admission':str(self.admission),'admission_sha256':hashlib.sha256(self.admission.read_bytes()).hexdigest(),
            'database':'fresh_signet_native_ln'}
        (self.root/'cln').write_bytes(b'cln fixture')
        return stage(self.campaign,self.spec,self.runtime_pins,self.registration,self.source)

    def decoded(self):
        return {'type':'bolt11 invoice','valid':True,'currency':'tbs','amount_msat':5000000,
                'payee':PUB,'payment_hash':HASH,'created_at':self.invoice_created_at,'expiry':3600,
                'min_final_cltv_expiry':256 if self.spec['profile']==PRODUCTION_PROFILE else 56,
                'payment_secret':'never public'}

    def cln(self,campaign,spec,intent,kind,*args):
        if args[0]=='getinfo':return {'id':self.spec['payer_pubkey'],'network':'signet'}
        if args[0]=='decode':return self.decoded()
        if args[0]=='listpays':return {'pays':[]}
        if args[0]=='xpay':return {'amount_msat':5000000,'amount_sent_msat':5000123,'payment_preimage':'12'*32}
        raise AssertionError(args)

    def invoice(self):
        with patch('simulator.signet_lightning._cln',side_effect=self.cln), \
             patch('simulator.signet_lightning._rest',return_value={'invoice':'lntbs50-fixture'}):
            return issue_invoice(self.campaign)

    def test_stage_retains_only_original_seed_and_fences_recipient(self):
        with patch('simulator.signet_lightning.subprocess.run') as native:self.prepare()
        native.assert_not_called()
        self.assertFalse(self.campaign.actor_path('absent').exists())
        from simulator.signet_s02 import recovery_source
        self.assertEqual(recovery_source(self.campaign,'absent').read_bytes(),self.source.read_bytes())
        with self.assertRaisesRegex(ValueError,'absent actor'):
            self.campaign.execute('no-open','absent','vtxos',{})

    def test_production_stage_binds_current_pins_without_opening_absent_recipient(self):
        with patch('simulator.signet_lightning.subprocess.run') as native:
            result=self.prepare(PRODUCTION_PROFILE)
        native.assert_not_called()
        self.assertEqual(result['stage'],'STAGED_NO_INVOICE')
        self.assertFalse(self.campaign.actor_path('absent').exists())
        from simulator.signet_s02 import recovery_source
        self.assertEqual(recovery_source(self.campaign,'absent').read_bytes(),self.source.read_bytes())
        with self.assertRaisesRegex(ValueError,'new empty|already staged'):
            stage(self.campaign,self.spec,self.runtime_pins,self.registration,self.source)

    def test_production_requires_admission_bound_to_exact_runtime_manifest_sources_and_configs(self):
        with patch('simulator.signet_lightning.subprocess.run') as native, \
             self.assertRaisesRegex(ValueError,'exact paired runtime pins'):
            self.prepare(PRODUCTION_PROFILE,bind_pins=False)
        native.assert_not_called()
        self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM actor').fetchone()[0],0)

    def test_production_cannot_substitute_backend_source_inside_retained_runtime_pins(self):
        self.prepare(PRODUCTION_PROFILE)
        pins=json.loads(self.campaign.db.execute("SELECT value FROM meta WHERE key='phase_runtime_pins'").fetchone()[0])
        pins['elf_source']['captaind']='e'*40
        self.campaign.db.execute("UPDATE meta SET value=? WHERE key='phase_runtime_pins'",(canonical(pins),))
        with patch('simulator.signet_lightning._cln') as payer, \
             self.assertRaisesRegex(ValueError,'exact paired runtime pins'):
            issue_invoice(self.campaign)
        payer.assert_not_called()
        self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM action').fetchone()[0],0)

    def test_production_rejects_coherently_pinned_short_pool_geometry(self):
        with self.assertRaisesRegex(ValueError,'configuration differs'):
            self.prepare(PRODUCTION_PROFILE,config_profile=PROFILE)
        self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM actor').fetchone()[0],0)

    def test_production_requires_real_nonempty_pool_without_reconfiguring_it(self):
        with self.assertRaisesRegex(ValueError,'configuration differs'):
            self.prepare(PRODUCTION_PROFILE,pool_targets=False)
        self.assertIn('vtxo_targets=[]',(self.root/'service-config/captaind.toml').read_text())
        self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM actor').fetchone()[0],0)

    def test_invoice_checks_exact_amount_network_signature_payee_and_expiry(self):
        self.prepare();decoded=self.decoded()
        self.assertEqual(validate_invoice(decoded,self.spec,int(time.time()))['payment_hash'],HASH)
        for key,value in [('valid',False),('currency','tb'),('amount_msat',5000001),('payee','03'+'5'*64),('created_at',int(time.time())-7200)]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                validate_invoice({**decoded,key:value},self.spec,int(time.time()))

    def test_effect_is_durable_before_dispatch_and_existing_unknown_never_retries(self):
        self.prepare()
        def lost_reply():
            db=sqlite3.connect(self.campaign.root/'signet.sqlite')
            try:self.assertEqual(db.execute("SELECT state FROM action WHERE id='test-once'").fetchone()[0],'dispatched')
            finally:db.close()
            raise subprocess.TimeoutExpired('effect',1)
        with self.assertRaises(subprocess.TimeoutExpired):
            _once(self.campaign,'test-once','ln-payer','native_bolt11_xpay',{'payment_hash':HASH},lost_reply)
        with self.assertRaisesRegex(ValueError,'reconciliation'),patch('simulator.signet_lightning.subprocess.run') as replay:
            _once(self.campaign,'test-once','ln-payer','native_bolt11_xpay',{'payment_hash':HASH},lambda:replay())
        replay.assert_not_called()
        with self.assertRaisesRegex(ValueError,'immutable'):
            _once(self.campaign,'test-once','ln-payer','native_bolt11_xpay',{'payment_hash':'f'*64},lost_reply)

    def test_original_invoice_and_payment_are_once_and_preimage_stays_private(self):
        self.prepare();self.invoice()
        with patch('simulator.signet_lightning._rest') as duplicate:
            issue_invoice(self.campaign)
        duplicate.assert_not_called()
        with patch('simulator.signet_lightning._cln',side_effect=self.cln) as calls:
            paid=pay_invoice(self.campaign);again=pay_invoice(self.campaign)
        self.assertEqual(paid,again)
        self.assertEqual(sum(call.args[4]=='xpay' for call in calls.call_args_list),1)
        self.assertEqual(paid['routing_fee_msat'],123)
        replies=' '.join(r[0] for r in self.campaign.db.execute('SELECT reply FROM action'))
        self.assertNotIn('12'*32,replies);self.assertNotIn('payment_preimage',replies)

    def test_production_keeps_original_invoice_payment_and_absent_recipient_lineage(self):
        self.prepare(PRODUCTION_PROFILE);self.invoice()
        with patch('simulator.signet_lightning._rest') as duplicate:
            issue_invoice(self.campaign)
        duplicate.assert_not_called()
        with patch('simulator.signet_lightning._cln',side_effect=self.cln) as calls:
            pay_invoice(self.campaign);pay_invoice(self.campaign)
        self.assertEqual(sum(call.args[4]=='xpay' for call in calls.call_args_list),1)
        state={'payment_hash':HASH,'amount_sat':5000,'state':'settled','htlc_vtxo_ids':[]}
        history=[{'metadata':{'payment_hash':HASH,'htlc_vtxos':[GRANT],'payment_preimage':'12'*32}}]
        grant={'coin':{'id':GRANT,'policy_type':'server-htlc-receive-v1','expiry_height':632},
               'serialized_sha256':'8'*64}
        terms=[{'grant_id':GRANT,'payment_hash':HASH,'direction':'outgoing','htlc_expiry':414}]
        with patch('simulator.signet_lightning._rest',side_effect=[state,history]), \
             patch('simulator.signet_lightning.signed_public_coin',return_value=grant), \
             patch('simulator.signet_lightning._private_call',return_value=terms):
            observation=observe_receive(self.campaign)
        self.assertEqual(observation['grant_signed_proofs'][0]['tree_expiry'],632)
        claim={'coin':{'id':CLAIM,'amount_sat':4890,'policy_type':'pubkey',
                      'chain_anchor':test_signet_s02.ANCHOR+':0','expiry_height':632},
               'path_outpoints':[test_signet_s02.ANCHOR+':0',GRANT,CLAIM]}
        with patch('simulator.signet_lightning.signed_public_coin',return_value=claim) as proof:
            frozen=freeze_claim(self.campaign,[CLAIM])
        self.assertTrue(proof.call_args.kwargs['recipient'])
        self.assertEqual(frozen['coins'][0]['amount_sat'],4890)
        self.assertEqual(frozen['coins'][0]['expiry_height'],632)
        self.assertFalse(self.campaign.actor_path('absent').exists())
        self.assertNotIn('12'*32,canonical(frozen))

    def test_production_lost_payment_reply_retains_hold_and_never_replays(self):
        self.prepare(PRODUCTION_PROFILE);self.invoice()
        def lost(*args):
            if args[4]=='xpay':raise subprocess.TimeoutExpired('xpay',1)
            return self.cln(*args)
        with patch('simulator.signet_lightning._cln',side_effect=lost),self.assertRaises(subprocess.TimeoutExpired):
            pay_invoice(self.campaign)
        with patch('simulator.signet_lightning._cln') as replay, \
             self.assertRaisesRegex(ValueError,'reconciliation'):
            pay_invoice(self.campaign)
        replay.assert_not_called()
        with patch('simulator.signet_lightning._native') as native, \
             self.assertRaisesRegex(ValueError,'reconciliation'):
            advance_recovery(self.campaign)
        native.assert_not_called()

    def test_existing_payer_hash_or_wrong_returned_preimage_holds_without_second_payment(self):
        for mode in ['existing','wrong-preimage']:
            with self.subTest(mode=mode):
                if mode=='existing':self.prepare();self.invoice()
                else:
                    # Same issued invoice, fresh payment journal for isolated
                    # fault injection only; no live action is being deleted.
                    self.campaign.db.execute("DELETE FROM action WHERE id='native-ln-payment'")
                    self.campaign.db.execute("DELETE FROM action_context WHERE intent='native-ln-payment'")
                def cln(*args):
                    if args[4]=='listpays' and mode=='existing':return {'pays':[{'payment_hash':HASH,'status':'pending'}]}
                    reply=self.cln(*args)
                    return {**reply,'payment_preimage':'99'*32} if args[4]=='xpay' else reply
                with patch('simulator.signet_lightning._cln',side_effect=cln),self.assertRaises(ValueError):pay_invoice(self.campaign)
                self.assertEqual(self.campaign.db.execute("SELECT state FROM action WHERE id='native-ln-payment'").fetchone()[0],'unknown')

    def test_subprocess_notifications_disabled_and_timeout_retained(self):
        self.prepare()
        with patch('simulator.signet_lightning.subprocess.run',return_value=subprocess.CompletedProcess([],0,b'{}',b'')) as native:
            from simulator.signet_lightning import _cln
            _cln(self.campaign,self.spec,'machine','decode','decode','invoice')
        self.assertIn('--notifications=none',native.call_args.args[0]);self.assertIn('--json',native.call_args.args[0])
        with patch('simulator.signet_lightning.subprocess.run',side_effect=subprocess.TimeoutExpired('xpay',1,output=b'partial-secret',stderr=b'diagnostic')):
            with self.assertRaises(subprocess.TimeoutExpired):_private_call(self.campaign,'timed','xpay',['fixed'])
        artifacts=self.campaign.db.execute("SELECT relative_path FROM native_artifact WHERE intent='timed'").fetchall()
        self.assertEqual(len(artifacts),2)
        self.assertTrue(all((self.campaign.root/r[0]).stat().st_mode&0o777==0o600 for r in artifacts))
        self.assertEqual([_attempt(self.campaign,'failed-read') for _ in range(2)],[0,1])

    def test_settled_receive_uses_durable_grant_history_without_secret_projection(self):
        self.prepare();self.invoice()
        state={'payment_hash':HASH,'amount_sat':5000,'state':'settled','htlc_vtxo_ids':[],
               'payment_preimage':'12'*32,'invoice':'private-original','settled_at':'2026-10-17T17:00:00Z'}
        history=[{'metadata':{'payment_hash':HASH,'htlc_vtxos':[GRANT],'payment_preimage':'12'*32}}]
        proof={'coin':{'id':GRANT,'policy_type':'server-htlc-receive-v1','expiry_height':232},'serialized_sha256':'8'*64}
        deadline=[{'grant_id':GRANT,'payment_hash':HASH,'direction':'outgoing','htlc_expiry':248}]
        with patch('simulator.signet_lightning._rest',side_effect=[state,history]), \
             patch('simulator.signet_lightning.signed_public_coin',return_value=proof), \
             patch('simulator.signet_lightning._private_call',return_value=deadline) as query:
            result=observe_receive(self.campaign)
        self.assertEqual(result['htlc_vtxo_ids'],[GRANT]);self.assertGreater(result['grant_terms'][0]['htlc_expiry'],232)
        sql=query.call_args.args[3][-1]
        self.assertIn('BEGIN READ ONLY',sql);self.assertNotIn('preimage',sql)
        self.assertNotIn('12'*32,canonical(result));self.assertNotIn('payment_preimage',canonical(result))

    def test_claim_requires_exact_net_recipient_and_real_grant_lineage(self):
        self.prepare();self.invoice()
        with patch('simulator.signet_lightning._cln',side_effect=self.cln):pay_invoice(self.campaign)
        self.campaign.db.execute('INSERT INTO result VALUES (?,?,?)',('grants',time.time(),canonical({'kind':'native_ln_receive_state','htlc_vtxo_ids':[GRANT]})))
        proof={'coin':{'id':CLAIM,'amount_sat':4890,'policy_type':'pubkey','chain_anchor':test_signet_s02.ANCHOR+':0','expiry_height':232},
               'path_outpoints':[test_signet_s02.ANCHOR+':0',GRANT,CLAIM]}
        for bad in [{**proof,'path_outpoints':[test_signet_s02.ANCHOR+':0',CLAIM]},
                    {**proof,'coin':{**proof['coin'],'amount_sat':5000}}]:
            with patch('simulator.signet_lightning.signed_public_coin',return_value=bad),self.assertRaises(ValueError):
                freeze_claim(self.campaign,[CLAIM])
        with patch('simulator.signet_lightning.signed_public_coin',return_value=proof):frozen=freeze_claim(self.campaign,[CLAIM])
        self.assertEqual(frozen['coins'][0]['amount_sat'],4890)
        self.assertNotIn('state',frozen['coins'][0])
        self.assertFalse(self.campaign.actor_path('absent').exists())

    def test_no_recovery_wallet_open_until_exact_payout_and_fee_child_have_six(self):
        self.prepare()
        frozen={'coins':[{'id':CLAIM,'amount_sat':4890}]}
        self.campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)",(canonical(frozen),))
        payout={'kind':'S02_payout_observation','payout_check':'PASS','coin_ids':[CLAIM],'outpoint':'a'*64+':0','confirmations':6}
        self.campaign.db.execute('INSERT INTO result VALUES (?,?,?)',('payout',time.time(),canonical(payout)))
        with patch('simulator.signet_lightning.discover_payouts'), \
             patch('simulator.signet_lightning.observe_payout',return_value=payout), \
             patch('simulator.signet_lightning._fee_child',return_value={'confirmations':5}), \
             patch('simulator.signet_lightning._native') as native:
            result=advance_recovery(self.campaign)
        native.assert_not_called();self.assertEqual(result['case_verdict'],'INCOMPLETE')

    def test_production_recovery_resumes_after_chain_movement_and_requires_drain_six(self):
        from simulator.signet_s02 import observe_payout
        self.prepare(PRODUCTION_PROFILE)
        coin={'id':CLAIM,'amount_sat':4890,'chain_anchor':test_signet_s02.ANCHOR+':0',
              'expiry_height':180}
        frozen={'coins':[coin],'registration':self.registration,
                'signature_proofs':[{'coin_id':CLAIM,'status':'PASS',
                    'path_outpoints':[coin['chain_anchor'],GRANT,CLAIM]}]}
        self.campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)",(canonical(frozen),))
        transactions=self.campaign.core.transactions
        transactions[test_signet_s02.PAYOUT]['vout'][0]=test_signet_s02.output(3890)
        transactions[test_signet_s02.PAYOUT]['vout'][1]=test_signet_s02.output(16110,'0014'+'3'*40,1)
        transactions[test_signet_s02.RECOVERY]['vout'][0]=test_signet_s02.output(12890,test_signet_s02.DESTINATION)
        observation=observe_payout(self.campaign,'absent',test_signet_s02.PAYOUT,0,[CLAIM])
        self.assertEqual(observation['payout_check'],'PASS')
        def native(argv,**kwargs):
            self.assertNotIn(str(self.campaign.actor_path('absent')),argv)
            if 'create' in argv:
                self.assertIn('--mnemonic-file',argv)
                self.assertNotIn(str(self.source),argv)
                return subprocess.CompletedProcess(argv,0)
            if argv[-2:]==['onchain','utxos']:
                reply=[{'outpoint':test_signet_s02.PAYOUT+':0','amount_sat':3890,'confirmation_height':190}]
            else:
                self.assertIn('drain',argv)
                reply={'txid':test_signet_s02.RECOVERY}
            kwargs['stdout'].write(json.dumps(reply).encode())
            return subprocess.CompletedProcess(argv,0)
        with patch('simulator.signet_lightning.discover_payouts'), \
             patch('simulator.signet_lightning._fee_child',return_value={'confirmations':5}) as fee, \
             patch('simulator.signet.subprocess.run',side_effect=native) as process:
            self.assertEqual(advance_recovery(self.campaign)['stage'],'WAITING_FOR_SIX_CONFIRMED_PARENTS_AND_CHILDREN')
            process.assert_not_called()
            def next_block(*args):
                self.campaign.core.info['blocks']+=1
                for transaction in transactions.values():transaction['confirmations']+=1
                return {'confirmations':6}
            fee.side_effect=next_block
            self.assertEqual(advance_recovery(self.campaign)['stage'],'WAITING_FOR_STABLE_CHAIN_VIEW')
            process.assert_not_called()
            fee.side_effect=None;fee.return_value={'confirmations':6}
            waiting=advance_recovery(self.campaign)
            self.assertEqual(waiting['stage'],'WAITING_FOR_SIX_CONFIRMED_RECOVERY')
            self.assertEqual(waiting['case_verdict'],'INCOMPLETE')
            self.assertEqual(waiting['confirmations'],2)
            calls=process.call_count
            increment=6-transactions[test_signet_s02.RECOVERY]['confirmations']
            self.campaign.core.info['blocks']+=increment
            for transaction in transactions.values():transaction['confirmations']+=increment
            result=advance_recovery(self.campaign)
            self.assertEqual(result['case_verdict'],'PASS')
            self.assertEqual(result['recovery'][0]['recovered_payout_sat'],3890)
            self.assertEqual(process.call_count,calls)
            self.assertEqual(advance_recovery(self.campaign)['case_verdict'],'PASS')
            self.assertEqual(process.call_count,calls)
        for operation in ['restore','onchain_drain']:
            self.assertEqual(self.campaign.db.execute('SELECT count(*) FROM action WHERE operation=?',(operation,)).fetchone()[0],1)
        restore=json.loads(self.campaign.db.execute("SELECT arguments FROM action WHERE id='native-ln-seed-restore'").fetchone()[0])
        self.assertEqual(restore['wallet_profile'],{'vtxo_refresh_expiry_threshold':144,'vtxo_exit_margin':12})

    def test_actual_native_proof_contract_has_no_wallet_open_and_requires_payee(self):
        self.prepare()
        coin={'id':CLAIM,'amount_sat':4890,'server_pubkey':PUB,'policy_type':'pubkey',
              'chain_anchor':test_signet_s02.ANCHOR+':0','user_pubkey':'03'+'6'*64,'expiry_height':232}
        proof={'verified':True,'address_verified':True,'anchor_txid':test_signet_s02.ANCHOR,
               'vtxo':coin,'path_outpoints':[coin['chain_anchor'],GRANT,CLAIM]}
        actual=self.campaign.core.call
        def core(method,*args):
            if method=='getrawtransaction' and args[1] is False:return 'deadbeef'
            return actual(method,*args)
        with patch.object(self.campaign.core,'call',side_effect=core), \
             patch('simulator.signet_lightning.public_vtxo',return_value='abcd'), \
             patch('simulator.signet_lightning._private_call',side_effect=[coin,proof]) as native:
            signed_public_coin(self.campaign,CLAIM,recipient=True)
        for call in native.call_args_list:self.assertNotIn('--datadir',call.args[3])
        self.assertEqual(native.call_args.args[3][-2:],['--address',self.spec['recipient_address']])
        self.assertFalse(self.campaign.actor_path('absent').exists())
        with patch.object(self.campaign.core,'call',side_effect=core), \
             patch('simulator.signet_lightning.public_vtxo',return_value='abcd'), \
             patch('simulator.signet_lightning._private_call',side_effect=[coin,{**proof,'address_verified':False}]),self.assertRaises(ValueError):
            signed_public_coin(self.campaign,CLAIM,recipient=True)


class PublicVtxoTests(unittest.TestCase):
    def response(self,body,status=b'grpc-status: 0\r\n'):
        raw=b'\0'+struct.pack('>I',len(body))+body+b'\x80'+struct.pack('>I',len(status))+status
        result=io.BytesIO(raw);result.status=200;return result

    def test_exact_proto_txid_byteorder_and_readonly_unary_response(self):
        txid='0123456789abcdef'*4;coin_id=txid+':7'
        with patch('simulator.signet_lightning._loopback_open',return_value=self.response(b'\x0a\x02\xab\xcd')) as rpc:
            self.assertEqual(public_vtxo('http://127.0.0.1:3565',coin_id),'abcd')
        request=rpc.call_args.args[0]
        self.assertTrue(request.full_url.endswith('/bark_server.ArkService/GetVtxo'))
        self.assertEqual(request.data[5:],b'\x0a\x24'+bytes.fromhex(txid)[::-1]+struct.pack('<I',7))

    def test_failed_status_truncation_duplicate_fields_and_u32_overflow_rejected(self):
        for body,status in [(b'\x0a\x02\xab',b'grpc-status: 0\r\n'),
                            (b'\x0a\x01\xab\x0a\x01\xcd',b'grpc-status: 0\r\n'),
                            (b'\x0a\x01\xab',b'grpc-status: 5\r\n')]:
            with self.subTest(body=body,status=status),patch('simulator.signet_lightning._loopback_open',return_value=self.response(body,status)),self.assertRaises(ValueError):
                public_vtxo('http://127.0.0.1:3565',GRANT)
        with self.assertRaises(ValueError):public_vtxo('http://127.0.0.1:3565','1'*64+':4294967296')

    def test_loopback_opener_has_no_proxy_and_refuses_redirects(self):
        import urllib.request
        request=urllib.request.Request('http://127.0.0.1:3000/api/v1/lightning/receives',
                                       headers={'Authorization':'Bearer private-fixture'})
        with patch.dict(os.environ,{'HTTP_PROXY':'http://untrusted.invalid:8080','HTTPS_PROXY':'http://untrusted.invalid:8080'}), \
             patch('simulator.signet_lightning.urllib.request.build_opener') as factory:
            _loopback_open(request,60)
        handlers=factory.call_args.args
        self.assertIsInstance(handlers[0],urllib.request.ProxyHandler)
        self.assertEqual(handlers[0].proxies,{})
        self.assertIsInstance(handlers[1],_NoRedirect)
        with self.assertRaisesRegex(ValueError,'must not redirect'):
            handlers[1].redirect_request(request,None,302,'redirect',{},'http://untrusted.invalid/')
