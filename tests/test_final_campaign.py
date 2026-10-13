"""Synthetic ledger regressions: fixtures never dispatch clients or earn live credit."""
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from simulator.campaign import CampaignClock, RampPlan, traffic_ready
from simulator.engine import initialize
from simulator.model import canonical
from simulator.report import generate
from simulator.store import Store

PINS = {'product_commit':'1'*40, 'sdk_commit':'2'*40, 'driver_sha256':'3'*64,
        'configuration_sha256':'4'*64, 'schema_sha256':'5'*64}

class FinalCampaignRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name), 'synthetic', 1000000)
        initialize(self.store)
        self.store.db.execute("INSERT INTO meta VALUES ('real_campaign_started','100')")
        self.declaration = {'id':'final-fixture', 'pins':PINS, 'started_at':100,
            'windows_seconds':{'ark':600, 'internal_lightning':600, 'external_lightning':600},
            'minimum_observations':{'ark':1, 'internal_lightning':1, 'external_lightning':1}}
        self.store.db.execute("INSERT INTO meta VALUES ('final_financial_epoch',?)", (canonical(self.declaration),))

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def transfer(self, identity, operation, data, at, args=None):
        self.store.queue(identity, 'actor-01', 'H07', operation, args or {}, 0)
        self.store.db.execute('UPDATE action SET state=?,result=?,updated_at=? WHERE id=?',
            ('completed', canonical({'status':'ok', 'data':data}), at, identity))

    def old_dual_rail(self):
        self.transfer('ark', 'send_arkoor', {'submitted':'send_arkoor'}, 101)
        self.store.event('ark_transfer_verified', {'action_id':'ark', 'verified_at':101})
        self.transfer('internal', 'pay_invoice', {'paid':True, 'payment_status_verified':True,
            'payment_state':'succeeded'}, 102, {'recipient_actor':'actor-02'})

    def test_final_clock_cannot_use_old_dual_rail_as_complete_three_rail_evidence(self):
        self.old_dual_rail()
        self.assertFalse(traffic_ready(self.store, 103),
            'internal Lightning plus Ark does not qualify external Lightning or final financial pins')

    def test_final_clock_does_not_credit_a_foreign_financial_epoch(self):
        self.old_dual_rail()
        self.store.event('final_traffic_verified', {'epoch_id':'previous-financial-build',
            'pins':PINS, 'rail':'external_lightning', 'action_id':'internal', 'verified_at':102})
        self.assertFalse(traffic_ready(self.store, 103), 'an older financial build cannot earn new final time')

    def test_creating_ramp_actor_rows_does_not_qualify_the_actual_funded_ramp(self):
        # Existing expansion is useful preparation, but has no funding or boards.
        clock_now = [0]
        clock = CampaignClock(self.store, RampPlan(), clock=lambda:clock_now[0])
        clock.tick(healthy=True, real_campaign_started=True)
        for _ in range(90):
            clock_now[0] += 120
            clock.tick(healthy=True, real_campaign_started=True)
        report = generate(self.store)
        self.assertFalse(report['campaign']['ramp_applied'],
            'preparing actor rows cannot report a final-build qualified funded ramp')

class FinalEpochEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name), 'synthetic', 1000000)
        initialize(self.store)
        self.store.db.execute("INSERT INTO meta VALUES ('paused','fixture-preflight')")
        self.declaration = {'id':'final-fixture', 'pins':PINS, 'started_at':100,
            'windows_seconds':{'ark':600, 'internal_lightning':600, 'external_lightning':600},
            'minimum_observations':{'ark':1, 'internal_lightning':1, 'external_lightning':1}}
        from simulator.final_campaign import declare_epoch
        declare_epoch(self.store,self.declaration)
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")

    def tearDown(self):
        self.store.close();self.temp.cleanup()

    def action(self, identity, operation, actor='actor-01', at=101, data=None, args=None):
        self.store.queue(identity,actor,'H07',operation,args or {},0)
        self.store.db.execute('UPDATE action SET created_at=?,state=?,result=?,updated_at=? WHERE id=?',
            (at,'completed',canonical({'data':data or {}}),at,identity))

    def event(self, kind, payload):
        at=payload.get('verified_at')
        if at is None:
            row=self.store.db.execute('SELECT updated_at FROM action WHERE id=?',(payload.get('action_id'),)).fetchone()
            at=row[0] if row else 104
        with patch('simulator.store.time.time',return_value=float(at)):
            self.store.event(kind,payload)
        return self.store.db.execute('SELECT MAX(sequence) FROM event').fetchone()[0]

    def credit(self, rail, action, sequence):
        from simulator.final_campaign import record_traffic
        return record_traffic(self.store,rail,action,sequence,PINS)

    def ark(self, at=101):
        self.action('ark','send_arkoor',at=at)
        return self.credit('ark','ark',self.event('ark_transfer_verified',
            {'action_id':'ark','recipient_actor':'actor-02','verified_at':at}))

    def internal(self, at=102):
        payment='a'*64
        self.action('invoice','invoice','actor-02',at,data={'payment_hash':payment})
        self.action('internal-send','pay_invoice',at=at,
            data={'payment_hash':payment,'payment_status_verified':True,'payment_state':'succeeded'},
            args={'recipient_actor':'actor-02','recipient_invoice_action':'invoice'})
        self.action('claim','sync','actor-02',at)
        seq=self.event('client_fee_reconciled',{'action_id':'claim',
            'claims':[{'payment_hash':payment,'invoice_action_id':'invoice','output_coin_ids':['coin:0']}]})
        return self.credit('internal_lightning','claim',seq)

    def external(self, at=103):
        payment='b'*64
        self.action('external','pay_invoice',at=at,data={'payment_hash':payment})
        sequence=self.event('controlled_peer_payment_verified',{'action_id':'external','payment_hash':payment,
            'state':'succeeded','direction':'send','peer_pubkey':'02'+'6'*64,
            'peer_outcome_checked':True,'verified_at':at})
        return self.credit('external_lightning','external',sequence)

    def test_each_rail_and_exact_live_pins_required(self):
        from simulator.final_campaign import traffic_ready
        self.ark();self.internal()
        self.assertFalse(traffic_ready(self.store,104,PINS))
        self.external()
        self.assertTrue(traffic_ready(self.store,104,PINS))
        self.assertFalse(traffic_ready(self.store,104,{**PINS,'product_commit':'9'*40}))
        self.assertFalse(traffic_ready(self.store,104,None))
        self.assertFalse(traffic_ready(self.store,702,PINS))

    def test_reimporting_old_ark_proof_cannot_manufacture_fresh_traffic(self):
        from simulator.final_campaign import traffic_ready
        self.ark();self.internal();self.external()
        self.assertFalse(traffic_ready(self.store,1000,PINS))
        seq=self.store.db.execute("SELECT sequence FROM event WHERE kind='ark_transfer_verified'").fetchone()[0]
        self.assertFalse(self.credit('ark','ark',seq))
        self.assertFalse(traffic_ready(self.store,1000,PINS))
        self.assertEqual(3,self.store.db.execute('SELECT COUNT(*) FROM final_traffic').fetchone()[0])

    def test_pin_change_requires_new_namespace_preserves_counter(self):
        from simulator.final_campaign import declare_epoch
        self.store.db.execute("UPDATE meta SET value='120' WHERE key='qualified_campaign_active_seconds'")
        with self.assertRaisesRegex(ValueError,'immutable'):
            declare_epoch(self.store,{**self.declaration,'pins':{**PINS,'sdk_commit':'9'*40}})
        self.assertEqual('120',self.store.get_meta('qualified_campaign_active_seconds'))
        self.assertFalse(declare_epoch(self.store,self.declaration))
        self.store.verify_event_chain()

    def test_foreign_source_action_and_tampered_event_are_not_credited(self):
        self.action('ark','send_arkoor')
        seq=self.event('ark_transfer_verified',{'action_id':'other','verified_at':101})
        with self.assertRaisesRegex(ValueError,'action differs'):self.credit('ark','ark',seq)
        self.store.db.execute('UPDATE event SET payload=? WHERE sequence=?',
            (canonical({'action_id':'ark','verified_at':101}),seq))
        with self.assertRaisesRegex(ValueError,'frame changed'):self.credit('ark','ark',seq)
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM final_traffic').fetchone()[0])

    def test_pre_epoch_action_cannot_be_relabelled(self):
        self.action('ark','send_arkoor',at=99)
        seq=self.event('ark_transfer_verified',{'action_id':'ark','verified_at':101})
        with self.assertRaisesRegex(ValueError,'exploratory'):self.credit('ark','ark',seq)

    def test_internal_sender_status_is_not_receiver_claim_evidence(self):
        self.action('send','pay_invoice',data={'payment_hash':'a'*64})
        seq=self.event('lightning_payment_outcome',{'action_id':'send','state':'succeeded'})
        with self.assertRaisesRegex(ValueError,'receive claim'):self.credit('internal_lightning','send',seq)

    def test_external_success_requires_original_hash_and_peer_outcome(self):
        self.action('external','pay_invoice',data={'payment_hash':'a'*64})
        for changes in [{'payment_hash':'b'*64},{'peer_outcome_checked':False},{'state':'pending'}]:
            seq=self.event('controlled_peer_payment_verified',{'action_id':'external','payment_hash':'a'*64,
                'state':'succeeded','direction':'send','peer_pubkey':'02'+'6'*64,
                'peer_outcome_checked':True,'verified_at':101,**changes})
            with self.assertRaises(ValueError):self.credit('external_lightning','external',seq)
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM final_traffic').fetchone()[0])

    def test_declared_ramp_has_no_qualified_result_without_funding(self):
        from simulator.final_campaign import ramp_status,verify_ramp
        self.store.db.execute("INSERT INTO meta VALUES ('ramp_applied','true')")
        self.store.db.execute("UPDATE meta SET value='10800' WHERE key='qualified_campaign_active_seconds'")
        self.assertEqual('prepared',ramp_status(self.store)['state'])
        with self.assertRaisesRegex(ValueError,'funding has not confirmed'):
            verify_ramp(self.store,None,PINS)

    def test_final_clock_requires_live_financial_pins(self):
        self.ark();self.internal();self.external()
        now=[0];clock=CampaignClock(self.store,RampPlan(),clock=lambda:now[0])
        clock.tick(healthy=True,real_campaign_started=True,financial_pins=PINS)
        now[0]=120
        self.assertEqual(0,clock.tick(healthy=True,real_campaign_started=True))
        now[0]=240
        self.assertEqual(0,clock.tick(healthy=True,real_campaign_started=True,financial_pins=PINS))
        now[0]=360
        self.assertEqual(120,clock.tick(healthy=True,real_campaign_started=True,financial_pins=PINS))
        resumed=CampaignClock(self.store,RampPlan(),clock=lambda:now[0])
        now[0]+=86400
        self.assertEqual(120,resumed.tick(healthy=True,real_campaign_started=True,financial_pins=PINS))

class FinalRampEvidenceTests(unittest.TestCase):
    setUp=FinalEpochEvidenceTests.setUp
    tearDown=FinalEpochEvidenceTests.tearDown
    action=FinalEpochEvidenceTests.action
    def prepare(self):
        self.store.db.execute("INSERT INTO meta VALUES ('ramp_applied','true')")
        self.store.db.execute("UPDATE meta SET value='10800' WHERE key='qualified_campaign_active_seconds'")
        self.store.db.execute('CREATE TABLE funding_batch(id TEXT PRIMARY KEY,state TEXT,recipients TEXT,txid TEXT,raw_tx TEXT,fee_sat INTEGER,updated_at REAL)')
        recipients=[]
        for index in range(13,25):
            actor=f'actor-{index:02}'
            self.store.actor(actor,'fresh ramp client')
            recipients.append({'actor':actor,'address':f'fixture-address-{index}','amount_sat':8000})
            identity=f'board-{index}'
            self.action(identity,'board',actor,at=201)
            key=f'key-{index}';coin=f'coin-{index}:0'
            binding={'mailbox_pk':actor,'key_link_signature_valid':True,'record_signature_valid':True}
            proof={'id':coin,'user_pubkey':key,'amount_sat':5000,'binding':binding,
                   'signed_path_valid':True,'anchor_confirmations':1}
            self.store.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,actor,actor,canonical(proof)))
            self.store.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',
                (coin,key,5000,'fixture-hash','aa',canonical(proof)))
            self.store.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',(coin,identity,'Spendable',201))
        self.store.db.execute('INSERT INTO funding_batch VALUES (?,?,?,?,?,?,?)',
            ('ramp','confirmed',canonical(recipients),'a'*64,'fixture-raw',1000,200))
        # Real post-funding movement proof registration has separate tests. Here
        # checked registry fixtures isolate ramp accounting and chain verification.
        for rail in ('ark','internal_lightning'):
            self.store.db.execute('INSERT INTO final_traffic VALUES (?,?,?,?,?)',
                (900 if rail=='ark' else 901,rail,'board-13',202,canonical({'participants':['actor-13']})))
        return RampChain(recipients)

    def test_all_twelve_confirmed_funded_boards_and_real_activity_qualify_once(self):
        from simulator.final_campaign import verify_ramp,ramp_status
        chain=self.prepare()
        self.assertTrue(verify_ramp(self.store,chain,PINS))
        self.assertTrue(ramp_status(self.store)['qualified'])
        self.assertEqual(24,ramp_status(self.store)['total_clients'])
        previous=chain.calls
        self.assertFalse(verify_ramp(self.store,chain,PINS))
        self.assertEqual(previous,chain.calls,'idempotent verified ramp should not requery or refund')
        self.assertEqual(1,self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='final_ramp_verified'").fetchone()[0])
        self.store.verify_event_chain()

    def test_one_missing_board_or_unconfirmed_funding_cannot_qualify(self):
        from simulator.final_campaign import verify_ramp
        chain=self.prepare()
        self.store.db.execute("DELETE FROM coin_observation WHERE action_id='board-24'")
        with self.assertRaisesRegex(ValueError,'board evidence'):verify_ramp(self.store,chain,PINS)
        chain.confirmations=0
        with self.assertRaisesRegex(ValueError,'independently confirmed'):verify_ramp(self.store,chain,PINS)
        self.assertEqual(0,self.store.db.execute("SELECT COUNT(*) FROM event WHERE kind='final_ramp_verified'").fetchone()[0])

    def test_funding_amount_and_fee_are_independent_checks(self):
        from simulator.final_campaign import verify_ramp
        chain=self.prepare();chain.wrong_output=True
        with self.assertRaisesRegex(ValueError,'actual chain output'):verify_ramp(self.store,chain,PINS)
        chain.wrong_output=False;chain.fee=1001
        with self.assertRaisesRegex(ValueError,'exact fee'):verify_ramp(self.store,chain,PINS)

    def test_funded_actor_rows_without_real_ramped_traffic_do_not_qualify(self):
        from simulator.final_campaign import verify_ramp
        chain=self.prepare()
        self.store.db.execute('DELETE FROM final_traffic')
        with self.assertRaisesRegex(ValueError,'real post-funding'):verify_ramp(self.store,chain,PINS)

class RampChain:
    def __init__(self,recipients):
        self.recipients=recipients;self.calls=0;self.fee=1000;self.confirmations=1;self.wrong_output=False
    def identity(self):self.calls+=1
    def transaction(self,txid):
        self.calls+=1
        return {'txid':txid,'fee_sat':self.fee,'confirmations':self.confirmations,
            'outputs':[{'vout':i,'script':r['address'],'amount_sat':r['amount_sat']-(1 if self.wrong_output and i==0 else 0)}
                       for i,r in enumerate(self.recipients)]}
    def call(self,method,address):
        self.calls+=1
        if method!='validateaddress':raise AssertionError(method)
        return {'scriptPubKey':address}

class EpochTransitionTests(unittest.TestCase):
    setUp=FinalEpochEvidenceTests.setUp
    tearDown=FinalEpochEvidenceTests.tearDown

    def test_declaring_final_epoch_excludes_last_exploratory_interval(self):
        from simulator.final_campaign import declare_epoch
        # Fresh namespace initially has exploratory clock/evidence.
        self.store.db.execute('DELETE FROM final_traffic')
        self.store.db.execute("DELETE FROM event WHERE kind='final_financial_epoch_declared'")
        self.store.db.execute("DELETE FROM meta WHERE key IN ('final_financial_epoch','exploratory_active_seconds')")
        now=[0];clock=CampaignClock(self.store,RampPlan(),clock=lambda:now[0])
        clock.tick(healthy=True,real_campaign_started=True)
        now[0]=120
        self.assertEqual(120,clock.tick(healthy=True,real_campaign_started=True))
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declare-final')")
        declare_epoch(self.store,self.declaration)
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")
        self.assertEqual('120.0',self.store.get_meta('exploratory_active_seconds'))
        now[0]=240
        self.assertEqual(0,clock.tick(healthy=True,real_campaign_started=True,financial_pins=PINS))

    def test_private_unknown_funding_prevents_final_epoch(self):
        from simulator.final_campaign import declare_epoch
        self.store.db.execute("DELETE FROM event WHERE kind='final_financial_epoch_declared'")
        self.store.db.execute("DELETE FROM meta WHERE key IN ('final_financial_epoch','exploratory_active_seconds')")
        self.store.db.execute("INSERT INTO meta VALUES ('paused','declare-final')")
        self.store.db.execute('CREATE TABLE funding_batch(id TEXT PRIMARY KEY,state TEXT)')
        self.store.db.execute("INSERT INTO funding_batch VALUES ('original','outcome_unknown')")
        with self.assertRaisesRegex(ValueError,'funding_batch'):
            declare_epoch(self.store,self.declaration)
        self.assertIsNone(self.store.get_meta('final_financial_epoch'))

class FinalCollectorTests(unittest.TestCase):
    setUp=FinalEpochEvidenceTests.setUp
    tearDown=FinalEpochEvidenceTests.tearDown
    action=FinalEpochEvidenceTests.action
    event=FinalEpochEvidenceTests.event

    def test_pending_proof_does_not_starve_later_eligible_rail(self):
        from simulator.final_campaign import collect_traffic
        self.action('unresolved','sync',at=101)
        self.event('client_fee_reconciled',{'action_id':'unresolved','claims':[]})
        self.action('ark','send_arkoor',at=102)
        self.event('ark_transfer_verified',{'action_id':'ark','recipient_actor':'actor-02','verified_at':102})
        self.assertEqual(0,collect_traffic(self.store,PINS,limit=1))
        self.assertEqual(1,collect_traffic(self.store,PINS,limit=1))
        self.assertEqual(0,collect_traffic(self.store,PINS,limit=1))
        self.assertEqual(1,self.store.db.execute('SELECT COUNT(*) FROM final_traffic').fetchone()[0])
        self.assertEqual(0,self.store.db.execute("SELECT COUNT(*) FROM action WHERE state='dispatched'").fetchone()[0])

    def test_missing_runtime_pin_context_cannot_promote_proofs(self):
        from simulator.final_campaign import collect_traffic
        self.action('ark','send_arkoor',at=102)
        self.event('ark_transfer_verified',{'action_id':'ark','verified_at':102})
        self.assertEqual(0,collect_traffic(self.store,None))
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM final_traffic').fetchone()[0])

class OriginalPinBindingRegressions(unittest.TestCase):
    setUp=FinalEpochEvidenceTests.setUp
    tearDown=FinalEpochEvidenceTests.tearDown
    action=FinalEpochEvidenceTests.action
    event=FinalEpochEvidenceTests.event
    credit=FinalEpochEvidenceTests.credit

    def test_matching_current_pins_cannot_relabel_wrong_original_proof(self):
        self.action('ark','send_arkoor',at=101)
        seq=self.event('ark_transfer_verified',{'action_id':'ark','recipient_actor':'actor-02',
            'verified_at':101,'financial_pins':{**PINS,'sdk_commit':'9'*40}})
        with self.assertRaisesRegex(ValueError,'original.*pin'):
            self.credit('ark','ark',seq)
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM final_traffic').fetchone()[0])

    def test_unpinned_original_intent_cannot_gain_a_current_pin_label(self):
        self.action('ark','send_arkoor',at=101)
        seq=self.event('ark_transfer_verified',{'action_id':'ark','recipient_actor':'actor-02',
            'verified_at':101,'financial_pins':PINS})
        with self.assertRaisesRegex(ValueError,'original.*pin'):
            self.credit('ark','ark',seq)
        self.assertEqual(0,self.store.db.execute('SELECT COUNT(*) FROM final_traffic').fetchone()[0])
