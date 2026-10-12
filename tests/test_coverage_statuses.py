"""Coverage counts meaningful operations without certifying whole scenarios."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from simulator.engine import initialize
from simulator.fees import collect
from simulator.model import canonical
from simulator.report import generate
from simulator.store import Store


class CoverageStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.s = Store(Path(self.tmp.name), 'synthetic', 10000)
        initialize(self.s)

    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()

    def action(self, name, operation, scenario='H01', state='completed', result=None, actual=None):
        self.s.queue(name, 'actor-01', scenario, operation, {}, 1)
        if state != 'queued':
            self.s.db.execute("UPDATE action SET state='dispatched' WHERE id=?", (name,))
            self.s.finish(name, state, result or {}, actual)

    def case(self, scenario='H01'):
        return next(c for c in generate(self.s, evaluate=False)['coverage'] if c['id'] == scenario)

    def test_maintenance_does_not_inflate_board_coverage_or_verify_it(self):
        with self.s.transaction():
            self.s.db.executemany("""INSERT INTO action VALUES (?, 'actor-01','H01','snapshot','{}',
                'completed',0,0,0,'{}',?,?)""", [(f'snapshot-{i}', i, i) for i in range(100)])
        self.action('board', 'board')
        case = self.case()
        self.assertEqual(1, case['actions'])
        self.assertEqual('executed-unverified', case['status'])
        self.assertEqual('not_qualified', case['scenario_verdict'])
        self.assertEqual(100, case['excluded_maintenance_actions'])
        self.assertTrue(case['driver_available'])

    def board_proof(self, name='board', scenario='H01'):
        key = '02' + '11' * 32
        txid = 'b' * 64
        self.s.db.execute('INSERT OR IGNORE INTO owner_key VALUES (?,?,?,?)',
                          (key,'actor-01','mailbox','{}'))
        self.s.db.execute('INSERT OR IGNORE INTO owned_coin VALUES (?,?,?,?,?,?)',
                          ('coin',key,900,'digest','signed',canonical({'chain_anchor':txid + ':0'})))
        self.action(name,'board',scenario,result={'data':{'board':{'vtxos':['coin']},'sdk_service_fee_sat':100}})
        self.s.db.execute('UPDATE action SET args=?,fee_reservation_sat=200 WHERE id=?',
                          (canonical({'amount_sat':1000}),name))

        class Chain:
            def identity(self):
                return None

            def transaction(self, value):
                return {'txid':value,'confirmations':1,'fee_sat':20,
                        'inputs':[{'outpoint':'source:0','amount_sat':1020,'script':'own'}],
                        'outputs':[{'vout':0,'amount_sat':1000,'script':'anchor'}]}

        asyncio.run(collect(self.s,Chain()))

    def test_board_fee_proof_marks_only_action_exercised_not_whole_scenario(self):
        self.board_proof()
        case = self.case()
        self.assertEqual('exercised-verified',case['status'])
        self.assertEqual(1,case['verified_actions'])
        self.assertEqual('not_qualified',case['scenario_verdict'])
        self.assertEqual('board',case['evidence_ids'][0]['action_id'])
        self.assertEqual('client_fee_reconciled',case['evidence_ids'][0]['kind'])
        self.assertIn('complete',case['reason'])

    def test_local_zero_fee_without_independent_event_does_not_verify(self):
        self.action('create','create',actual=0)
        self.action('address','address',actual=0)
        case = self.case()
        self.assertEqual(2,case['actions'])
        self.assertEqual('executed-unverified',case['status'])
        self.assertEqual(0,case['verified_actions'])

    def test_unrelated_action_or_same_actor_evidence_does_not_promote_board(self):
        self.action('board','board',actual=0)
        self.s.event('client_fee_reconciled',{'action_id':'missing','actor':'actor-01','actual_fee_sat':0})
        self.s.event('public_ownership_verified',{'action_id':'board','actor':'actor-01','objects':0})
        self.assertEqual('executed-unverified',self.case()['status'])

    def test_fee_event_without_independent_coin_or_chain_is_insufficient(self):
        self.action('board','board',actual=0)
        self.s.event('client_fee_reconciled',{'action_id':'board','actor':'actor-01','actual_fee_sat':0})
        self.assertEqual('executed-unverified',self.case()['status'])

    def test_changed_actor_fee_or_chain_proof_keeps_unverified(self):
        self.board_proof()
        self.s.db.execute("UPDATE owner_key SET actor='actor-02'")
        self.assertEqual('executed-unverified',self.case()['status'])

    def test_preparatory_board_does_not_verify_external_lightning_behavior(self):
        self.board_proof(scenario='H35')
        case = self.case('H35')
        self.assertEqual(1,case['actions'])
        self.assertEqual('executed-unverified',case['status'])
        self.assertEqual([],case['evidence_ids'])

    def test_catalogue_sdk_adapter_is_available_even_without_raw_flag(self):
        self.assertEqual(0,self.s.db.execute("SELECT implemented FROM scenario WHERE id='H01'").fetchone()[0])
        self.assertTrue(self.case()['driver_available'])
        self.assertEqual('enumerated',self.case()['status'])

    def test_allowlist_removal_makes_raw_adapter_unavailable(self):
        from simulator.engine import OPERATIONS
        with patch('simulator.engine.OPERATIONS',OPERATIONS - {'raw_foreign_record'}):
            case = self.case('D01')
        self.assertFalse(case['driver_available'])
        self.assertEqual('blocked-by-adapter',case['status'])

    def test_create_support_alone_does_not_advertise_confirmed_board_adapter(self):
        from simulator.engine import OPERATIONS
        with patch('simulator.engine.OPERATIONS',OPERATIONS - {'board'}):
            case = self.case()
        self.assertFalse(case['driver_available'])
        self.assertEqual('blocked-by-adapter',case['status'])

    def test_unimplemented_raw_phase_and_exit_are_blocked_by_adapter(self):
        for scenario in ['D13','H14','H21','H26','H27','H29','H34']:
            with self.subTest(scenario=scenario):
                case = self.case(scenario)
                self.assertFalse(case['driver_available'])
                self.assertEqual('blocked-by-adapter',case['status'])

    def test_queued_action_is_enumerated_until_dispatched(self):
        self.action('board','board',state='queued')
        case = self.case()
        self.assertEqual(1,case['actions'])
        self.assertEqual('enumerated',case['status'])

    def test_unknown_action_is_executed_unverified(self):
        self.action('board','board',state='outcome_unknown')
        self.assertEqual('executed-unverified',self.case()['status'])

    def test_funding_block_exposes_action_reason(self):
        self.action('board','board',state='blocked',result={'data':{'reason':'insufficient confirmed funds'}})
        case = self.case()
        self.assertEqual('blocked-by-funds',case['status'])
        self.assertEqual([{'action_id':'board','reason':'insufficient confirmed funds'}],case['block_reasons'])

    def test_explicit_adapter_block_is_separate_from_funding(self):
        self.action('board','board',state='blocked',result={'reason':'unsupported adapter operation'})
        self.assertEqual('blocked-by-adapter',self.case()['status'])

    def test_h01_maintenance_is_not_applicable_and_keeps_behavior_enumerated(self):
        self.action('snapshot','snapshot',actual=0)
        self.action('sync','sync',actual=0)
        case = self.case()
        self.assertEqual(0,case['actions'])
        self.assertEqual(2,case['excluded_maintenance_actions'])
        self.assertEqual('enumerated',case['status'])
        self.assertEqual({'not-applicable'},{op['status'] for op in case['operations']})

    def test_sync_receive_outside_h01_is_kept_as_meaningful_attempt(self):
        self.action('receive-sync','sync','H37')
        self.assertEqual(1,self.case('H37')['actions'])

    def test_simulator_d37_is_fragmentation_and_keeps_its_adapter(self):
        case = self.case('D37')
        self.assertIn('fragmentation',case['behavior'])
        self.assertTrue(case['driver_available'])
        self.assertEqual('enumerated',case['status'])

    def test_epoch_counts_and_old_proof_survive_bounded_details(self):
        self.board_proof()
        with self.s.transaction():
            self.s.db.executemany("""INSERT INTO action VALUES (?, 'actor-01','H01','board','{}',
                'completed',0,0,NULL,'{}',?,?)""", [(f'later-{i}',i+2000000000,i+2000000000) for i in range(2010)])
        report = generate(self.s,evaluate=False)
        case = next(c for c in report['coverage'] if c['id']=='H01')
        self.assertEqual(2011,case['actions'])
        self.assertEqual(1,case['verified_actions'])
        self.assertEqual('board',case['evidence_ids'][0]['action_id'])
        self.assertEqual(2000,len(report['actions']))

    def test_markdown_contains_all_80_rows_and_qualification_limit(self):
        generate(self.s,evaluate=False)
        text = (self.s.root/'coverage-80.md').read_text()
        self.assertEqual(80,sum(line.startswith('| H') or line.startswith('| D') for line in text.splitlines()))
        self.assertIn('Every complete scenario remains unqualified',text)
        self.assertIn('not-applicable',text)

    def test_qualified_clock_zero_overrides_legacy_counter(self):
        self.s.db.executemany('INSERT OR REPLACE INTO meta VALUES (?,?)',
            [('qualified_campaign_active_seconds','0'),('legacy_clock_seconds','5943'),('campaign_active_seconds','6000')])
        report = generate(self.s,evaluate=False)
        self.assertEqual(0,report['campaign']['active_seconds'])
        self.assertEqual(5943,report['campaign']['legacy_clock_seconds'])
        self.assertEqual(6000,report['campaign']['campaign_active_seconds'])
        self.assertIn('qualified',report['campaign']['active_seconds_scope'])
        self.assertIn('Legacy clock seconds: 5943',(self.s.root/'report.md').read_text())

    def test_unmigrated_clock_is_clearly_labeled(self):
        self.s.db.execute("INSERT OR REPLACE INTO meta VALUES ('campaign_active_seconds','123')")
        clock = generate(self.s,evaluate=False)['campaign']
        self.assertEqual(123,clock['active_seconds'])
        self.assertIsNone(clock['qualified_campaign_active_seconds'])
        self.assertIn('not migrated',clock['active_seconds_scope'])

    def test_real_receive_fee_shape_verifies_nonmaintenance_sync(self):
        key = '02' + '11' * 32
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,'actor-01','mailbox','{}'))
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('received',key,900,'digest','signed','{}'))
        self.action('invoice','invoice','H37',result={'data':{'payment_hash':'a'*64,'estimated_claim_fee_sat':100}},actual=0)
        self.s.db.execute("UPDATE action SET args=? WHERE id='invoice'",(canonical({'amount_sat':1000}),))
        movement = {'id':'1','subsystem':'bark.lightning_receive','status':'successful','payment_hash':'a'*64,
                    'input_vtxos':[],'output_vtxos':['received'],'offchain_fee_sat':100,'effective_balance_sat':900}
        self.s.db.execute('INSERT INTO movement_evidence VALUES (?,?,?)',('actor-01','1',canonical(movement)))
        self.action('claim','sync','H37',result={'data':{'receive_count_before':1,'receive_count_after':0,
                    'before_evidence':{'movements':[]},'evidence':{'movements':[movement]}}})
        self.s.db.execute("UPDATE action SET fee_reservation_sat=200 WHERE id='claim'")
        asyncio.run(collect(self.s,None))
        case = self.case('H37')
        self.assertEqual('exercised-verified',case['status'])
        self.assertEqual(1,case['verified_actions'])
        self.assertEqual('claim',case['evidence_ids'][0]['action_id'])
        self.s.db.execute('DELETE FROM owned_coin')
        self.assertEqual('executed-unverified',self.case('H37')['status'])

    def payout_proof(self):
        self.action('board','board','H03')
        key = '02' + '11' * 32
        self.s.db.execute('INSERT INTO owner_key VALUES (?,?,?,?)',(key,'actor-01','mailbox','{}'))
        self.s.db.execute('INSERT INTO owned_coin VALUES (?,?,?,?,?,?)',('paid',key,900,'digest','signed','{}'))
        self.s.db.execute('INSERT INTO owner_record VALUES (?,?,?,?,?)',('actor-01','mailbox',1,'owner-script','{}'))
        self.s.db.execute('INSERT INTO coin_observation VALUES (?,?,?,?)',('paid','board','Spendable',1))
        self.s.db.execute('INSERT INTO checked_settlement VALUES (?,?,?,?,?,?)',('paid','payout','actor-01','owner-script',900,'{}'))
        self.s.db.execute('INSERT INTO chain_payout VALUES (?,?)',('payout',canonical({'txid':'payout','confirmations':1})))
        # This is the actual settlement event shape: there is no action_id.
        self.s.event('confirmed_payout_amounts_checked',{'txid':'payout','coins':['paid'],
                     'recipient_fee_sat':0,'operator_fee_sat':0,'scope':'confirmed amounts only'})

    def test_payout_joins_actual_event_coin_to_its_observed_action_and_owner(self):
        self.payout_proof()
        case = self.case('H03')
        self.assertEqual('exercised-verified',case['status'])
        self.assertEqual('board',case['evidence_ids'][0]['action_id'])
        self.assertEqual('confirmed_payout_amounts_checked',case['evidence_ids'][0]['kind'])
        self.assertEqual('not_qualified',case['scenario_verdict'])

    def test_payout_for_other_owner_or_missing_chain_does_not_verify(self):
        self.payout_proof()
        self.s.db.execute("UPDATE checked_settlement SET actor='actor-02'")
        self.assertEqual('executed-unverified',self.case('H03')['status'])
        self.s.db.execute("UPDATE checked_settlement SET actor='actor-01'")
        self.s.db.execute('DELETE FROM chain_payout')
        self.assertEqual('executed-unverified',self.case('H03')['status'])


if __name__ == '__main__':
    unittest.main()
