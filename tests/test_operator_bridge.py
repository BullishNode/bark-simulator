"""A bridge declaration cannot replace independent rounds-wallet ownership."""
import asyncio,json,unittest
from unittest.mock import AsyncMock,patch
from tests import test_operator_scripts as operator_fixtures
from tests import test_settlements as settlement_fixtures
from simulator.settlements import check_payment
from simulator.ownership import EvidenceGap

class OperatorBridgeTests(unittest.TestCase):
    def setUp(self):
        operator_fixtures.OperatorScriptTests.setUp(self)
        self.s.attach_trace()
    tearDown=operator_fixtures.OperatorScriptTests.tearDown
    proof=settlement_fixtures.SettlementTests.proof
    record=settlement_fixtures.SettlementTests.record
    server=settlement_fixtures.SettlementTests.server
    evidence=settlement_fixtures.SettlementTests.evidence
    def response(self):
        return {'kind':'rounds_descriptor','declaration':{
            'kind':'operator_rounds_wallet_descriptor','version':1,
            'network':'regtest','genesis':'genesis','server_pubkey':'server',
            'wallet_kind':'rounds','descriptor':self.value['descriptor'],
            'range':[0,2],'wallet_last_revealed_at_capture':1,
            'declared_utc':'2026-10-12T23:07:14+00:00','captured_utc':'2026-10-12T23:02:16+00:00',
            'inventory_sha256':'a'*64,'live_production_head':'b'*40,
            'target_vm':'172.81.182.157','scope':'public descriptor, not an ownership verdict'}}
    def collect_bridge(self,response=None,error=None):
        from simulator.operator_scripts import collect
        self.config.operator_bridge_enabled=True
        self.config.inventory_command=('readonly-bridge',)
        command=AsyncMock(side_effect=error,return_value=self.response() if response is None else response)
        with patch('simulator.operator_bridge.json_command',command):
            asyncio.run(collect(self.s,self.config,self.chain))
        return command
    def test_valid_bridge_is_traced_but_change_still_needs_independent_core_anchor(self):
        command=self.collect_bridge()
        self.assertEqual({'kind':'rounds_descriptor'},command.await_args.args[1])
        self.assertEqual(129,check_payment(self.s,[self.row],self.tx)['operator_fee_sat'])
        rows=[r for r in self.s.trace.records() if r['kind']=='target.rounds_descriptor']
        self.assertEqual(1,len(rows));self.assertEqual(self.response(),rows[0]['payload']['response'])
        self.assertTrue(any(method=='getdescriptorinfo' for method,_ in self.chain.calls))
        self.s.verify_event_chain()
    def test_bridge_range_gap_cannot_qualify_new_change_or_mutate_local_declaration(self):
        response=self.response();response['declaration']['range']=[0,0]
        self.collect_bridge(response)
        with self.assertRaises(EvidenceGap):check_payment(self.s,[self.row],self.tx)
        self.assertEqual(self.value,json.loads(self.path.read_text()))
        self.assertFalse(self.chain.calls)
    def test_foreign_bridge_descriptor_or_identity_cannot_qualify_change(self):
        response=self.response();response['declaration']['server_pubkey']='foreign'
        self.collect_bridge(response)
        self.assertFalse(self.chain.calls)
        self.assertEqual(1,self.s.db.execute('SELECT count(*) FROM operator_script').fetchone()[0])
    def test_bridge_does_not_make_a_foreign_core_anchor_ours(self):
        self.chain.foreign=True;self.collect_bridge()
        with self.assertRaises(EvidenceGap):check_payment(self.s,[self.row],self.tx)
    def test_unavailable_bridge_preserves_evidence_and_reports_gap(self):
        self.collect_bridge(error=RuntimeError('offline'))
        self.assertFalse(self.chain.calls)
        self.assertTrue(any(row['kind']=='operator_descriptor_pending' for row in self.s.db.execute('SELECT kind FROM event')))
        self.assertEqual(self.value,json.loads(self.path.read_text()))
    def test_private_bridge_response_cannot_enter_trace_or_financial_journal(self):
        response=self.response();response['declaration']['mnemonic']='never-publish-this'
        self.collect_bridge(response)
        self.assertFalse(self.chain.calls)
        self.assertFalse(any('never-publish-this' in json.dumps(row['payload']) for row in self.s.trace.records()))
        self.assertFalse(any('never-publish-this' in row[0] for row in self.s.db.execute('SELECT payload FROM event')))
