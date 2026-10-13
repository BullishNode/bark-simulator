"""An explicit exit lifecycle owns one journal action and lifetime reservation."""
import asyncio,importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import AsyncMock,Mock,patch
from simulator.engine import initialize
from simulator.store import Store

spec=importlib.util.spec_from_file_location('exit_fixture_controller',Path(__file__).resolve().parents[1]/'integration/unilateral-exit-client.py')
controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)


class ExitControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.manifest=self.root/'manifest.json'
        self.manifest.write_text(json.dumps({'exit_fixture':True,'network':'regtest','core_url':'http://127.0.0.1:1234',
            'core_cookie':str(self.root/'cookie'),'genesis':'genesis','state_dir':str(self.root/'state'),
            'wallet_root':str(self.root/'wallets'),'driver_config':str(self.root/'driver.json'),
            'driver':'native','proof':'verifier','server_pubkey':'server','fee_budget_sat':10000}))
        self.s=Store(self.root/'state','live',10000);initialize(self.s)
        self.request={'action_id':'one-exit','actor':'actor-01','maximum_fee_sat':2000,
            'args':{'input_vtxo_ids':['a'*64+':0'],'fee_rate_sat_per_vb':1,'fee_funding_outpoint':'b'*64+':0'}}
        self.requests=[]
    def tearDown(self):self.s.close();self.tmp.cleanup()
    async def native(self,argv,request,**kwargs):
        self.requests.append(request)
        frame={'binding':{'mailbox_pk':'mailbox','seq':1,'spk':'owned'},'coins':[],'movements':[]}
        for phase in ('before','after'):
            kwargs['on_event']({'kind':'driver_event','action_id':request['action_id'],'operation':'exit',
                'event':'client_evidence_'+phase,'data':{'fresh':True,'evidence':frame}})
        return {'action_id':request['action_id'],'status':'error' if request['maximum_fee_sat']>2000 else 'ok',
            'actual_fee_sat':None,'data':{'started':True,'held':True}}
    def run_phase(self,phase):
        chain=Mock();chain.identity.return_value={}
        with patch.object(controller,'ChainReader',return_value=chain),patch.object(controller,'json_command',side_effect=self.native),patch('builtins.print'):
            asyncio.run(controller.run(phase,self.manifest,self.request))
    def row(self):return dict(self.s.db.execute("SELECT * FROM action WHERE id='one-exit'").fetchone())
    def test_start_advance_and_inspect_keep_one_original_action_and_reservation(self):
        self.run_phase('start');original=self.row()
        for phase in ('advance','inspect'):self.run_phase(phase)
        self.assertEqual(original,self.row());self.assertEqual('outcome_unknown',original['state']);self.assertIsNone(original['actual_fee_sat'])
        self.assertEqual(1,self.s.db.execute('SELECT count(*) FROM action').fetchone()[0])
        self.assertEqual(1,self.s.db.execute("SELECT count(*) FROM event WHERE kind='action_intent'").fetchone()[0])
        self.assertEqual(['start','advance','inspect'],[r['args']['phase'] for r in self.requests])
        self.assertTrue(all(r['action_id']=='one-exit' and r['maximum_fee_sat']==2000 for r in self.requests))
        self.assertTrue(self.s.verify_event_chain())
    def test_changed_cap_probe_never_changes_original_authorization_or_reserve(self):
        self.run_phase('start');original=self.row();self.run_phase('probe_cap')
        self.assertEqual(original,self.row());self.assertEqual(2001,self.requests[-1]['maximum_fee_sat'])
        self.assertEqual(2000,self.row()['fee_reservation_sat'])
    def test_audit_is_public_only_and_never_reopens_an_offline_wallet(self):
        self.run_phase('start');self.s.set_online('actor-01',False);original=self.row()
        chain=Mock();chain.identity.return_value={}
        command=AsyncMock(side_effect=AssertionError('audit must not call native wallet'))
        with patch.object(controller,'ChainReader',return_value=chain),patch.object(controller,'json_command',command),patch('builtins.print'):
            asyncio.run(controller.run('audit',self.manifest,self.request))
        command.assert_not_called();chain.transaction.assert_not_called()
        self.assertEqual(original,self.row());self.assertFalse(self.s.online('actor-01'))
    def test_offline_or_permanently_absent_fixture_never_reaches_native_dispatch(self):
        self.s.set_online('actor-01',False)
        command=AsyncMock(side_effect=AssertionError('absent wallet must remain closed'))
        with patch.object(controller,'ChainReader',return_value=Mock()),patch.object(controller,'json_command',command),self.assertRaises(AssertionError):
            asyncio.run(controller.run('start',self.manifest,self.request))
        command.assert_not_called();self.assertEqual(0,self.s.db.execute('SELECT count(*) FROM action').fetchone()[0])


if __name__=='__main__':unittest.main()
