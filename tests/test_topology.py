import copy, unittest
from simulator.topology import ready

class TopologyTests(unittest.TestCase):
    def setUp(self):
        channel={'channel_id':'a'*64,'funding_txid':'b'*64,'funding_outnum':0,
                 'state':'CHANNELD_NORMAL','spendable_msat':5_000_000,'receivable_msat':'5000000msat'}
        self.snapshot={'height':100,'capabilities':{'lightning_configured':True},'lightning':{
            'operator':{'node_id':'operator','fully_synced':True,'blockheight':100,'channels':[{**channel,'peer_id':'peer'}]},
            'fixture_peer':{'node_id':'peer','fully_synced':True,'blockheight':100,'channels':[{**channel,'peer_id':'operator'}]}}}
    def test_matching_normal_liquid_channel_is_ready(self):
        self.assertTrue(ready(self.snapshot))
    def test_unrelated_channel_or_wrong_funding_cannot_start_clock(self):
        for key,value in [('peer_id','other'),('funding_txid','c'*64),('funding_outnum',1)]:
            snapshot=copy.deepcopy(self.snapshot);snapshot['lightning']['operator']['channels'][0][key]=value
            self.assertFalse(ready(snapshot))
    def test_opening_channel_or_one_way_liquidity_cannot_start_clock(self):
        for key,value in [('state','DUALOPEND_AWAITING_LOCKIN'),('spendable_msat',0),('receivable_msat',None)]:
            snapshot=copy.deepcopy(self.snapshot);snapshot['lightning']['operator']['channels'][0][key]=value
            self.assertFalse(ready(snapshot))
    def test_lag_or_missing_peer_evidence_cannot_start_clock(self):
        self.snapshot['lightning']['fixture_peer']['blockheight']=90;self.assertFalse(ready(self.snapshot))
        self.snapshot['lightning']['fixture_peer']['blockheight']=100
        self.snapshot['lightning']['fixture_peer']['fully_synced']=False;self.assertFalse(ready(self.snapshot))
