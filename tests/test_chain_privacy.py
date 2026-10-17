"""Private witness bytes never become observation-journal records."""
import json
import unittest
from simulator.chain import ChainReader

class ChainPrivacyTests(unittest.TestCase):
    def test_signed_core_response_is_projected_before_capture(self):
        secret='ab'*32
        # An actual canonical Bitcoin witness encoding, not a payment fixture.
        body='02000000'+'01'+'11'*32+'00000000'+'00'+'ffffffff'+'01'+'e803000000000000'+'01'+'51'
        encoded=body[:8]+'0001'+body[8:]+'02'+'40'+'aa'*64+'20'+secret+'00000000'
        value={'txid':'unused','hex':encoded,'vin':[{'txid':'11'*32,'vout':0,'txinwitness':['aa'*64,secret]}],
               'vout':[{'n':0,'value':'0.00001000','scriptPubKey':{'hex':'51'}}]}
        captured=[]
        reader=ChainReader('http://127.0.0.1:1234','unused','unused',capture=captured.append)
        reader._capture('getrawtransaction',['unused',True],value,None,json.dumps({'result':value}).encode())
        frame=captured[0]
        self.assertNotIn(secret,json.dumps(frame))
        self.assertIsNone(frame['raw'])
        public=frame['payload']['result']
        self.assertEqual(body+'00000000',public['hex'])
        self.assertTrue(public['witness_redacted'])
        self.assertEqual([64,32],public['vin'][0]['witness_item_sizes'])
        self.assertEqual([secret],value['vin'][0]['txinwitness'][1:])

    def test_other_public_rpc_raw_evidence_remains_available(self):
        captured=[]
        reader=ChainReader('http://127.0.0.1:1234','unused','unused',capture=captured.append)
        raw=b'{"result":{"chain":"regtest"}}'
        reader._capture('getblockchaininfo',[],{'chain':'regtest'},None,raw)
        self.assertEqual(raw,captured[0]['raw'])

    def test_block_inventory_omits_extra_signed_fields_and_other_verbosity_is_rejected(self):
        captured=[]
        reader=ChainReader('http://127.0.0.1:1234','unused','unused',capture=captured.append)
        value={'hash':'11'*32,'height':10,'tx':['22'*32],'unexpected_witness':['private preimage']}
        reader._capture('getblock',['11'*32,1],value,None,json.dumps(value).encode())
        self.assertNotIn('private preimage',json.dumps(captured))
        self.assertIsNone(captured[0]['raw'])
        self.assertEqual({'hash','height','tx'},set(captured[0]['payload']['result']))
        for args in [('11'*32,2),('11'*32,0),('11'*32,True),('bad',1)]:
            with self.assertRaisesRegex(ValueError,'transaction-id inventory'):
                reader.call('getblock',*args)
