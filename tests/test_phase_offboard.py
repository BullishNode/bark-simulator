"""Prepared SDK offboards preserve exact on-chain destination/value/identity."""
import unittest
from simulator.model import InvariantError
class OffboardPhaseTests(unittest.TestCase):
    def quote(self):
        from simulator.bundle_audit import decode_transaction
        script='0014'+'11'*20
        raw='0200000001'+'aa'*32+'0000000000ffffffff01'+(4800).to_bytes(8,'little').hex()+'16'+script+'00000000'
        return {'principal_sat':5000,'maximum_fee_sat':2000,'inputs':[{'coin_id':'bb'*32+':0'}],'context':{'offboard_script':script}}, {'rpc':'FinishOffboard','input_coin_ids':['bb'*32+':0'],'unsigned_offboard_hex':raw,'offboard_txid':decode_transaction(raw)['txid'],'net_amount_sat':4800,'committed_fee_sat':200,'destination_script':script,'input_spends':[{'coin_id':'bb'*32+':0','txid':'cc'*32}]}
    def test_real_serialized_offboard_quote_binds_destination_net_and_once_only_fee(self):
        from simulator.phase_offboard import validate_quote
        intent,leg=self.quote();self.assertEqual(5000,validate_quote(intent,leg)['opening_principal_sat'])
    def test_changed_destination_or_locktime_cannot_reuse_the_saved_offboard_identity(self):
        from simulator.phase_offboard import validate_quote
        intent,leg=self.quote();leg['destination_script']='0014'+'22'*20
        with self.assertRaises(InvariantError):validate_quote(intent,leg)
        intent,leg=self.quote();leg['unsigned_offboard_hex']=leg['unsigned_offboard_hex'][:-8]+'01000000'
        with self.assertRaises(InvariantError):validate_quote(intent,leg)
    def test_hidden_fee_or_frozen_input_change_is_not_a_valid_offboard_preparation(self):
        from simulator.phase_offboard import validate_quote
        intent,leg=self.quote();leg['committed_fee_sat']=201
        with self.assertRaises(InvariantError):validate_quote(intent,leg)
        intent,leg=self.quote();leg['input_coin_ids']=['dd'*32+':0']
        with self.assertRaises(InvariantError):validate_quote(intent,leg)
