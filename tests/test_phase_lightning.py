"""Claim/refund controllers bind real HTLC identities and retain unknown money."""
import unittest
from simulator.model import InvariantError
from simulator.ownership import EvidenceGap
class LightningPhaseTests(unittest.TestCase):
    def prepared(self):
        from simulator.phase_lightning import validate_prepared
        intent={'scenario':'D34','actor':'actor-04','principal_sat':5000,'maximum_fee_sat':2000,'context':{'payment_hash':'aa'*32,'sender_actor':'actor-11','sender_htlc_ids':['b1'*32+':0']},'inputs':[{'coin_id':'a1'*32+':0'}]}
        legs=[]
        for leg,rpc,ids,prefix in [('claim','ClaimLightningReceive',['a1'*32+':0'],'c1'),('refund','RequestLightningPayHtlcRevocation',['b1'*32+':0'],'c2')]:
            legs.append({'leg_id':leg,'rpc':rpc,'payment_hash':'aa'*32,'input_coin_ids':ids,'wire_sha256':prefix*32,'private_checkpoint_sha256':prefix*32,'signing_session_sha256':prefix*32,'nonce_retention':'single_process','restart_continuation':False,'input_spends':[{'coin_id':ids[0],'txid':prefix*32}], 'outputs':[{'coin_id':prefix*32+':0','amount_sat':5000,'input_coin_ids':ids}], 'input_principal_sat':5000})
        return validate_prepared,intent,legs
    def test_real_claim_and_refund_inputs_are_separate_but_same_hash_and_one_principal(self):
        validate,intent,legs=self.prepared();out=validate(intent,legs)
        self.assertEqual(5000,out['principal_sat']);self.assertFalse(out['financial_outcome_verified'])
    def test_different_hash_or_sender_ids_cannot_become_same_payment_race(self):
        validate,intent,legs=self.prepared();legs[1]['payment_hash']='ff'*32
        with self.assertRaises(InvariantError):validate(intent,legs)
        legs[1]['payment_hash']='aa'*32;legs[1]['input_coin_ids']=['ff'*32+':0']
        with self.assertRaises(InvariantError):validate(intent,legs)
    def test_opaque_nonce_restart_and_inflated_output_are_rejected(self):
        validate,intent,legs=self.prepared();legs[0]['restart_continuation']=True
        with self.assertRaises(InvariantError):validate(intent,legs)
        legs[0]['restart_continuation']=False;legs[0]['outputs'][0]['amount_sat']=5001
        with self.assertRaises(InvariantError):validate(intent,legs)
    def test_withheld_claim_does_not_require_or_invent_refund_package(self):
        validate,intent,legs=self.prepared();intent['scenario']='D36';intent['context']['withhold_until_height']=326200
        out=validate(intent,legs[:1]);self.assertEqual(326200,out['withhold_until_height'])
        self.assertFalse(out['claim_dispatched']);self.assertFalse(out['customer_traffic_credit'])
    def test_refund_authorization_requires_actual_exact_signed_current_refund_evidence(self):
        from simulator.phase_lightning import refund_authorization
        _,intent,legs=self.prepared();intent['scenario']='D33'
        with self.assertRaises(EvidenceGap):refund_authorization(None,intent,legs[1])
    def test_partial_lost_or_two_signed_competing_replies_hold_further_registration(self):
        from simulator.phase_lightning import registration_allowed
        self.assertFalse(registration_allowed([{'kind':'sdk_signed_successors'},{'kind':'transport_unknown'}]))
        self.assertFalse(registration_allowed([{'kind':'sdk_signed_successors'},{'kind':'sdk_signed_successors'}]))
        self.assertFalse(registration_allowed([{'kind':'sdk_signed_successors'}]))
        self.assertTrue(registration_allowed([{'kind':'sdk_signed_successors'},{'kind':'protocol_refusal'}]))

class SenderPreparationReadinessTests(unittest.TestCase):
    def test_actual_pending_checkpoints_use_only_the_prederived_key_without_mutation(self):
        import copy
        from simulator.phase_lightning import sender_refund_terms
        for stage in ('HtlcReceived','PaymentInitiated'):
            checkpoint={'progress':{stage:{'vtxo_ids':['a'*64+':0']}},'revocation_key':'02'+'11'*32}
            frozen=copy.deepcopy(checkpoint)
            self.assertEqual(('02'+'11'*32,['a'*64+':0']),sender_refund_terms(checkpoint))
            self.assertEqual(frozen,checkpoint)
        with self.assertRaises(EvidenceGap):sender_refund_terms({'progress':{'PaymentInitiated':{'vtxo_ids':['a'*64+':0']}},'revocation_key':None})
    def test_existing_revocation_cannot_drift_or_reuse_an_ambiguous_stuck_attempt(self):
        from simulator.phase_lightning import sender_refund_terms
        checkpoint={'progress':{'RevocableHtlcs':{'htlcs':{'vtxo_ids':['a'*64+':0']},'revocation':{'key':'02'+'11'*32}}},'revocation_key':'02'+'22'*32}
        with self.assertRaises(InvariantError):sender_refund_terms(checkpoint)
        with self.assertRaises(EvidenceGap):sender_refund_terms({'progress':'Start'})

class WithheldRefundReadinessTests(unittest.TestCase):
    def evidence(self):
        return {'payment_hash':'aa'*32,'height':121,'receiver_deadline':120,'sweep_min_confirmations':3,
            'granted_ids':['a'*64+':0','b'*64+':0'],'paths':[
            {'coin_id':'a'*64+':0','resolution':'swept','confirmed_height':118,'raw_chain_proof_sha256':'11'*32},
            {'coin_id':'b'*64+':0','resolution':'exited_timeout','confirmed_height':119,'raw_chain_proof_sha256':'22'*32}]}
    def test_deadline_equality_missing_paths_notfound_or_shallow_timeout_stay_held(self):
        import copy
        from simulator.phase_lightning import withheld_refund_ready
        good=self.evidence()
        import hashlib
        from simulator.model import canonical
        proofs={}
        for path in good['paths']:
            proof={k:v for k,v in path.items() if k!='raw_chain_proof_sha256'}
            proof.update(payment_hash=good['payment_hash'],method='independent_raw_chain_path_audit')
            checksum=hashlib.sha256(canonical(proof).encode()).hexdigest();path['raw_chain_proof_sha256']=checksum;proofs[checksum]=proof
        self.assertTrue(withheld_refund_ready(good,proof_lookup=proofs.get)['ready'])
        self.assertFalse(withheld_refund_ready(good)['ready'])
        for change in [{'height':120},{'paths':good['paths'][:1]}, {'paths':[{**good['paths'][0],'resolution':'not_found'},good['paths'][1]]},
            {'paths':[good['paths'][0],{**good['paths'][1],'confirmed_height':120}]}, {'paths':[good['paths'][0],{**good['paths'][1],'raw_chain_proof_sha256':None}]}]:
            evidence=copy.deepcopy(good);evidence.update(change)
            self.assertFalse(withheld_refund_ready(evidence,proof_lookup=proofs.get)['ready'])
