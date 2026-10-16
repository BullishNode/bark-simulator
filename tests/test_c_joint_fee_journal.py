"""Synthetic transaction bytes/qualification declaration, no native signing credit."""
import copy
import hashlib
import json
import unittest
from simulator import c_joint_fee_journal as c
from tests import test_c_native_fee_sources as f

class JointLedger(unittest.TestCase):
    def setUp(self):
        self.policy=c.encode({'urgent_reserve_sat':40000,'ordinary_budget_sat':58000});self.marker=None;self.declaration=None
        self.parent=f.wire([('0'*64,4294967295)],[(25000,bytes.fromhex('5120'+'5'*64))]);self.pid=c.decode_transaction(self.parent.hex())['txid']
        self.signed=f.wire([(self.pid,0)],[(24000,bytes.fromhex('5120'+'3'*64))],True)
        self.weight=c.decode_transaction(self.signed.hex())['weight'];self.record={'version':2,'path':'pool','policy_sha256':c.sha(self.policy),'raw':list(self.signed),'input_parents':[list(self.parent)],'max_fee_rate':10000}
    def publication(self,record=None):
        record=copy.deepcopy(self.record if record is None else record);raw=c.encode(record);signed=bytes(record['raw']);tx=c.decode_transaction(signed.hex())
        wtxid=hashlib.sha256(hashlib.sha256(signed).digest()).digest()[::-1].hex();fee=25000-sum(v['amount_sat']for v in tx['outputs'])
        charge=self.marker if self.marker is not None else(fee if record['version']==1 else(record['max_fee_rate']*tx['weight']+999)//1000)
        entry={'version':record['version'],'path':record['path'],'wtxid':wtxid,'record_sha256':c.sha(raw),'fee_sat':fee,'charge_sat':charge}
        return b'p1\t'+c.encode(entry)+b'\n',{wtxid:raw},entry
    def decode(self,raw,records,**extra):
        args={'policy_raw':self.policy,'expected_policy_sha256':c.sha(self.policy),'publication_witnesses':records,
          'network':'signet','actual_genesis':c.SIGNET_GENESIS,'declaration_raw':self.declaration};args.update(extra)
        return c.decode(raw,**args)
    def test_joint_same_allowance_numeric_and_full_V2_ceiling_not_burned_fee(self):
        line,records,entry=self.publication();out=self.decode(b'20000\n'+line,records)
        self.assertEqual(20000+entry['charge_sat'],out['ordinary_booked_sat']);self.assertEqual(20000,out['carrier_booked_sat'])
        self.assertEqual(1000,out['publications'][0]['fee_sat']);self.assertGreater(entry['charge_sat'],1000)
        self.assertFalse(out['complete']);self.assertFalse(out['financial_readiness'])
    def test_original_v1_fee_semantics_not_repriced_after_V2(self):
        old=copy.deepcopy(self.record);old['version']=1
        line,records,entry=self.publication(old);out=self.decode(line,records)
        self.assertEqual(1000,out['publication_booked_sat']);self.assertEqual(1000,out['publications'][0]['charge_sat'])
    def test_exact_finite_REGTEST_C_is_separate_from_live_rate_times_weight(self):
        declaration={'version':1,'purpose':'common-regtest-scale-qualification','network':'regtest','genesis':c.REGTEST_GENESIS,
          'max_attempts':4,'per_attempt_ceiling_sat':10000,'ordinary_budget_sat':40000,'urgent_reserve_sat':40000,'workload_sha256':'a'*64}
        self.declaration=c.encode(declaration);self.marker=10000
        self.policy=c.encode({'urgent_reserve_sat':40000,'ordinary_budget_sat':40000,'regtest_qualification':{
          'max_attempts':4,'per_attempt_ceiling_sat':10000,'declaration_sha256':c.sha(self.declaration)}})
        self.record['policy_sha256']=c.sha(self.policy);line,records,_=self.publication()
        out=self.decode(b'10000\n'+line,records,network='regtest',actual_genesis=c.REGTEST_GENESIS)
        self.assertEqual(20000,out['ordinary_booked_sat']);self.assertEqual(10000,out['publications'][0]['charge_sat'])
        with self.assertRaises(ValueError):self.decode(line,records)  # Never live chain authority.
        with self.assertRaises(ValueError):self.decode(line,records,network='regtest',actual_genesis=c.REGTEST_GENESIS,declaration_raw=None)
    def test_same_wtxid_replay_cannot_add_second_debit(self):
        line,records,_=self.publication()
        with self.assertRaises(ValueError):self.decode(line+line,records)
        self.assertEqual(self.decode(line,records),self.decode(line,records))
    def test_original_numeric_prefix_or_publication_cannot_be_reset(self):
        line,records,_=self.publication()
        self.decode(b'20000\n'+line,records,previous_ledger=b'20000\n')
        for previous in (b'10000\n',b'20000\n'+line+b'1\n'):
            with self.assertRaises(ValueError):self.decode(b'20000\n'+line,records,previous_ledger=previous)
    def test_torn_unknown_noncanonical_order_or_boolean_entry_holds(self):
        line,records,entry=self.publication()
        bad=copy.deepcopy(entry);bad['fee_sat']=True
        for raw in (line[:-1],b'020000\n',b'0\n',b'p2\t{}\n',b'p1\t'+json.dumps(entry,sort_keys=True).encode()+b'\n',b'p1\t'+c.encode(bad)+b'\n'):
            with self.assertRaises(ValueError):self.decode(raw,records)
    def test_missing_or_orphan_private_witness_and_wrong_hash_holds(self):
        line,records,_=self.publication()
        for changed in ({},{**records,'a'*64:b'{}'},{k:v+b' 'for k,v in records.items()}):
            with self.assertRaises(ValueError):self.decode(line,changed)
    def test_actual_fee_parent_set_missing_extra_duplicate_wrong_prevout_holds(self):
        for parents in ([],[list(self.parent),list(self.parent)], [list(f.wire([('1'*64,1)],[(25000,b'\x51')]))]):
            record=copy.deepcopy(self.record);record['input_parents']=parents;line,records,_=self.publication(record)
            with self.assertRaises(ValueError):self.decode(line,records)
    def test_actual_signed_weight_ceiling_and_sat_per_kwu_not_sat_per_vbyte(self):
        record=copy.deepcopy(self.record);record['max_fee_rate']=1
        line,records,_=self.publication(record)
        with self.assertRaises(ValueError):self.decode(line,records)
        record['max_fee_rate']=c.U64;line,records,_=self.publication(record)
        with self.assertRaises(ValueError):self.decode(line,records)
    def test_whole_existing_budget_not_separate_publication_allowance(self):
        line,records,_=self.publication()
        with self.assertRaises(ValueError):self.decode(b'58000\n'+line,records)
        self.assertEqual(0,self.decode(b'58000\n',{})['ordinary_remaining_sat'])
    def test_duplicate_transaction_input_and_coinbase_are_not_native_spend(self):
        record=copy.deepcopy(self.record);record['raw']=list(f.wire([(self.pid,0),(self.pid,0)],[(24000,b'\x51')],True))
        line,records,_=self.publication(record)
        with self.assertRaises(ValueError):self.decode(line,records)
    def test_old_numeric_parser_still_holds_typed_lines_until_explicit_new_producer(self):
        line,records,_=self.publication();out=self.decode(line,records)
        self.assertEqual('pool',out['publications'][0]['path'])
        self.assertNotIn('router',out);self.assertNotIn('confirmed_cost',out)
        old=f.CNativeFeeSources();old.setUp();self.addCleanup(old.doCleanups)
        old.cut['budget_hex']=line.hex()
        with self.assertRaisesRegex(ValueError,'noncanonical native reservation'):old.collect()
