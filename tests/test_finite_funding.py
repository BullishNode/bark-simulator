"""Synthetic PSBT/Core controls only; no wallet process, payment or live credit."""
import copy
import hashlib
import json
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from simulator.bundle_audit import decode_transaction
from simulator.engine import initialize
from simulator.finite_funding import AMOUNTS, declare_finite_funding, fund_finite_cohort
from simulator import finite_funding
from simulator.model import SIGNET_GENESIS, canonical
from simulator.operating_limits import declare_envelope
from simulator.store import Store
from simulator.treasury import declare_boundary
from tests.test_final_campaign import PINS

TIP = 'a'*64
BANK_TX = 'b'*64


def raw_transaction(outputs):
    wire = bytes.fromhex('0200000001')+bytes.fromhex(BANK_TX)[::-1]+bytes.fromhex('0000000000fdffffff')
    wire += bytes([len(outputs)])
    for output in outputs:
        script = bytes.fromhex(output['scriptPubKey']['hex'])
        wire += int(Decimal(output['value'])*100000000).to_bytes(8,'little')+bytes([len(script)])+script
    return (wire+bytes(4)).hex()


class Chain:
    def __init__(self, recipients):
        self.recipients = recipients; self.confirmed = False; self.found = False; self.raw = None
        self.scripts = {'bank': '0014'+'11'*20, **{r['member_id']:r['script'] for r in recipients}}
    def identity(self):
        return {'chain':'signet','initialblockdownload':False,'blocks':100,'bestblockhash':TIP}
    def call(self, method, *args):
        if method == 'getdescriptorinfo': return {'descriptor':args[0],'hasprivatekeys':False}
        if method == 'deriveaddresses':
            member = args[0].split('(')[1].split(')')[0]
            return ['tb1q'+member]
        if method == 'validateaddress': return {'isvalid':True,'scriptPubKey':self.scripts[args[0][4:]]}
        if method == 'gettxout':
            return {'confirmations':5,'value':Decimal('.00665454'),'scriptPubKey':{'hex':self.scripts['bank']},'bestblock':TIP}
        raise AssertionError(method)
    def tx(self, txid):
        if not self.found: raise ValueError('not observed')
        return {'txid':txid,'hex':self.raw,'confirmations':1 if self.confirmed else 0,'blockhash':TIP}
    def transaction(self, txid):
        parsed = decode_transaction(self.raw)
        return {'txid':txid,'inputs':[{'outpoint':BANK_TX+':0','amount_sat':665454,'script':self.scripts['bank']}],
            'outputs':parsed['outputs'],'fee_sat':665454-sum(o['amount_sat'] for o in parsed['outputs']),
            'confirmations':1 if self.confirmed else 0,'blockhash':TIP}


class Bank:
    wallet = 'original-bank'
    token_file = 'never-read-fake-credential'
    def __init__(self, chain):
        self.chain = chain; self.calls = []; self.outputs = []; self.fee = 1000
        self.bad_payee = False; self.stolen_change = False; self.unknown = False; self.sign_unknown = False
        self.before_send = None
    def call(self, method, *args, **kwargs):
        self.calls.append(method)
        if method == 'getblockhash': return SIGNET_GENESIS
        if method == 'getwalletinfo': return {'walletname':self.wallet}
        if method == 'listlockunspent': return []
        if method == 'getaddressinfo':
            return {'ismine':not self.stolen_change,'parent_desc':'wpkh(bank)#checksum',
                    'scriptPubKey':self.chain.scripts['bank']}
        if method == 'walletcreatefundedpsbt':
            assert args[0] == [{'txid':BANK_TX,'vout':0}]
            assert args[3]['add_inputs'] is False and args[3]['lockUnspents'] is False
            self.outputs = [{'n':i,'value':amount,'scriptPubKey':{'address':address,'hex':self.chain.scripts[address[4:]]}}
                for i,item in enumerate(args[1]) for address,amount in item.items()]
            self.outputs.append({'n':5,'value':str(Decimal(665454-325000-self.fee)/100000000),
                'scriptPubKey':{'address':'tb1qbank','hex':self.chain.scripts['bank']}})
            if self.bad_payee: self.outputs[0]['value'] = '.00000001'
            self.chain.raw = raw_transaction(self.outputs)
            return {'fee':str(Decimal(self.fee)/100000000),'psbt':'public-fake-psbt'}
        if method == 'decodepsbt': return {'tx':self.decoded()}
        if method == 'walletprocesspsbt':
            if self.sign_unknown: raise TimeoutError('synthetic signing uncertainty')
            return {'psbt':'private-fake-signed-psbt'}
        if method == 'finalizepsbt': return {'complete':True,'hex':self.chain.raw}
        if method == 'decoderawtransaction': return self.decoded()
        if method == 'sendrawtransaction':
            if self.before_send: self.before_send()
            if self.unknown: raise TimeoutError('synthetic broadcast uncertainty')
            self.chain.found = True
            return decode_transaction(self.chain.raw)['txid']
        raise AssertionError(method)
    def decoded(self):
        return {'txid':decode_transaction(self.chain.raw)['txid'],
            'vin':[{'txid':BANK_TX,'vout':0}], 'vout':copy.deepcopy(self.outputs)}


class FiniteFundingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Store(Path(self.tmp.name),'synthetic',1000000)
        initialize(self.store);self.store.db.execute("INSERT INTO meta VALUES ('paused','declare')")
        self.recipients=[{'member_id':member,'role':'customer' if member.startswith('actor-') else 'operator',
            'address':'tb1q'+member,'script':'0014'+f'{index+2:02x}'*20,'amount_sat':amount,
            'descriptor_index':0,'child_index':1 if member.startswith('actor-') else 8}
            for index,(member,amount) in enumerate(AMOUNTS.items())]
        self.chain=Chain(self.recipients);self.bank=Bank(self.chain);members=[]
        for member in ['bank',*AMOUNTS]:
            item={'id':member,'identity':member,'kind':'wallet','role':'customer' if member.startswith('actor-') else 'operator',
                  'descriptors':['wpkh('+member+')#checksum']}
            self.event('treasury_member_verified',{'member':item,'genesis':SIGNET_GENESIS,'financial_pins':PINS})
            members.append({**item,'verification_sequence':self.sequence()})
        self.boundary={'id':'finite-boundary','genesis':SIGNET_GENESIS,'pins':PINS,'members':members,'excluded':['miners']}
        declare_boundary(self.store,self.boundary,self.chain)
        self.coin={'txid':BANK_TX,'vout':0,'address':'tb1qbank','amount':'.00665454','confirmations':5,
                   'spendable':True,'scriptPubKey':self.chain.scripts['bank']}
        self.event('treasury_bank_original_source',{'genesis':SIGNET_GENESIS,'complete_source_projection':True,
            'read_only':True,'stable_tip':True,'source_identity':{'wallet_name':Bank.wallet,'descriptors':['wpkh(bank)#checksum']},
            'height':100,'tip_hash':TIP,'listunspent':[self.coin]})
        bank_sequence=self.sequence()
        self.event('finite_initial_funding_sources_verified',{'financial_pins':PINS,'boundary_id':'finite-boundary',
            'bank_member_id':'bank','bank_wallet_name':Bank.wallet,'bank_source_sequence':bank_sequence,
            'principal_sat':325000,'maximum_funding_fee_sat':10000,'maximum_fee_rate_sat_kvb':20000,
            'funding_recipients':self.recipients,'height':100,'tip_hash':TIP})
        self.plan={'id':'one-and-only','pins':PINS,'boundary_id':'finite-boundary','bank_member_id':'bank',
            'bank_wallet_name':Bank.wallet,'bank_source_sequence':bank_sequence,'finite_initial_source_sequence':self.sequence(),
            'recipients':copy.deepcopy(self.recipients),'maximum_principal_sat':325000,
            'maximum_miner_fee_sat':10000,'fee_rate_sat_kvb':5000}
        self.config=SimpleNamespace(board_amount_sat=31000,action_fee_reserve_sat=19000)
        inventories={}
        for member in members:
            self.event('treasury_inventory',{'member_id':member['id'],'identity':member['identity'],'financial_pins':PINS,
                'height':100,'tip_hash':TIP,'complete':True,'utxos':[] if member['id']!='bank' else [
                    {'outpoint':BANK_TX+':0','amount_sat':665454,'script':self.chain.scripts['bank'],'descriptor_index':0,'child_index':0}]})
            inventories[member['id']]=self.sequence()
        self.limits={'id':'funding-only','pins':PINS,'boundary_id':'finite-boundary','capital_exposure_msat':1000000000,
            'fee_budgets_msat':{'ordinary':10000000,'urgent':10000000},
            'fee_ceilings_sat_kvb':{'round':20000,'pool':None,'sweep':None,'payout':None,'claim':None,'progression':None},
            'operation_fee_paths':{'funding':['round']},'per_action_fee_sat':10000,'grant_sat':50000,
            'board_sat':31000,'board_fee_reserve_sat':19000,'minimum_pool_sat':1,'minimum_channel_msat':1,
            'fee_assets':[BANK_TX+':0']}
        declare_envelope(self.store,self.limits,self.config,inventories,self.chain)
        self.proof={'financial_pins':PINS,'boundary_id':'finite-boundary','tip_hash':TIP,'height':100,'complete':True,
            'observed_at':time.time(),'effective_fee_ceilings_sat_kvb':self.limits['fee_ceilings_sat_kvb'],
            'capital_exposure_msat':665454000,'available_fee_funding_msat':665454000,'estimated_fee_rate_sat_kvb':1000,
            'operation_scope':['funding'],'bank_source_sequence':bank_sequence,
            'finite_initial_source_sequence':self.plan['finite_initial_source_sequence'],
            'funding_plan_sha256':hashlib.sha256(canonical(self.recipients).encode()).hexdigest()}
        self.event('financial_operating_readiness',self.proof)
        self.snapshot={'financial_pins':PINS,'height':100,'tip_hash':TIP,'operating_readiness_sequence':self.sequence()}
        declare_finite_funding(self.store,self.plan,self.chain)
        self.store.db.execute("DELETE FROM meta WHERE key='paused'")

    def tearDown(self):self.store.close();self.tmp.cleanup()
    def event(self,kind,payload):self.store.event(kind,payload)
    def sequence(self):return self.store.db.execute('SELECT max(sequence) FROM event').fetchone()[0]
    def fund(self):
        with patch('simulator.finite_funding.WalletRpc',return_value=self.bank):
            return fund_finite_cohort(self.store,self.bank,self.chain,self.config,self.snapshot)

    def test_five_outputs_durable_before_send_and_confirmed_fee_once(self):
        def durable():
            row=self.store.db.execute('SELECT * FROM funding_batch').fetchone()
            self.assertEqual('broadcasting',row['state']);self.assertEqual(self.chain.raw,row['raw_tx'])
            self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='fixture_funding_broadcast_intent'").fetchone()[0])
        self.bank.before_send=durable
        self.assertEqual('broadcast',self.fund()['state'])
        self.chain.confirmed=True
        self.assertEqual('confirmed',self.fund()['state']);self.fund()
        for kind in ('fixture_funding_confirmed','financial_cost_verified'):
            self.assertEqual(1,self.store.db.execute('SELECT count(*) FROM event WHERE kind=?',(kind,)).fetchone()[0])
        self.assertEqual(1,self.bank.calls.count('walletprocesspsbt'))
        self.assertEqual(1,self.bank.calls.count('sendrawtransaction'))
        prepared=json.loads(self.store.db.execute("SELECT payload FROM event WHERE kind='fixture_funding_prepared'").fetchone()[0])
        self.assertNotIn('raw_tx',prepared);self.store.verify_event_chain()

    def test_broadcast_unknown_never_rebuilds_resigns_or_resends(self):
        self.bank.unknown=True
        self.assertEqual('outcome_unknown',self.fund()['state'])
        self.fund();self.fund()
        for method in ('walletcreatefundedpsbt','walletprocesspsbt','sendrawtransaction'):
            self.assertEqual(1,self.bank.calls.count(method))

    def test_signing_unknown_never_resigns(self):
        self.bank.sign_unknown=True
        with self.assertRaises(TimeoutError):self.fund()
        self.assertEqual('outcome_unknown',self.fund()['state'])
        self.assertEqual(1,self.bank.calls.count('walletprocesspsbt'))
        self.assertNotIn('sendrawtransaction',self.bank.calls)

    def test_wrong_payee_or_change_theft_refuses_before_signing(self):
        self.bank.bad_payee=True
        with self.assertRaises(ValueError):self.fund()
        self.assertNotIn('walletprocesspsbt',self.bank.calls)
        self.assertEqual('outcome_unknown',self.fund()['state'])

    def test_change_theft_refuses_before_signing(self):
        self.bank.stolen_change=True
        # Keep the independently owned input valid and make only change foreign.
        original=self.bank.call
        def call(method,*args,**kwargs):
            if method=='getaddressinfo' and 'walletcreatefundedpsbt' not in self.bank.calls:
                return {'ismine':True,'scriptPubKey':self.chain.scripts['bank']}
            return original(method,*args,**kwargs)
        self.bank.call=call
        with self.assertRaises(ValueError):self.fund()
        self.assertNotIn('walletprocesspsbt',self.bank.calls)

    def test_fee_cap_refuses_before_signing(self):
        self.bank.fee=10001
        with self.assertRaisesRegex(ValueError,'fee exceeds'):self.fund()
        self.assertNotIn('walletprocesspsbt',self.bank.calls)

    def test_changed_declaration_and_unscoped_readiness_refuse_before_psbt(self):
        changed=copy.deepcopy(self.plan);changed['recipients'][0]['amount_sat']+=1
        with self.assertRaises(ValueError):declare_finite_funding(self.store,changed,self.chain)
        self.proof['operation_scope']=['sync'];self.event('financial_operating_readiness',self.proof)
        self.snapshot['operating_readiness_sequence']=self.sequence()
        with self.assertRaises(ValueError):self.fund()
        self.assertNotIn('walletcreatefundedpsbt',self.bank.calls)

    def test_preparation_intent_is_durable_before_first_wallet_rpc(self):
        original=self.bank.call
        def call(method,*args,**kwargs):
            if method=='walletcreatefundedpsbt':
                self.assertEqual('outcome_unknown',self.store.db.execute('SELECT state FROM funding_batch').fetchone()[0])
                self.assertEqual(1,self.store.db.execute("SELECT count(*) FROM event WHERE kind='fixture_funding_prepare_intent'").fetchone()[0])
            return original(method,*args,**kwargs)
        self.bank.call=call
        self.assertEqual('broadcast',self.fund()['state'])

    def test_crash_after_prepared_bytes_resumes_without_resigning(self):
        original=finite_funding._admit;count=0
        def admit(*args,**kwargs):
            nonlocal count
            count+=1
            if count==3:raise RuntimeError('synthetic crash after signed bytes committed')
            return original(*args,**kwargs)
        with patch('simulator.finite_funding._admit',side_effect=admit),self.assertRaises(RuntimeError):self.fund()
        self.assertEqual('prepared',self.store.db.execute('SELECT state FROM funding_batch').fetchone()[0])
        self.assertEqual('broadcast',self.fund()['state'])
        self.assertEqual(1,self.bank.calls.count('walletprocesspsbt'))
        self.assertEqual(1,self.bank.calls.count('sendrawtransaction'))

    def test_changed_retained_transaction_refuses_without_resend(self):
        self.fund()
        self.store.db.execute('UPDATE funding_batch SET txid=?',('c'*64,))
        with self.assertRaises(ValueError):self.fund()
        self.assertEqual(1,self.bank.calls.count('sendrawtransaction'))

    def test_owned_change_from_wrong_descriptor_refuses_before_signing(self):
        original=self.bank.call
        def call(method,*args,**kwargs):
            result=original(method,*args,**kwargs)
            if method=='getaddressinfo' and 'walletcreatefundedpsbt' in self.bank.calls:
                result['parent_desc']='wpkh(other-wallet)#checksum'
            return result
        self.bank.call=call
        with self.assertRaisesRegex(ValueError,'original declared bank'):self.fund()
        self.assertNotIn('walletprocesspsbt',self.bank.calls)

    def test_actual_signed_fee_rate_cap_refuses_before_broadcast(self):
        self.bank.fee=7000
        with self.assertRaisesRegex(ValueError,'fee policy differs'):self.fund()
        self.assertNotIn('sendrawtransaction',self.bank.calls)
        self.assertEqual('outcome_unknown',self.fund()['state'])


if __name__=='__main__':unittest.main()
