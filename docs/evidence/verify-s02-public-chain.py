#!/usr/bin/env python3
"""Read-only independent Core verification; never opens an actor wallet."""
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
import sqlite3
import base64
import urllib.request

base = Path('/var/lib/abandon-fresh')
cookie = (base / 'core/signet/.cookie').read_text().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def rpc(method, *args):
    request = urllib.request.Request('http://127.0.0.1:38332/',
        data=json.dumps({'jsonrpc': '2.0', 'id': 'root-read-only', 'method': method, 'params': args}).encode(),
        headers={'Content-Type': 'application/json', 'Authorization': 'Basic ' + base64.b64encode(cookie.encode()).decode()})
    with opener.open(request, timeout=30) as response:
        result = json.load(response, parse_float=Decimal)
    assert result.get('error') is None, method + ' failed'
    return result['result']
def sats(value):
    value = Decimal(str(value)) * 100_000_000
    assert value == value.to_integral_value()
    return int(value)
def tx(txid):
    return rpc('getrawtransaction', txid, True)
def inputs(transaction):
    return [(item, tx(item['txid'])['vout'][item['vout']]) for item in transaction['vin']]

first = base / 'simulation/s02-7055d1fce-first-pass.json'
assert hashlib.sha256(first.read_bytes()).hexdigest() == '18c876d882211e62fb748ce5bd4f153fc349bdcc78797488554bc0a5e99d9de5'
chain = rpc('getblockchaininfo')
assert chain['chain'] == 'signet' and not chain['initialblockdownload']
assert chain['signet_challenge'] == ('512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430'
    '210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae')
assert rpc('getblockhash', 0) == '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'
state = base / 'simulation/s02-7055d1fce'
with sqlite3.connect('file:' + str(state / 'signet.sqlite') + '?mode=ro', uri=True) as database:
    row = database.execute("SELECT id,reply FROM action WHERE actor='absent' AND operation='fallback_record' AND state='acknowledged' ORDER BY created LIMIT 1").fetchone()
    assert row is not None
    registration_intent, raw = row
    registration = json.loads(raw)
payout_id = '7e6fc92a2dd6a7422eacf340d1555f45bfa7945c22027de6b92672b2b200cea7'
recovery_id = '4147d72db6958f05705d3d4386597d6a06168ac72e119fdc1b88b485c1679c0b'
payout = tx(payout_id)
recovery = tx(recovery_id)
assert payout['confirmations'] >= 6 and recovery['confirmations'] >= 6
assert payout['blockhash'] == rpc('getblockhash', 326685)
assert recovery['blockhash'] == rpc('getblockhash', 326686)
assert payout['vout'][0]['scriptPubKey']['hex'] == registration['record']['spk'] == '001469728388534686afa68f051cb3fb9eacfb7710ea'
assert sats(payout['vout'][0]['value']) == 28_670
payout_input_total = sum(sats(previous['value']) for _, previous in inputs(payout))
assert payout_input_total == sum(sats(output['value']) for output in payout['vout'])
recovery_inputs = inputs(recovery)
covered = [(item, previous) for item, previous in recovery_inputs if item['txid'] == payout_id and item['vout'] == 0]
assert len(covered) == 1
ordinary_change = sum(sats(previous['value']) for item, previous in recovery_inputs if item['txid'] != payout_id or item['vout'] != 0)
assert ordinary_change == 69_847
assert len(recovery['vout']) == 1
assert recovery['vout'][0]['scriptPubKey']['address'] == 'tb1qusq7m3xctjl5csfrr5zpfzg0lqsp9q46z5pa5p'
received = sats(recovery['vout'][0]['value'])
assert received == 98_339
assert 28_670 + ordinary_change - received == 178
assert rpc('gettxout', payout_id, 0, True) is None
fee_child_id = 'ee22e1a94127f9917251e1813f7198f07e8bb3ad60ab852b717573d2a6c5c467'
fee_child = tx(fee_child_id)
assert fee_child['confirmations'] >= 6
assert fee_child['blockhash'] == payout['blockhash']
child_inputs = inputs(fee_child)
anchor_inputs = [(item, previous) for item, previous in child_inputs if item['txid'] == payout_id]
assert len(anchor_inputs) == 1 and sats(anchor_inputs[0][1]['value']) == 0
gross_miner_fee = sum(sats(previous['value']) for _, previous in child_inputs) - sum(sats(output['value']) for output in fee_child['vout'])
assert gross_miner_fee == 916
operator_remainder = sum(sats(output['value']) for output in payout['vout'][1:])
assert operator_remainder == 1_330
proof = {'at': datetime.now(timezone.utc).isoformat(), 'observer': 'root read-only Bitcoin Core31 RPC; no actor wallet opened',
    'network': 'public signet', 'default_signet_challenge_verified': True, 'observed_height': chain['blocks'], 'first_pass_sha256': hashlib.sha256(first.read_bytes()).hexdigest(),
    'original_first_pass_height': 326686, 'original_first_pass_payout_confirmations': 2,
    'registered_script_verified_from_native_journal_intent': registration_intent,
    'payout': {'txid': payout_id, 'vout': 0, 'amount_sat': 28_670, 'customer_coin_sat': 29_670, 'output_fee_sat': 1_000,
               'block_height': 326685, 'confirmations_now': payout['confirmations'], 'parent_miner_fee_sat': 0},
    'recovery': {'txid': recovery_id, 'block_height': 326686, 'confirmations_now': recovery['confirmations'],
                 'exact_payout_consumed': True, 'other_ordinary_change_input_sat': ordinary_change,
                 'destination_received_sat': received, 'miner_fee_sat': 178},
    'fee_accounting': {'child_txid': fee_child_id, 'gross_watchman_funded_miner_fee_sat': gross_miner_fee,
                      'operator_parent_remainder_sat': operator_remainder,
                      'earlier_board_residual_sat': 330, 'new_fallback_output_fee_sat': 1_000,
                      'operator_chain_net_sat': operator_remainder - gross_miner_fee,
                      'fallback_fee_less_miner_fee_excluding_board_residual_sat': 1_000 - gross_miner_fee,
                      'net_operator_subsidy_sat': max(gross_miner_fee - operator_remainder, 0)},
    'scope': 'independent current canonical chain/script/value/spend/cost proof; seed-only methodology is separately attested by original controller/native artifacts'}
print(json.dumps(proof))
