#!/usr/bin/env python3
"""Reconstruct raw blocks and freshly verify public payout and recovery evidence."""
import argparse, json, shutil, sqlite3, subprocess, sys
from pathlib import Path

SIM = Path(__file__).resolve().parents[1]
from chain_audit import Core, sats, sha


def verify(run, core, evidence):
    pre = json.loads((run / 'predeclared.json').read_text())
    summary = json.loads((run / 'summary.json').read_text())
    assert summary['overall'] == 'PASS' and not summary['invalidated_sources']
    fixture = run / 'test-data/bark_sdk/simulator_public_payout_seed_recovery'
    manifest = json.loads((fixture / 'sim-fixture.json').read_text())
    db = sqlite3.connect('file:' + str(fixture / 'public-payout-oracle/state.sqlite') + '?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    original = sqlite3.connect('file:' + str(fixture / 'sim-journal/state.sqlite') + '?mode=ro', uri=True)
    boundary = original.execute("SELECT MAX(sequence) FROM event WHERE kind='fixture_absence_armed'").fetchone()[0]
    assert boundary and original.execute("SELECT COUNT(*) FROM event WHERE sequence>? AND kind='driver_request'", (boundary,)).fetchone()[0] == 0
    assert db.execute("SELECT online FROM actor WHERE id='actor-01'").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM event WHERE kind IN ('driver_request','ark_transfer_verified','recycle_confirmed')").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM event WHERE kind='public_proof_imported'").fetchone()[0] == 1
    row = db.execute('SELECT * FROM recovered_capital').fetchone()
    recovery = db.execute('SELECT * FROM seed_recovery').fetchone()
    assert row and recovery['state'] == 'confirmed' and row['recovery_id'] == recovery['id']
    assert db.execute("SELECT COUNT(*) FROM event WHERE kind='seed_recovery_spend'").fetchone()[0] == 1
    assert db.execute('SELECT state FROM settlement_check').fetchone()[0] == 'amounts_checked'
    bundle = json.loads((run / 'out/public-proof-bundle.json').read_text())
    proof_bin = SIM / 'target/debug/vtxo-proof'
    assert sha(proof_bin) == pre['proof_sha256']
    argv = [str(proof_bin), f'http://127.0.0.1:{core.port}', str(core.datadir / 'regtest/.cookie'), manifest['server_pubkey']]
    verified = []
    for coin in bundle['coins']:
        result = subprocess.run(argv, input=json.dumps(coin), text=True, capture_output=True, check=True, timeout=30)
        proof = json.loads(result.stdout)
        assert proof['id'] == coin['id'] and proof['amount_sat'] == coin['amount_sat']
        assert proof['signed_path_valid'] and proof['anchor_confirmations'] > 0
        assert proof['binding']['record_signature_valid'] and proof['binding']['key_link_signature_valid']
        verified.append(proof)
    inventory = json.loads((run / 'out/public-payout-inventory.json').read_text())
    assert len(inventory['settlements']) == len(verified) == 1
    candidate = inventory['settlements'][0]
    assert {h['spend_state'] for h in candidate['pre_commit_rows']} == {'spendable'}
    payout = core.tx(candidate['txid'])
    assert payout['confirmations'] > 0
    owner = verified[0]
    assert owner['binding']['spk'] == candidate['spk']
    payee = [o for o in payout['vout'] if o['scriptPubKey']['hex'] == candidate['spk']]
    assert len(payee) == 1
    gross = owner['amount_sat']
    net = sats(payee[0]['value'])
    assert gross == net + candidate['fee_sat']
    others = [o for o in payout['vout'] if o not in payee]
    assert len(others) == 1
    descriptor = json.loads((run / 'out/public-operator-descriptor.json').read_text())
    info = core.call('getdescriptorinfo', descriptor['descriptor'])
    assert info['hasprivatekeys'] is False and info['isrange'] and info['issolvable']
    addresses = core.call('deriveaddresses', info['descriptor'], [descriptor['first_index'], descriptor['last_index']])
    scripts = {core.call('validateaddress', address)['scriptPubKey'] for address in addresses}
    anchor = inventory['operator_anchor']
    anchor_txid, anchor_vout = anchor['outpoint'].split(':')
    anchor_tx = core.tx(anchor_txid)
    assert anchor_tx['confirmations'] > 0 and anchor_tx['vout'][int(anchor_vout)]['scriptPubKey']['hex'] == anchor['script']
    assert anchor['script'] in scripts and others[0]['scriptPubKey']['hex'] in scripts
    assert anchor['script'] != others[0]['scriptPubKey']['hex'], 'historical anchor must independently establish another change script'
    input_sum = sum(sats(core.tx(i['txid'])['vout'][i['vout']]['value']) for i in payout['vin'])
    mining = input_sum - sum(sats(o['value']) for o in payout['vout'])
    assert mining >= candidate['fee_sat']
    spend = core.tx(row['txid'])
    assert spend['confirmations'] > 0 and len(spend['vin']) == 1 and len(spend['vout']) == 1
    expected_point = candidate['txid'] + ':' + str(payee[0]['n'])
    actual_point = spend['vin'][0]['txid'] + ':' + str(spend['vin'][0]['vout'])
    assert actual_point == expected_point
    intent = json.loads(recovery['intent'])
    assert [s['outpoint'] for s in intent['sources']] == [expected_point]
    decoded = core.call('decoderawtransaction', recovery['raw_tx'])
    assert decoded['txid'] == spend['txid'] and decoded['vin'] == spend['vin'] and decoded['vout'] == spend['vout']
    destination = core.call('validateaddress', manifest['recovery_destination'])['scriptPubKey']
    assert destination == spend['vout'][0]['scriptPubKey']['hex'] == intent['destination_script']
    recovered = sats(spend['vout'][0]['value'])
    fee = net - recovered
    assert net == row['gross_sat'] and recovered == row['recovered_sat'] and fee == row['fee_sat'] <= 2000
    assert net == fee + recovered
    assert db.execute('SELECT COUNT(*) FROM seed_recovery_input').fetchone()[0] == 1
    (evidence / 'fresh-public-proofs.json').write_text(json.dumps(verified, indent=2) + '\n')
    (evidence / 'raw-confirmed-transactions.json').write_text(json.dumps([anchor_tx, payout, spend], default=str, indent=2) + '\n')
    db.close(); original.close()
    return {'overall': 'PASS', 'fresh_native_public_signatures': True, 'historical_operator_change': True,
            'payout': {'txid': candidate['txid'], 'gross_sat': gross, 'net_sat': net, 'recipient_fee_sat': candidate['fee_sat'],
                       'operator_fee_sat': mining - candidate['fee_sat']},
            'recovery': {'txid': row['txid'], 'gross_sat': net, 'fee_sat': fee, 'recovered_sat': recovered},
            'original_wallet_calls_after_absence': 0, 'source_spent_once': True, 'traffic_credit': 0, 'recycling_credit': 0,
            'scope': 'one registered-board payout and confirmed automated BIP84 seed-only spend; other actors/sources and live signet remain unqualified'}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('run', type=Path)
    parser.add_argument('--bitcoind',type=Path,required=True,help='trusted compatible Bitcoin Core executable')
    args = parser.parse_args()
    run = args.run.resolve(); evidence = run / 'recovery-independent-audit'; evidence.mkdir(exist_ok=False)
    data = evidence / 'core'; (data / 'regtest').mkdir(parents=True)
    shutil.copytree(run / 'test-data/bark_sdk/simulator_public_payout_seed_recovery/bitcoind/regtest/blocks', data / 'regtest/blocks')
    executable = args.bitcoind.resolve()
    (evidence / 'predeclared.json').write_text(json.dumps({'auditor_sha256': sha(Path(__file__)), 'core_sha256': sha(executable)}, indent=2))
    try:
        with Core(data, executable, evidence) as core: result = verify(run, core, evidence)
    except Exception as error:
        (evidence / 'summary.json').write_text(json.dumps({'overall': 'FAIL', 'reason': type(error).__name__ + ': ' + str(error)})); raise
    (evidence / 'summary.json').write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps(result))


if __name__ == '__main__': main()
