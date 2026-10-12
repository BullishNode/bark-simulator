#!/usr/bin/env python3
"""Rebuild raw blocks and freshly audit a complete capped unilateral exit."""
import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from chain_audit import Core, sats, sha

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from simulator.bundle_audit import decode_transaction
from simulator.store import Store
from simulator.unknown_outcomes import _prove, boundary_evidence


def verify(run, core, evidence):
    declaration = json.loads((run / 'predeclared.json').read_text())
    summary = json.loads((run / 'summary.json').read_text())
    assert summary['overall'] == 'PASS' and not summary['invalidated_sources']
    test = declaration['test'].split('::')[-1]
    assert test in {'simulator_explicit_board_exit','simulator_explicit_ark_exit_with_cpfp'}
    fixture = run / 'test-data/bark_sdk' / test
    manifest = json.loads((fixture / 'exit-fixture.json').read_text())
    assert manifest['fee_budget_sat'] == declaration['fixture_customer_fee_budget_sat']
    db = sqlite3.connect('file:' + str(fixture / 'exit-journal/state.sqlite') + '?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    store = SimpleNamespace(db=db, root=fixture / 'exit-journal')
    try:
        Store.verify_event_chain(store)
        actions = db.execute("SELECT * FROM action WHERE operation='exit'").fetchall()
        assert len(actions) == 1
        action = dict(actions[0])
        assert action['state'] == 'completed' and action['fee_reservation_sat'] == 2000
        assert db.execute("SELECT COUNT(*) FROM event WHERE kind='unknown_outcome_resolved' AND json_extract(payload,'$.action_id')=?", (action['id'],)).fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM event WHERE kind='action_intent' AND json_extract(payload,'$.action_id')=?", (action['id'],)).fetchone()[0] == 1
        args = json.loads(action['args']); ids = args['input_vtxo_ids']
        verifier = ROOT / 'target/debug/vtxo-proof'
        assert sha(verifier) == declaration['proof_sha256']
        argv = [str(verifier), f'http://127.0.0.1:{core.port}', str(core.datadir / 'regtest/.cookie'), manifest['server_pubkey']]
        frames = db.execute("SELECT payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='client_evidence_before' ORDER BY sequence", (action['id'],)).fetchall()
        assert frames
        first = boundary_evidence(store, action, 'before', json.loads(frames[0][0])['data'])
        checked = []
        for coin_id in ids:
            coins = [c for c in first['coins'] if c['id'] == coin_id]
            assert len(coins) == 1
            binding = {key: first['binding'][key] for key in ('mailbox_pk','seq','spk','record_attestation')}
            request = {**coins[0], 'binding': binding}
            response = subprocess.run(argv, input=json.dumps(request), text=True, capture_output=True, check=True, timeout=30)
            proof = json.loads(response.stdout)
            assert proof['signed_path_valid'] and proof['anchor_confirmations'] > 0
            assert proof['binding']['record_signature_valid'] and proof['binding']['key_link_signature_valid']
            coin = db.execute('SELECT c.*,k.actor FROM owned_coin c JOIN owner_key k ON k.pubkey=c.pubkey WHERE c.id=?', (coin_id,)).fetchone()
            cached = json.loads(coin['proof'])
            assert coin['actor'] == action['actor_id'] and coin['signed_vtxo'] == coins[0]['signed_vtxo']
            for key in ('id','user_pubkey','amount_sat','chain_anchor','path','server_pubkey','genesis'):
                assert proof[key] == cached[key]
            assert proof['binding']['mailbox_pk'] == cached['binding']['mailbox_pk']
            bound=proof['binding']
            assert db.execute('SELECT 1 FROM owner_record WHERE actor=? AND mailbox=? AND seq=? AND script=?',(action['actor_id'],bound['mailbox_pk'],bound['seq'],bound['spk'])).fetchone()
            checked.append(proof)
        proposals = [json.loads(r[0])['data'] for r in db.execute("SELECT payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=? AND json_extract(payload,'$.event')='exit_proposal' ORDER BY sequence", (action['id'],))]
        starts = [p for p in proposals if p['stage'] == 'start']
        assert len(starts) == 1
        steps = [p for p in proposals if p['stage'] in {'cpfp','claim'}]
        transactions = {}
        for step in steps:
            raw = core.tx(step['txid'])
            assert raw['confirmations'] > 0
            unsigned = decode_transaction(step['unsigned_tx'])
            assert unsigned['txid'] == raw['txid'] == step['txid']
            outputs = [{'vout': o['n'], 'amount_sat': sats(o['value']), 'script': o['scriptPubKey']['hex']} for o in raw['vout']]
            assert unsigned['outputs'] == outputs
            inputs = []
            for item in raw['vin']:
                previous = core.tx(item['txid'])['vout'][item['vout']]
                inputs.append({'outpoint': item['txid'] + ':' + str(item['vout']), 'amount_sat': sats(previous['value']), 'script': previous['scriptPubKey']['hex']})
            assert unsigned['inputs'] == [{'outpoint': i['outpoint']} for i in inputs]
            fee = sum(i['amount_sat'] for i in inputs) - sum(o['amount_sat'] for o in outputs)
            assert fee == step['fee_sat'] >= 0
            transactions[step['txid']] = {'txid': step['txid'], 'inputs': inputs, 'outputs': outputs, 'confirmations': raw['confirmations'], 'fee_sat': fee}
        data, proof, _ = _prove(store, action, transactions, None)
        assert data['finished'] is True and proof['actual_fee_sat'] == action['actual_fee_sat'] <= 2000
        assert sum(t['fee_sat'] for t in transactions.values()) == proof['actual_fee_sat']
        assert len([p for p in steps if p['stage'] == 'claim']) == 1
        if test.endswith('_with_cpfp'):
            assert any(p['stage'] == 'cpfp' for p in steps)
            assert db.execute("SELECT COUNT(*) FROM event WHERE kind='exit_continuation_intent'").fetchone()[0] > 0
        (evidence / 'fresh-owner-proofs.json').write_text(json.dumps(checked, indent=2) + '\n')
        (evidence / 'confirmed-cost-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
        return {'overall': 'PASS', 'source': summary['result']['source'], 'original_action_id': action['id'], 'original_fee_cap_sat': 2000,
            'actual_fee_sat': proof['actual_fee_sat'], 'signed_principal_sat': sum(p['amount_sat'] for p in checked),
            'cpfp_count': sum(p['stage'] == 'cpfp' for p in steps), 'claim_count': 1,
            'scope': 'network-disabled reconstructed chain, freshly verified signed owners, exact pre-sign proposals and complete confirmed claim; offline-server and interrupted-round exits remain unqualified'}
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--bitcoind', type=Path, required=True)
    parser.add_argument('--audit-name',default='unilateral-exit-independent-audit')
    args = parser.parse_args(); run = args.run.resolve()
    test = json.loads((run / 'predeclared.json').read_text())['test'].split('::')[-1]
    assert args.audit_name.replace('-','').replace('_','').isalnum()
    evidence = run / args.audit_name; evidence.mkdir(exist_ok=False)
    data = evidence / 'core'; (data / 'regtest').mkdir(parents=True)
    shutil.copytree(run / 'test-data/bark_sdk' / test / 'bitcoind/regtest/blocks', data / 'regtest/blocks')
    executable = args.bitcoind.resolve()
    (evidence / 'predeclared.json').write_text(json.dumps({'auditor_sha256': sha(Path(__file__)), 'core_sha256': sha(executable)}, indent=2) + '\n')
    try:
        with Core(data, executable, evidence) as core: result = verify(run, core, evidence)
    except Exception as error:
        (evidence / 'summary.json').write_text(json.dumps({'overall': 'FAIL', 'reason': type(error).__name__ + ': ' + str(error)}) + '\n')
        raise
    (evidence / 'summary.json').write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps(result))


if __name__ == '__main__':
    main()
