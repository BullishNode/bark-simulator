#!/usr/bin/env python3
"""Reconstruct fixture blocks and verify concurrent clients without their wallets."""
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
from simulator.fees import board_fee
from simulator.store import Store


def verify(run, core, evidence):
    declaration = json.loads((run / 'predeclared.json').read_text())
    summary = json.loads((run / 'summary.json').read_text())
    assert summary['overall'] == 'PASS' and not summary['invalidated_sources']
    assert declaration['test'].endswith('::simulator_concurrent_clients')
    fixture = run / 'test-data/bark_sdk/simulator_concurrent_clients'
    manifest = json.loads((fixture / 'sim-fixture.json').read_text())
    db = sqlite3.connect('file:' + str(fixture / 'sim-journal/state.sqlite') + '?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    store = SimpleNamespace(db=db)
    try:
        Store.verify_event_chain(store)
        assert db.execute("SELECT COUNT(*) FROM action WHERE state IN ('dispatched','outcome_unknown')").fetchone()[0] == 0
        verifier = ROOT / 'target/debug/vtxo-proof'
        assert sha(verifier) == declaration['proof_sha256']
        argv = [str(verifier), f'http://127.0.0.1:{core.port}', str(core.datadir / 'regtest/.cookie'), manifest['server_pubkey']]
        checked = []
        actors = set()
        for slots in (2, 3):
            batch = json.loads((run / f'out/overlap-{slots}.json').read_text())
            assert len(batch['actors']) == len(set(batch['actors'])) == slots
            assert actors.isdisjoint(batch['actors'])
            actors.update(batch['actors'])
            starts, finishes = [], []
            for board in batch['boards']:
                action = db.execute('SELECT * FROM action WHERE id=?', (board['action_id'],)).fetchone()
                assert action['state'] == 'completed' and action['actor_id'] in batch['actors']
                events = db.execute("SELECT sequence,payload FROM event WHERE kind='driver_evidence' AND json_extract(payload,'$.action_id')=?", (action['id'],)).fetchall()
                before = [r['sequence'] for r in events if json.loads(r['payload'])['event'] == 'client_evidence_before']
                after = [r['sequence'] for r in events if json.loads(r['payload'])['event'] == 'client_evidence_after']
                assert len(before) == len(after) == 1 and before[0] < after[0]
                starts.extend(before); finishes.extend(after)
                coin_ids = json.loads(action['result'])['data']['board']['vtxos']
                assert len(coin_ids) == 1
                coin = db.execute('SELECT * FROM owned_coin WHERE id=?', (coin_ids[0],)).fetchone()
                assert coin and db.execute('SELECT actor FROM owner_key WHERE pubkey=?', (coin['pubkey'],)).fetchone()[0] == action['actor_id']
                observed = db.execute("SELECT result FROM action WHERE actor_id=? AND operation='snapshot' AND state='completed' ORDER BY updated_at DESC LIMIT 1", (action['actor_id'],)).fetchone()
                data = json.loads(observed[0])['data']['evidence']
                signed = [c for c in data['coins'] if c['id'] == coin['id']]
                assert len(signed) == 1 and signed[0]['signed_vtxo'] == coin['signed_vtxo']
                binding = {key: data['binding'][key] for key in ('mailbox_pk','seq','spk','record_attestation')}
                request = {**signed[0], 'binding': binding}
                response = subprocess.run(argv, input=json.dumps(request), text=True, capture_output=True, check=True, timeout=30)
                proof = json.loads(response.stdout)
                assert proof['signed_path_valid'] and proof['anchor_confirmations'] >= 6
                assert proof['binding']['record_signature_valid'] and proof['binding']['key_link_signature_valid']
                assert (proof['id'], proof['user_pubkey'], proof['amount_sat']) == (coin['id'], coin['pubkey'], 10000)
                txid, index = proof['chain_anchor'].split(':')
                raw = core.tx(txid)
                inputs = [{'outpoint': i['txid'] + ':' + str(i['vout']), 'amount_sat': sats(core.tx(i['txid'])['vout'][i['vout']]['value']), 'script': core.tx(i['txid'])['vout'][i['vout']]['scriptPubKey']['hex']} for i in raw['vin']]
                outputs = [{'vout': o['n'], 'amount_sat': sats(o['value']), 'script': o['scriptPubKey']['hex']} for o in raw['vout']]
                fee = sum(i['amount_sat'] for i in inputs) - sum(o['amount_sat'] for o in outputs)
                assert raw['confirmations'] >= 6 and fee >= 0
                assert outputs[int(index)]['amount_sat'] == 10000
                cost = board_fee(store, action, {'txid': txid, 'inputs': inputs, 'outputs': outputs, 'fee_sat': fee, 'confirmations': raw['confirmations']})
                assert cost['actual_fee_sat'] == action['actual_fee_sat'] <= action['fee_reservation_sat'] == 2000
                checked.append({'actor': action['actor_id'], 'action_id': action['id'], 'proof': proof, 'cost': cost})
            assert len(starts) == len(finishes) == slots and max(starts) < min(finishes)
        assert len(actors) == len(checked) == 5
        (evidence / 'signed-coins-and-chain-costs.json').write_text(json.dumps(checked, indent=2) + '\n')
        return {'overall': 'PASS', 'overlap_slots': [2, 3], 'independently_verified_actors': sorted(actors), 'signed_principal_sat': 50000, 'actual_fee_sat': sum(c['cost']['actual_fee_sat'] for c in checked), 'scope': 'real native before/after overlap, reconstructed network-disabled chain, fresh signed owner proofs and exact board costs; live campaign remains separate'}
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--bitcoind', type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    evidence = run / 'concurrency-independent-audit'; evidence.mkdir(exist_ok=False)
    data = evidence / 'core'; (data / 'regtest').mkdir(parents=True)
    shutil.copytree(run / 'test-data/bark_sdk/simulator_concurrent_clients/bitcoind/regtest/blocks', data / 'regtest/blocks')
    executable = args.bitcoind.resolve()
    (evidence / 'predeclared.json').write_text(json.dumps({'auditor_sha256': sha(Path(__file__)), 'core_sha256': sha(executable)}, indent=2) + '\n')
    try:
        with Core(data, executable, evidence) as core:
            result = verify(run, core, evidence)
    except Exception as error:
        (evidence / 'summary.json').write_text(json.dumps({'overall': 'FAIL', 'reason': type(error).__name__ + ': ' + str(error)}) + '\n')
        raise
    (evidence / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
