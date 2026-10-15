#!/usr/bin/env python3
"""Read-only padding assertions for an isolated native regtest fixture."""
import asyncio
import hashlib
import json
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from simulator.chain import ChainReader
from simulator.engine import initialize
from simulator.entitlements import unclaimed_expired_report
from simulator.model import canonical
from simulator.ownership import record_server_page
from simulator.padding import collect, collect_backing, decoded_coin, record_sweep, report
from simulator.bundle_audit import decode_transaction
from simulator.store import Store
from integration.fixture_runtime import fixture_profile


async def main():
    mode, source = sys.argv[1:]
    assert mode in {'before', 'after'}
    manifest = json.loads(Path(source).read_text())
    assert manifest['network'] == 'regtest'
    assert manifest['core_url'].startswith('http://127.0.0.1:')
    helper = Path(manifest['decoder'])
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == manifest['decoder_sha256']
    profile = fixture_profile(manifest)
    store = Store(Path(manifest['state_dir']), 'live', 10000, architecture_profile=profile)
    initialize(store)
    chain = ChainReader(manifest['core_url'], manifest['core_cookie'], manifest['genesis'],
                        capture=store.trace_sample, consumer='round-padding-fixture')
    try:
        rows = manifest['inventory']
        for offset in range(0, len(rows), 100):
            record_server_page(store, {'kind': 'coins', 'rows': rows[offset:offset + 100],
                                      'next': None, 'inventory_consistent': False})
        for _ in range((len(rows) + 31) // 32):
            await collect(store, [str(helper)], manifest['server_pubkey'], limit=32)
        for _ in range((len(rows) + 31) // 32):
            await collect_backing(store, chain, [str(helper)], manifest['server_pubkey'], limit=32)
        # Sweeps can aggregate padded trees with other expired backing. Verify
        # direct server contracts for those extra inputs too, so unknown input
        # ownership is not silently relaxed for this fixture.
        for row in rows:
            decoded = decoded_coin(store, row, server_pubkey=manifest['server_pubkey'])
            if not decoded or decoded['tree_padding'] or decoded['id'] != decoded['chain_anchor']:
                continue
            anchor = decoded['chain_anchor']; txid, index = anchor.split(':')
            transaction = chain.tx(txid)
            assert transaction.get('confirmations', 0) > 0
            request = {'signed_vtxo': row['signed_vtxo'], 'server_pubkey': manifest['server_pubkey'], 'anchor_raw': transaction['hex']}
            proof = json.loads(subprocess.run([str(helper)], input=json.dumps(request), capture_output=True, text=True, check=True).stdout)
            raw = decode_transaction(transaction['hex']); output = raw['outputs'][int(index)]
            assert raw['txid'] == txid and proof['id'] == row['vtxo_id'] and proof['chain_anchor'] == anchor
            assert proof['server_pubkey'] == manifest['server_pubkey']
            assert proof['chain_contract_verified'] is True and proof['client_owner_verified'] is False
            assert (proof['anchor_amount_sat'], proof['anchor_script']) == (output['amount_sat'], output['script'])
            store.trace_capture('padding.fixture.contract', {'request': request, 'response': proof})
            store.db.execute('INSERT OR IGNORE INTO tree_padding_backing VALUES (?,?,?,?)',
                (anchor, output['amount_sat'], output['script'], canonical(proof)))
        # The isolated fixture explicitly declares scripts from its own operator
        # wallet_status. This is not permission to infer live descriptor ownership.
        for script in manifest['fixture_operator_scripts']:
            store.db.execute('INSERT OR IGNORE INTO operator_script VALUES (?,?)',
                (script, canonical({'scope': 'isolated native fixture operator declaration'})))
        tip = chain.identity()
        for txid in manifest.get('sweep_candidates', []):
            tx = chain.tx(txid)
            assert tx.get('confirmations', 0) > 0
            height = tip['blocks'] - tx['confirmations'] + 1
            assert chain.call('getblockhash', height) == tx['blockhash']
            raw = decode_transaction(tx['hex'])
            wires = {txid: tx['hex']}
            for item in raw['inputs']:
                parent = item['outpoint'].split(':')[0]
                wires[parent] = chain.tx(parent)['hex']
            record_sweep(store, {**tx, 'height': height}, wires)
        result = report(store, height=tip['blocks'])
        customer = unclaimed_expired_report(store, tip['blocks'])
        assert result['unclassified_coin_rows'] == 0, result
        assert customer['expired_unclaimed_public_key_rows'] == 0, customer
        assert result['additive_asset'] is False
        if mode == 'before':
            assert result['tree_padding_unclaimed'] > 0, result
            assert result['tree_padding_swept'] == 0, result
            assert result['tree_padding_locked_sat'] == result['tree_padding_unclaimed'] * 330, result
            result['fixture_initial_padding_count'] = result['tree_padding_unclaimed']
        else:
            previous = json.loads((Path(manifest['out_dir']) / 'round-padding-before.json').read_text())
            assert result['tree_padding_swept'] == previous['fixture_initial_padding_count'], result
            assert result['tree_padding_locked_sat'] == 0, result
        (Path(manifest['out_dir']) / f'round-padding-{mode}.json').write_text(json.dumps(result, indent=2) + '\n')
        store.verify_event_chain()
        print(json.dumps({'status': 'PASS', 'phase': mode, 'padding': result}))
    finally:
        store.close()


if __name__ == '__main__':
    asyncio.run(main())
