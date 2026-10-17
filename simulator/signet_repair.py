"""Repair observation for the stopped S03 cohort; never reopens its actors."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

from .model import btc_to_sat, canonical
from .signet import Campaign, network_identity
from .signet_discovery import discover_payouts
from .signet_phase import _native, _quiescent, _verify_runtime
from .signet_s02 import _confirmed_transaction, _freeze, _save, check_recovery, observe_payout, recovery_source

FIRST_PAYOUT = "08247b6a71e60f2bdac4730c05476669f1e1c6e72b1bbc5e6cfc60ba958582ef:0"
BIRTHDAY = 326700


def stage(origin: Path, directory: Path, config: dict, runtime_pins: dict, *,
          stop_file: Path, lock_file: Path, frozen_sha256: str, destination: str):
    """Import frozen public evidence and protected phrase, not wallet databases.

    Run only after the coordinator's checked service-deployment handoff. Runtime
    hashes verify that packet; this function does not manufacture qualification.
    """
    origin, directory = Path(origin).absolute(), Path(directory).absolute()
    if (directory.exists() or directory == origin or origin in directory.parents
            or directory in origin.parents or any(p.is_symlink() for p in
                [origin, origin / "private", origin / "signet.sqlite", stop_file, lock_file])):
        raise ValueError("new disjoint phase and nonsymlink original evidence required")
    if not stop_file.is_file() or not lock_file.is_file():
        raise ValueError("original STOP and existing runner lock required")
    with lock_file.open("r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = sqlite3.connect((origin / "signet.sqlite").as_uri() + "?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN")
            if db.execute("SELECT 1 FROM action WHERE state IN ('unknown','dispatched')").fetchone():
                raise ValueError("original unknown outcome requires reconciliation")
            if not db.execute("SELECT 1 FROM actor WHERE id='absent' AND absent=1").fetchone():
                raise ValueError("original absent fence required")
            frozen = db.execute("SELECT value FROM meta WHERE key='s02_absent:absent'").fetchone()[0]
            if hashlib.sha256(frozen.encode()).hexdigest() != frozen_sha256:
                raise ValueError("original frozen evidence digest differs")
            public = json.loads(frozen)
            if (sorted(c['amount_sat'] for c in public['coins']) != [10000, 29670]
                    or len({c['chain_anchor'] for c in public['coins']}) != 2
                    or {c['expiry_height'] for c in public['coins']} != {326714}
                    or {p['coin_id'] for p in public['signature_proofs']} != {c['id'] for c in public['coins']}
                    or any(p.get('status') != 'PASS' or not p.get('path_outpoints') for p in public['signature_proofs'])):
                raise ValueError("exact original two-root S03 signed cohort required")
            create = db.execute("SELECT chain FROM action WHERE id='s02-absent-create'").fetchone()
            if not create or json.loads(create[0])['height'] != BIRTHDAY:
                raise ValueError("original birthday 326700 required")
            old_config = json.loads(db.execute("SELECT value FROM meta WHERE key='config'").fetchone()[0])
            if any(old_config[k] != config[k] for k in ['ark_url', 'core_url', 'core_credential']):
                raise ValueError("repair must retain the original target endpoints")
            source = recovery_source(SimpleNamespace(root=origin, db=db, actor_path=lambda _: origin / 'wallets/absent'), 'absent')
            if source.parent != origin / 'private':
                raise ValueError("original protected recovery source path required")
            phrase = source.read_bytes()
            artifact = db.execute("SELECT sha256 FROM native_artifact WHERE intent='s02-recovery-source-absent' AND kind='source'").fetchone()
            if hashlib.sha256(phrase).hexdigest() != artifact[0]:
                raise ValueError('protected source changed while staging')
            campaign = Campaign(directory, config)
            try:
                campaign.db.execute("INSERT INTO meta VALUES ('phase_runtime_pins',?)", (canonical(runtime_pins),))
                _verify_runtime(campaign)
                valid = campaign.core.call('validateaddress', destination)
                if valid.get('isvalid') is not True or not valid.get('scriptPubKey'):
                    raise ValueError("valid owned recovery destination required")
                campaign._retain_private('s02-recovery-source-absent', 'source', io.BytesIO(phrase))
                provenance = {'kind': 'S03_repair_origin', 'origin_directory': str(origin),
                              'stop_file': str(stop_file), 'lock_file': str(lock_file),
                              'frozen_sha256': frozen_sha256, 'original_config': old_config,
                              'birthday_height': BIRTHDAY, 'recovery_destination': destination,
                              'first_payout_outpoint': FIRST_PAYOUT,
                              'scope': 'Original public proofs remain historical; new runtime pins apply to repair/recovery only. No original wallet database copied.'}
                campaign.db.execute('BEGIN IMMEDIATE')
                campaign.db.execute("INSERT INTO actor VALUES ('absent',1)")
                campaign.db.execute("INSERT INTO meta VALUES ('s02_absent:absent',?)", (frozen,))
                campaign.db.execute("INSERT INTO meta VALUES ('s03_repair_origin',?)", (canonical(provenance),))
                campaign.db.execute('COMMIT')
                return {'stage': 'REPAIR_OBSERVER_STAGED', 'frozen_sha256': frozen_sha256,
                        'birthday_height': BIRTHDAY, 'original_wallet_copied': False}
            finally:
                campaign.close()
        finally:
            db.close()


def _fee_child(campaign, payout, chain):
    """Read public blocks for the actual confirmed P2A fee child, resumably."""
    parent_id = payout['outpoint'].split(':')[0]
    parent, height = _confirmed_transaction(campaign, parent_id, chain)
    anchors = {f"{parent_id}:{out['n']}" for out in parent['vout']
               if out['scriptPubKey']['hex'] == '51024e73'}
    if len(anchors) != 1:
        raise ValueError('one actual P2A anchor required')
    key = 's03_repair_child:' + parent_id
    previous = campaign.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    cursor = json.loads(previous[0]) if previous else {'height': height}
    if cursor.get('blockhash') and campaign.core.call('getblockhash', cursor['height'] - 1) != cursor['blockhash']:
        cursor = {'height': height}
    for block_height in range(cursor['height'], min(chain['height'] + 1, cursor['height'] + 8)):
        blockhash = campaign.core.call('getblockhash', block_height)
        block = campaign.core.call('getblock', blockhash, 2)
        for tx in block['tx']:
            if any(v.get('txid', '') + ':' + str(v.get('vout')) in anchors for v in tx['vin']):
                child, _ = _confirmed_transaction(campaign, tx['txid'], chain)
                total = 0
                for v in child['vin']:
                    prev = campaign.core.call('getrawtransaction', v['txid'], True)
                    total += btc_to_sat(prev['vout'][v['vout']]['value'])
                fee = total - sum(btc_to_sat(o['value']) for o in child['vout'])
                if child.get('version') != 3 or fee <= 0:
                    raise ValueError('actual version-3 positive-fee child required')
                # Keep cursor at the child's block for independent recheck,
                # including a replaced/undone child after a public-chain reorg.
                campaign.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',
                                    (key, canonical({'height': block_height})))
                return {'parent_txid': parent_id, 'child_txid': child['txid'],
                        'child_miner_fee_sat': fee, 'parent_miner_fee_sat': 0,
                        'confirmation_height': block_height, 'confirmations': child['confirmations']}
        cursor = {'height': block_height + 1, 'blockhash': blockhash}
    campaign.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, canonical(cursor)))
    return None


def advance(campaign):
    """Observe both payouts, then one native phrase-only restore and drain."""
    _quiescent(campaign)
    _verify_runtime(campaign)
    row = campaign.db.execute("SELECT value FROM meta WHERE key='s03_repair_origin'").fetchone()
    if not row:
        raise ValueError('separate staged S03 repair phase required')
    origin = json.loads(row[0])
    if not Path(origin['stop_file']).is_file():
        raise ValueError('original controller STOP must remain present')
    with Path(origin['lock_file']).open('r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        frozen = _freeze(campaign, 'absent')
        if hashlib.sha256(canonical(frozen).encode()).hexdigest() != origin['frozen_sha256']:
            raise ValueError('imported frozen evidence changed')
        discovery = discover_payouts(campaign, 'absent')
        payouts = {}
        for row in campaign.db.execute("""SELECT id,payload FROM result
            WHERE json_extract(payload,'$.kind')='S02_payout_observation'
            AND json_extract(payload,'$.payout_check')='PASS' ORDER BY observed""").fetchall():
            old = json.loads(row['payload'])
            point = old['outpoint']
            if point in payouts:
                continue
            txid, index = point.split(':')
            current = observe_payout(campaign, 'absent', txid, int(index), old['coin_ids'])
            if current['payout_check'] == 'PASS':
                payouts[point] = (row['id'], current)
        base = {'kind': 'S03_repair_observation', 'case': 'S03-repair',
                'case_verdict': 'INCOMPLETE', 'historical_grouping_verdict': 'NOT_QUALIFIED',
                'first_payout_outpoint': FIRST_PAYOUT, 'discovery': discovery}
        expected = {c['id']: c['amount_sat'] - 1000 for c in frozen['coins']}
        if (len(payouts) != 2 or FIRST_PAYOUT not in payouts
                or {c for _, p in payouts.values() for c in p['coin_ids']} != set(expected)
                or any(len(p['coin_ids']) != 1 or p['amount_sat'] != expected[p['coin_ids'][0]] for _, p in payouts.values())
                or payouts[FIRST_PAYOUT][1]['amount_sat'] != 28670):
            return _save(campaign, 's03-repair', {**base, 'stage': 'WAITING_FOR_BOTH_EXACT_PAYOUTS'})
        chain = network_identity(campaign.core)
        fees = [_fee_child(campaign, p, chain) for _, p in payouts.values()]
        if network_identity(campaign.core) != chain:
            raise ValueError('chain changed during repair fee observation')
        if any(p is None for p in fees):
            return _save(campaign, 's03-repair', {**base, 'stage': 'WAITING_FOR_CONFIRMED_FEE_CHILDREN'})
        _native(campaign, 's03-repair-seed-restore', 'restored', 'restore', {
            'source_actor': 'absent', 'birthday_height': BIRTHDAY,
            'wallet_profile': {'vtxo_refresh_expiry_threshold': 4, 'vtxo_exit_margin': 2}})
        if not campaign.db.execute("SELECT 1 FROM action WHERE id='s03-repair-drain'").fetchone():
            number = campaign.db.execute("SELECT count(*) FROM action WHERE operation='onchain_utxos'").fetchone()[0]
            utxos = _native(campaign, f's03-repair-utxos-{number}', 'restored', 'onchain_utxos')
            found = {u['outpoint']: u for u in utxos if u['confirmation_height'] is not None}
            if any(point not in found or found[point]['amount_sat'] != p['amount_sat'] for point, (_, p) in payouts.items()):
                return _save(campaign, 's03-repair', {**base, 'stage': 'WAITING_FOR_NATIVE_SEED_DISCOVERY'})
            if network_identity(campaign.core) != chain:
                return _save(campaign, 's03-repair', {**base, 'stage': 'WAITING_FOR_STABLE_CHAIN_BEFORE_DRAIN'})
        _native(campaign, 's03-repair-drain', 'restored', 'onchain_drain', {'destination': origin['recovery_destination']})
        recovery = [check_recovery(campaign, 'absent', 'restored', 's03-repair-drain', i,
                                   origin['recovery_destination']) for i, _ in payouts.values()]
        complete = all(r['recovery_check'] == 'PASS' for r in recovery)
        return _save(campaign, 's03-repair', {**base,
                     'stage': 'REPAIRED_PAYOUTS_AND_SEED_RECOVERY_CONFIRMED' if complete else 'WAITING_FOR_CONFIRMED_RECOVERY',
                     'case_verdict': 'PASS' if complete else 'INCOMPLETE',
                     'confirmed_payout_sat': 37670, 'actual_payout_output_fees_sat': 2000,
                     'payout_outpoints': sorted(payouts), 'fee_children': fees, 'recovery': recovery,
                     'scope': 'Repair of the historical two-output liability, not a successful grouped payout.'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    sub = parser.add_subparsers(dest='operation', required=True)
    start = sub.add_parser('stage')
    for name in ['origin', 'runtime-pins', 'stop-file', 'lock-file']:
        start.add_argument('--' + name, type=Path, required=True)
    start.add_argument('--frozen-sha256', required=True)
    start.add_argument('--destination', required=True)
    sub.add_parser('step')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if args.operation == 'stage':
        result = stage(args.origin, args.state, config, json.loads(args.runtime_pins.read_text()),
                       stop_file=args.stop_file, lock_file=args.lock_file,
                       frozen_sha256=args.frozen_sha256, destination=args.destination)
    else:
        campaign = Campaign(args.state, config)
        try:
            with (args.state / 'repair.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = advance(campaign)
        finally:
            campaign.close()
    print(canonical(result))


if __name__ == '__main__':
    main()
