#!/usr/bin/env python3
"""Replay saved native sync evidence on a copy; never run clients or fixtures.

This checks reservation accounting and preservation. It relies on the signed
proofs already independently verified in the saved fixture journal; it does
not replace the reconstructed-Core proof audit or a newly compiled fixture.
"""
import argparse
import asyncio
import hashlib
import json
import sqlite3
from pathlib import Path

from simulator.fees import collect, receive_fee
from simulator.model import canonical
from simulator.store import Store


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preserved_rows(db):
    return {table: [list(row) for row in db.execute(f'SELECT * FROM {table} ORDER BY 1')]
            for table in ['owned_coin', 'owner_key', 'movement_evidence']}


def audit(journal, output, earlier_id, proving_id):
    journal = journal.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before_hash = sha(journal)
    source = sqlite3.connect(journal.as_uri() + '?mode=ro', uri=True)
    source.row_factory = sqlite3.Row
    original_proofs = preserved_rows(source)
    original_results = [list(r) for r in source.execute('SELECT id,result FROM action ORDER BY id')]
    destination = sqlite3.connect(output / 'state.sqlite')
    source.backup(destination)
    destination.close()
    mode = source.execute("SELECT value FROM meta WHERE key='mode'").fetchone()[0]
    source.close()
    store = Store(output, mode)
    try:
        store.verify_event_chain()
        earlier = store.db.execute('SELECT * FROM action WHERE id=?', (earlier_id,)).fetchone()
        proving = store.db.execute('SELECT * FROM action WHERE id=?', (proving_id,)).fetchone()
        assert earlier['operation'] == proving['operation'] == 'sync'
        assert earlier['actor_id'] == proving['actor_id']
        assert earlier['actual_fee_sat'] is None
        independent_claim = receive_fee(store, proving)
        assert independent_claim['actual_fee_sat'] == proving['actual_fee_sat']
        before_budget = store.remaining_fee_budget()
        asyncio.run(collect(store, None, limit=100000))
        assert store.db.execute('SELECT actual_fee_sat FROM action WHERE id=?', (earlier_id,)).fetchone()[0] == 0
        assert store.db.execute('SELECT actual_fee_sat FROM action WHERE id=?', (proving_id,)).fetchone()[0] == independent_claim['actual_fee_sat']
        releases = [json.loads(r[0]) for r in store.db.execute("""SELECT payload FROM event
            WHERE kind='fee_reservation_released' AND json_extract(payload,'$.action_id')=?""", (earlier_id,))]
        assert len(releases) == 1 and releases[0]['proving_action_id'] == proving_id
        after_budget = store.remaining_fee_budget()
        asyncio.run(collect(store, None, limit=100000))
        assert store.remaining_fee_budget() == after_budget
        assert store.db.execute("""SELECT count(*) FROM event WHERE kind='fee_reservation_released'
            AND json_extract(payload,'$.action_id')=?""", (earlier_id,)).fetchone()[0] == 1
        rows = [json.loads(r[0]) for r in store.db.execute("""SELECT payload FROM event
            WHERE kind='client_fee_reconciled' AND json_extract(payload,'$.action_id')=?""", (proving_id,))]
        assert len(rows) == 1 and canonical(rows[0]) == canonical({'action_id': proving_id, **independent_claim})
        assert original_proofs == preserved_rows(store.db)
        assert original_results == [list(r) for r in store.db.execute('SELECT id,result FROM action ORDER BY id')]
        store.verify_event_chain()
        assert sha(journal) == before_hash
        summary = {'overall': 'PASS', 'source_journal_sha256': before_hash,
                   'auditor_sha256': sha(Path(__file__)),
                   'fees_sha256': sha(Path(__file__).parent / 'simulator/fees.py'),
                   'earlier_action_id': earlier_id, 'proving_action_id': proving_id,
                   'claimed_receive_fee_sat': independent_claim['actual_fee_sat'],
                   'release': releases[0], 'budget_reclaimed_sat': after_budget - before_budget,
                   'claim_charged_once': True, 'reservation_released_once': True,
                   'proofs_and_results_preserved': True, 'original_journal_unchanged': True,
                   'scope': 'saved native boundary accounting replay on separate DB copy; no wallets or node access; fresh native fixture and reconstructed-Core proof audit remain release gates'}
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary))
    finally:
        store.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('journal', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--earlier', default='fixture-sync-3')
    parser.add_argument('--proving', default='fixture-sync-5')
    args = parser.parse_args()
    audit(args.journal, args.output, args.earlier, args.proving)


if __name__ == '__main__':
    main()
