import json,tempfile,unittest
from pathlib import Path
from simulator.store import Store

class EventIndexTests(unittest.TestCase):
    def test_reopening_an_existing_campaign_indexes_without_changing_any_event(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory),'synthetic',10000)
            store.db.execute('DROP INDEX IF EXISTS event_action_kind')
            store.event('ownership_incident',{'action_id':'original-action','reason':'preserved failure'})
            store.event('ownership_incident',{'action_id':'other-action','reason':'another failure'})
            before=[tuple(row) for row in store.db.execute('SELECT * FROM event ORDER BY sequence')]
            store.close()
            store=Store(Path(directory),'synthetic',10000)
            self.assertEqual(before,[tuple(row) for row in store.db.execute('SELECT * FROM event ORDER BY sequence')])
            store.verify_event_chain()
            rows=store.db.execute("SELECT payload FROM event WHERE kind='ownership_incident' AND json_extract(payload,'$.action_id')=?",('original-action',)).fetchall()
            self.assertEqual([{'action_id':'original-action','reason':'preserved failure'}],[json.loads(row[0]) for row in rows])
            plan=store.db.execute("EXPLAIN QUERY PLAN SELECT payload FROM event WHERE kind='ownership_incident' AND json_extract(payload,'$.action_id')=?",('original-action',)).fetchall()
            self.assertTrue(any('event_action_kind' in row[3] for row in plan))
            store.close()
