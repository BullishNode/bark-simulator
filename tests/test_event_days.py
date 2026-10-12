import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from simulator.store import Store

class EventDayExportTests(unittest.TestCase):
    def test_full_export_appends_new_records_and_keeps_closed_days_unchanged(self):
        from simulator.export_bundle import export_event_days
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);store=Store(root,'synthetic',1000)
            try:
                at=dt.datetime(2026,1,1,tzinfo=dt.timezone.utc).timestamp()
                with patch('simulator.store.time.time',return_value=at):store.event('first',{'value':1})
                export_event_days(store)
                first=root/'events/events-2026-01-01.jsonl';original=first.read_bytes()
                with patch('simulator.store.time.time',return_value=at+86400):store.event('second',{'value':2})
                export_event_days(store);export_event_days(store)
                self.assertEqual(original,first.read_bytes())
                rows=[json.loads(line) for path in sorted((root/'events').glob('*.jsonl')) for line in path.read_text().splitlines()]
                self.assertEqual([1,2],[row['sequence'] for row in rows])
                self.assertEqual(2,json.loads((root/'events-manifest.json').read_text())['last_sequence'])
            finally:store.close()
    def test_restart_after_stale_cursor_does_not_duplicate_exported_record(self):
        from simulator.export_bundle import export_event_days
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);store=Store(root,'synthetic',1000)
            try:
                store.event('first',{});export_event_days(store)
                manifest=root/'events-manifest.json';manifest.unlink()
                export_event_days(store)
                self.assertEqual(1,sum(len(path.read_text().splitlines()) for path in (root/'events').glob('*.jsonl')))
            finally:store.close()
