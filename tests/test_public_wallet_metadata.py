"""Real SQLite metadata controls, no SDK, seed or transaction-body queries."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from simulator.public_wallet_metadata import wallet_metadata

class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'db.sqlite';self.db=sqlite3.connect(self.path)
        self.db.executescript('CREATE TABLE bdk_wallet(id,descriptor,change_descriptor,network);CREATE TABLE bdk_descriptor_last_revealed(descriptor_id,last_revealed);CREATE TABLE bdk_descriptor_derived_spks(descriptor_id,spk_index,spk);CREATE TABLE private_transaction_bodies(private_value);CREATE TABLE bdk_wallet_locked_outpoints(txid,vout);')
        self.db.execute('INSERT INTO bdk_wallet VALUES(1,?,NULL,?)',('wpkh(public/*)#sum','signet'))
        self.db.execute('INSERT INTO bdk_descriptor_last_revealed VALUES(?,1)',('a'*64,))
        self.db.executemany('INSERT INTO bdk_descriptor_derived_spks VALUES(?,?,?)',[('a'*64,n,bytes([81+n])) for n in range(3)])
        self.db.execute('INSERT INTO private_transaction_bodies VALUES(?)',('must not export',));self.db.commit()
    def tearDown(self):self.db.close();self.tmp.cleanup()
    def test_public_projection_and_byte_unchanged_database(self):
        before=self.path.read_bytes();value=wallet_metadata(self.path)
        self.assertEqual(1,value['issued_frontier']);self.assertEqual(before,self.path.read_bytes())
        self.assertNotIn('must not export',str(value));self.assertEqual(3,len(value['derived_scripts']))
    def test_nonempty_wal_and_private_descriptor_refuse(self):
        wal=Path(str(self.path)+'-wal');wal.write_bytes(b'active')
        with self.assertRaisesRegex(ValueError,'WAL'):wallet_metadata(self.path)
        wal.unlink();self.db.execute("UPDATE bdk_wallet SET descriptor='wpkh(tprv/private/*)'");self.db.commit()
        with self.assertRaisesRegex(ValueError,'public BIP84'):wallet_metadata(self.path)
    def test_missing_issued_script_foreign_network_and_multiple_descriptor_refuse(self):
        self.db.execute('DELETE FROM bdk_descriptor_derived_spks WHERE spk_index=1');self.db.commit()
        self.assertEqual(1,wallet_metadata(self.path)['issued_frontier']) # BDK may persist no derived-script cache.
        self.db.execute('INSERT INTO bdk_descriptor_last_revealed VALUES(?,2)',('b'*64,));self.db.commit()
        with self.assertRaisesRegex(ValueError,'index identity'):wallet_metadata(self.path)
        self.db.execute("UPDATE bdk_wallet SET network='regtest'");self.db.commit()
        with self.assertRaisesRegex(ValueError,'single External'):wallet_metadata(self.path)
