"""Public BDK SQLite metadata only; no SDK wallet or transaction-body reads."""
import hashlib
import re
import sqlite3
from pathlib import Path

def integer(value,name):
    if type(value) is not int or value<0:raise ValueError(name+' must be a nonnegative integer')
    return value


def wallet_metadata(path):
    path=Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size>16*1024*1024:
        raise ValueError('bounded existing public wallet metadata source required')
    wal=Path(str(path)+'-wal')
    if wal.exists() and wal.stat().st_size:
        raise ValueError('active SQLite WAL requires a separately authenticated consistent private snapshot')
    def identity():
        stat=path.stat()
        return (stat.st_dev,stat.st_ino,stat.st_size,stat.st_mtime_ns,hashlib.sha256(path.read_bytes()).hexdigest())
    before=identity();db=sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)
    try:
        db.execute('PRAGMA query_only=ON')
        wallet=[dict(zip(('id','descriptor','change_descriptor','network'),row)) for row in
            db.execute('SELECT id,descriptor,change_descriptor,network FROM bdk_wallet LIMIT 3')]
        last=[dict(zip(('descriptor_id','last_revealed'),row)) for row in
            db.execute('SELECT descriptor_id,last_revealed FROM bdk_descriptor_last_revealed ORDER BY descriptor_id LIMIT 3')]
        locked=[dict(zip(('txid','vout'),row)) for row in
            db.execute('SELECT txid,vout FROM bdk_wallet_locked_outpoints ORDER BY txid,vout LIMIT 2001')]
        if len(locked)>2000 or any(re.fullmatch('[0-9a-f]{64}',row['txid']) is None or type(row['vout']) is not int or row['vout']<0 for row in locked):
            raise ValueError('bounded public locked-outpoint metadata required')
        scripts=[dict(zip(('descriptor_id','spk_index','script'),row)) for row in
            db.execute('SELECT descriptor_id,spk_index,lower(hex(spk)) FROM bdk_descriptor_derived_spks ORDER BY descriptor_id,spk_index LIMIT 4001')]
        if len(wallet)!=1 or len(last)>2 or len(scripts)>4000:
            raise ValueError('public BDK descriptor/index projection exceeds declared bound')
        if wallet[0]['network']!='signet' or wallet[0]['change_descriptor'] is not None:
            raise ValueError('this A source expects actual single External signet descriptor')
        descriptor=wallet[0]['descriptor']
        if not isinstance(descriptor,str) or not descriptor.startswith('wpkh(') or any(v in descriptor for v in ('prv','\n','\x00')):
            raise ValueError('canonical public BIP84 descriptor required')
        ids={row['descriptor_id'] for row in scripts}|{row['descriptor_id'] for row in last}
        if len(ids)!=1 or any(not isinstance(v,str) or re.fullmatch('[0-9a-f]{64}',v) is None for v in ids):
            raise ValueError('one actual public descriptor index identity required')
        if len(last)!=1 or last[0]['descriptor_id'] not in ids:
            raise ValueError('actual issued descriptor frontier missing')
        frontier=integer(last[0]['last_revealed'],'actual issued public index')
        if frontier>=2000 or any(row['descriptor_id'] not in ids or type(row['spk_index']) is not int or not 0<=row['spk_index']<4000 for row in scripts):
            raise ValueError('bounded ordinary public index required')
        indices={row['spk_index'] for row in scripts}
        if len(indices)!=len(scripts):
            raise ValueError('actual public descriptor cache index repeated')
        result={'schema':'bdk-public-descriptor-index-v1','wallet':wallet[0],
            'last_revealed':last,'derived_scripts':scripts,'issued_frontier':frontier,
            'database_sha256':before[-1],'wal_absent_or_empty':True,'locked_outpoints':locked}
    finally:db.close()
    if identity()!=before or wal.exists() and wal.stat().st_size:
        raise ValueError('public metadata source changed during read')
    return result
