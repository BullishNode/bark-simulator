"""C-only private native bodies in the SAME fixed public19 RR transaction.

No connection setup, path/SQL dispatch, installs or ownership/readiness claims.
Full originals may contain witness preimages: retain only private0600/encrypted
wire. The trusted launcher must authenticate this and the existing adapter before
import, and supervise the ENTIRE call (checks alone cannot interrupt PG I/O).
"""
from pathlib import Path
import time
from . import c_private_fee_cut as common

MAX_BODY_BYTES = 2*1024*1024
MAX_BYTES = 16*1024*1024
MAX_ROWS = 10000
ROLE = 'trackcbodyobserver'
# Exact04c writers/readers, not a guessed wrapper prefix. User-policy encodings
# can overlap; that does not change the declared source's native type.
SOURCE_ENCODINGS = {'coins':'ServerVtxoFull','pending_boards':'VtxoFull','pool':'VtxoFull'}
ADDITIONAL_SELECT_COLUMNS = {
    'public.vtxo':['vtxo'],
    'public.pending_board':['id','vtxo'],
    'public.vtxo_pool':['vtxo','spent_at'],
    'public.vtxo_pool_retirement':['vtxo_id','pool_input_id'],
}
# SQL is compiled entirely from this immutable literal map, never a request,
# database row or observed config. All retained pool rows are included, spent or
# unspent; absence is never used as operator-capital proof.
SOURCES = {
 'coins':('public.vtxo','vtxo_id',
 "vtxo_id,amount,expiry,spend_state,policy_type,encode(policy,'hex') AS policy,anchor_point,vtxo_txid,oor_spent_txid,spent_in_round,offboarded_in,frontier_at,confirmed_height,onchain_spent_height,onchain_spent_txid", ''),
 'pending_boards':('public.pending_board','vtxo_id','vtxo_id,expiry',",'anchor_point',id"),
 'pool':('public.vtxo_pool','id','id,vtxo_id,expiry_height,amount',",'spent_at',spent_at::text"),
}

def _sql():
    pre=["'role',current_user", "'database',current_database()", "'read_only',current_setting('transaction_read_only')", "'isolation',current_setting('transaction_isolation')"];body=[]
    for name,(table,order,columns,extra) in SOURCES.items():
        pre.extend(["'%s',(SELECT count(*) FROM %s)"%(name,table),
          "'%s_bytes',COALESCE((SELECT sum(octet_length(vtxo)*2+octet_length(row_to_json(m)::text)+512) FROM %s b CROSS JOIN LATERAL (SELECT %s) m),0)"%(name,table,columns),
          "'%s_max',COALESCE((SELECT max(octet_length(vtxo)) FROM %s),0)"%(name,table),
          "'%s_null',(SELECT count(*) FROM %s WHERE vtxo IS NULL OR octet_length(vtxo)=0)"%(name,table)])
        body.append("'%s',COALESCE((SELECT jsonb_agg(jsonb_build_object('metadata',row_to_json(m),'source_encoding','%s','body_hex',encode(vtxo,'hex')%s) ORDER BY %s) FROM %s b CROSS JOIN LATERAL (SELECT %s) m),'[]'::jsonb)"%(name,SOURCE_ENCODINGS[name],extra,'b.'+order,table,columns))
    pre.extend(["'pool_retirements',(SELECT count(*) FROM public.vtxo_pool_retirement)",
      "'pool_retirements_bytes',COALESCE((SELECT sum(octet_length(vtxo_id)+octet_length(pool_input_id)+128) FROM public.vtxo_pool_retirement),0)"])
    body.append("'pool_retirements',COALESCE((SELECT jsonb_agg(jsonb_build_object('vtxo_id',vtxo_id,'pool_input_id',pool_input_id) ORDER BY vtxo_id) FROM public.vtxo_pool_retirement),'[]'::jsonb)")
    identity="'snapshot',pg_current_snapshot()::text,'backend_pid',pg_backend_pid(),'database',current_database(),'role',current_user,'read_only',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation')"
    return ('SELECT jsonb_build_object('+','.join(pre)+')',
            'SELECT jsonb_build_object('+identity+','+','.join(body)+')')

PREFLIGHT_SQL, PRIVATE_SQL = _sql()


def _preflight(value):
    identity={'role':ROLE,'database':'trackc','read_only':'on','isolation':'repeatable read'}
    expected={'pool_retirements','pool_retirements_bytes',*identity}
    for name in SOURCES:expected.update([name,name+'_bytes',name+'_max',name+'_null'])
    if (not isinstance(value,dict)or set(value)!=expected
            or any(value[k]!=v for k,v in identity.items())
            or any(type(v)is not int or v<0 for k,v in value.items()if k not in identity)
            or sum(value[n]for n in [*SOURCES,'pool_retirements'])>MAX_ROWS
            or sum(value[n+'_bytes']for n in [*SOURCES,'pool_retirements'])>MAX_BYTES
            or any(value[n+'_max']>MAX_BODY_BYTES or value[n+'_null'] for n in SOURCES)):
        raise ValueError('native body preflight exceeds fixed source bounds')


def _assemble(pg,header,public_rows,preflight):
    fields={'snapshot','backend_pid','database','role','read_only','isolation',*SOURCES,'pool_retirements'}
    if (not isinstance(pg,dict)or set(pg)!=fields or pg['role']!=ROLE
            or pg['database']!='trackc' or pg['read_only']!='on' or pg['isolation']!='repeatable read'
            or type(pg['backend_pid'])is not int or pg['backend_pid']<=0
            or any(pg[k]!=header['identity'][k]for k in ['snapshot','backend_pid','database','read_only','isolation'])):
        raise ValueError('native body actual same-RR identity differs')
    for name in SOURCES:
        rows=pg[name];extras={'pending_boards':{'anchor_point'},'pool':{'spent_at'}}.get(name,set())
        if not isinstance(rows,list)or len(rows)!=preflight[name]:raise ValueError('native body count differs from preflight')
        metadata=[];keys=[]
        for row in rows:
            if not isinstance(row,dict)or set(row)!={'metadata','source_encoding','body_hex',*extras}or row['source_encoding']!=SOURCE_ENCODINGS[name]:
                raise ValueError('native body source type/columns differ')
            raw=common._raw(row['body_hex'],MAX_BODY_BYTES)
            if not raw:raise ValueError('empty native body')
            if not isinstance(row['metadata'],dict):raise ValueError('native body metadata missing')
            metadata.append(row['metadata']);keys.append(row['metadata'].get('id'if name=='pool'else'vtxo_id'))
            if name=='pending_boards'and(not isinstance(row['anchor_point'],str)or not row['anchor_point']):raise ValueError('pending original anchor missing')
            if name=='pool'and row['spent_at']is not None and not isinstance(row['spent_at'],str):raise ValueError('native pool spent state malformed')
        if any(k is None for k in keys)or len(set(keys))!=len(keys):raise ValueError('native body source membership duplicate')
        if metadata!=public_rows[name]:raise ValueError('native body/public19 exact membership or metadata differs')
    rows=pg['pool_retirements']
    if not isinstance(rows,list)or len(rows)!=preflight['pool_retirements']:raise ValueError('retirement count differs')
    registered={v['metadata']['vtxo_id']for v in pg['coins']}
    pools={v['metadata']['vtxo_id']:v for v in pg['pool']}
    seen=[]
    for row in rows:
        if (not isinstance(row,dict)or set(row)!={'vtxo_id','pool_input_id'}
                or not all(isinstance(v,str)and v for v in row.values())
                or row['vtxo_id']not in registered or row['pool_input_id']not in registered
                or row['pool_input_id']not in pools or pools[row['pool_input_id']]['spent_at']is None):
            raise ValueError('retirement closure input missing or unspent')
        seen.append(row['vtxo_id'])
    if seen!=sorted(set(seen)):raise ValueError('retirement closure ordering or uniqueness differs')
    if len(common.canonical(pg).encode())>MAX_BYTES:raise ValueError('whole native body reply exceeds bound')
    return pg


def capture(raw_connection,adapter,*,limits,binding,observation,expected_financial_pins,chain_identity):
    """Called only by authenticated, process-supervised fixed C body worker.

    Caller is trusted code, not observer JSON; raw_connection must use the NEW
    dedicated fixed role. Existing public19 source binding is retained exactly.
    This is a private body auxiliary, not current economic ownership proof.
    """
    began=time.monotonic();f=adapter.frontier();limits=f.declaration(limits);binding=f.binding(binding)
    if limits['deadline_ms']>25000:raise ValueError('existing body caller deadline cannot be raised')
    pins=common._pins(expected_financial_pins);start=chain_identity()
    common._observation({'source_observation':observation},pins,start.get('height'),start.get('tip_hash'))
    if start.get('genesis')!=common.SIGNET_GENESIS or start.get('ibd')is not False:raise ValueError('independent Signet identity required')
    if binding['schema_sha256']!=pins['schema_sha256']or binding['genesis']!=start['genesis']or binding['network']!='signet'or binding['database']!='trackc':raise ValueError('body source binding/pins differ')
    deadline=began+limits['deadline_ms']/1000;private=[];sizes=[];lines=[]
    class BodyConnection(adapter._FixedConnection):
        def execute(self,sql):
            super().execute(sql)
            if sql==f.IDENTITY_SQL and not private:
                size=common._pg_query(self.raw,PREFLIGHT_SQL);_preflight(size);self.check()
                private.append(common._pg_query(self.raw,PRIVATE_SQL));sizes.append(size);self.check()
    connection=BodyConnection(raw_connection,f,limits,deadline,time.monotonic)
    f.produce(connection,limits,binding,lines.append)
    if chain_identity()!=start or time.monotonic()>=deadline:raise ValueError('body source chain/deadline changed')
    if len(private)!=1:raise ValueError('body original was not captured in single RR transaction')
    header=f.strict_json(lines[0]);public_rows={name:[]for name in f.projections()}
    for raw in lines:
        frame=f.strict_json(raw)
        if frame['kind']=='page':public_rows[frame['table']].extend(frame['rows'])
    pg=_assemble(private[0],header,public_rows,sizes[0])
    return {'schema_version':1,'kind':'c-native-body-private-cut','private_pg':common.canonical(pg).encode(),
      'public_lines':lines,'financial_pins':pins,'source_observation':observation,'chain':start,
      'source_sha256':common.digest(Path(__file__).read_bytes()),'preflight':sizes[0],
      'scope':'private native body originals and same-RR public19 only; no ownership, paid, readiness or producer-exit authority'}
