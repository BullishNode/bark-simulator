"""Public log collection with durable cursors, deduplication and named gaps.

A producer request is read-only. Diagnostic rows never create client actions,
wallet observations, payments, funding or customer traffic credit.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass
import hashlib
import json
import re
import time
from .model import canonical,integer,public_payload
from .process import json_command
from .log_producer import validate_request,collect_journal,checked_log,MAX_BYTES,MAX_ROWS

SERVICE_UNITS={'simulator':'abandon-simulation-client-setup.service','observer':'simulation-observer.service'}
SCHEMA='''CREATE TABLE IF NOT EXISTS log_capture_record(
 source TEXT NOT NULL,identity TEXT NOT NULL,digest TEXT NOT NULL,trace_reference TEXT,
 PRIMARY KEY(source,identity));'''


@dataclass(frozen=True)
class LogSource:
    name:str
    kind:str
    component:str
    command:tuple[str,...]
    since_us:int
    def __post_init__(self):
        if not isinstance(self.name,str) or re.fullmatch('[A-Za-z0-9_.-]{1,80}',self.name) is None:raise ValueError('invalid declared log source')
        public_payload(self.name);integer(self.since_us,'log opening UTC')
        allowed={'captaind','watchmand'} if self.kind in {'target','target_window'} else set(SERVICE_UNITS)
        if self.kind not in {'target','target_window','service'} or self.component not in allowed:raise ValueError('unsupported declared log component')
        if not isinstance(self.command,tuple) or any(not isinstance(v,str) or '\x00' in v for v in self.command):raise ValueError('log command must be an argument tuple')
        if self.kind=='service' and self.command:raise ValueError('service logs use a fixed local journal producer')


def _gap(store,source,kind,*,details=None):
    value={'kind':kind,'source':source.name,'component':source.component}
    if details:value['details']=details
    public_payload(value);key='log_capture_gap:'+source.name;encoded=canonical(value)
    if store.get_meta(key)!=encoded:
        store.trace_capture('log.capture.gap',value)
        store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',(key,encoded))
    return value


def _checked_response(source,request,response):
    if (not isinstance(response,dict) or set(response)!={'schema_version','kind','component','source_id','rows','next_cursor','more','gap'}
            or response['schema_version']!=1 or response['kind']!='logs' or response['component']!=source.component
            or type(response['more']) is not bool or not isinstance(response['rows'],list)):
        raise ValueError('producer response shape/identity differs')
    checked_log(response)
    if len(canonical(response).encode())>request['maximum_bytes'] or len(response['rows'])>request['limit']:
        raise ValueError('producer exceeded declared page bound')
    identity=response['source_id']
    if not isinstance(identity,str) or re.fullmatch('[A-Za-z0-9:._-]{1,160}',identity) is None:raise ValueError('invalid producer identity')
    next_cursor=response['next_cursor']
    if next_cursor is not None:
        validate_request({**request,'cursor':next_cursor},{source.component})
        if next_cursor['source_id']!=identity:raise ValueError('next cursor has another source identity')
    gap=response['gap']
    if gap is not None and (not isinstance(gap,dict) or set(gap)!={'kind','continuity_lost'}
            or not isinstance(gap['kind'],str) or type(gap['continuity_lost']) is not bool):raise ValueError('invalid producer gap')
    previous=request['cursor'];last=previous if previous and previous['source_id']==identity else None;rows=[]
    if previous and previous['source_id']!=identity and (not gap or gap['kind']!='source_replaced' or response['rows']):
        raise ValueError('producer silently replaced source')
    for row in response['rows']:
        if not isinstance(row,dict) or not {'utc_us','ordinal','stream','cursor','redacted'}<=set(row):raise ValueError('incomplete public log row')
        if type(row['redacted']) is not bool:raise ValueError('invalid redaction flag')
        fields={'utc_us','ordinal','stream','cursor','redacted','reason'} if row['redacted'] else {'utc_us','ordinal','stream','cursor','redacted','text','raw_line'}
        if set(row)!=fields:raise ValueError('public log row fields differ')
        if row['stream'] not in {'stdout','stderr','combined','service'}:raise ValueError('invalid log stream')
        cursor=row['cursor'];validate_request({**request,'cursor':cursor},{source.component})
        if (cursor['source_id'],cursor['utc_us'],cursor['ordinal'])!=(identity,row['utc_us'],row['ordinal']):raise ValueError('log row cursor differs')
        integer(cursor['ordinal'],'captured log ordinal',1)
        if (last is None or cursor['utc_us']>last['utc_us']) and cursor['ordinal']!=1:raise ValueError('new log timestamp bucket skipped its prefix')
        if last and (cursor['utc_us'],cursor['ordinal'])<=(last['utc_us'],last['ordinal']):raise ValueError('log row cursor does not advance')
        if last and cursor['utc_us']==last['utc_us'] and cursor['ordinal']!=last['ordinal']+1:raise ValueError('same timestamp log ordinal skipped')
        if not row['redacted'] and (not isinstance(row['text'],str) or not isinstance(row['raw_line'],str)):raise ValueError('public raw log text absent')
        rows.append(row);last=cursor
    if rows and next_cursor!=rows[-1]['cursor']:raise ValueError('page cursor skipped beyond captured logs')
    if not rows and previous and next_cursor!=previous:
        if not gap or not gap['continuity_lost'] or next_cursor is None or next_cursor['ordinal']!=0:
            raise ValueError('empty page silently advanced cursor')
    return rows


async def collect_source(store,source,*,command=None,limit=64,maximum_bytes=131072):
    if source.kind=='target_window':
        from .target_log_window import collect_window
        return await collect_window(store,source,command=command,maximum_bytes=maximum_bytes)
    store.db.executescript(SCHEMA)
    if store.trace is None:return {'gap':_gap(store,source,'trace_capture_disabled')}
    declaration={'kind':source.kind,'component':source.component,'since_us':source.since_us};key='log_capture_declaration:'+source.name
    if store.get_meta(key) is None:
        store.db.execute('INSERT INTO meta VALUES (?,?)',(key,canonical(declaration)))
        store.trace_capture('log.capture.declared',{'source':source.name,**declaration,'scope':'public diagnostic producer; continuity and live availability must be separately observed'})
    elif json.loads(store.get_meta(key))!=declaration:return {'gap':_gap(store,source,'declaration_changed')}
    cursor=json.loads(store.get_meta('log_capture_cursor:'+source.name) or 'null')
    request=validate_request({'kind':'logs','component':source.component,'since_us':source.since_us,'cursor':cursor,
        'limit':limit,'maximum_bytes':maximum_bytes},{source.component})
    if source.kind=='target' and not source.command:return {'gap':_gap(store,source,'producer_not_configured')}
    store.trace_capture('log.producer.call',{'source':source.name,'phase':'request','request':request},raw=canonical(request).encode())
    try:
        if command is not None:response=await command(source.command,request)
        elif source.kind=='service':response=await asyncio.to_thread(collect_journal,request,SERVICE_UNITS)
        else:
            def capture(kind):
                def callback(record):
                    try:checked_log(record['raw'].decode('utf-8'))
                    except (ValueError,UnicodeError):
                        store.trace_capture(kind,{'source':source.name,'redacted':True});return
                    store.trace_capture(kind,{'source':source.name,**{k:v for k,v in record.items() if k!='raw'}},raw=record['raw'])
                return callback
            response=await json_command(list(source.command),request,timeout=12,
                on_stdout_raw=capture('log.producer.stdout'),on_stderr_raw=capture('log.producer.stderr'))
    except Exception as error:return {'gap':_gap(store,source,'producer_unavailable',details={'error_type':type(error).__name__})}
    try:rows=_checked_response(source,request,response)
    except (ValueError,TypeError,KeyError,UnicodeError):
        store.trace_capture('log.producer.rejected',{'source':source.name,'redacted':True})
        return {'gap':_gap(store,source,'invalid_producer_response')}
    store.trace_capture('log.producer.call',{'source':source.name,'phase':'response','response':response})
    inserted=0
    for row in rows:
        identity=canonical(row['cursor']);digest=hashlib.sha256(canonical(row).encode()).hexdigest()
        old=store.db.execute('SELECT digest FROM log_capture_record WHERE source=? AND identity=?',(source.name,identity)).fetchone()
        if old:
            if old['digest']!=digest:return {'gap':_gap(store,source,'replayed_log_record_changed')}
            continue
        payload={'source':source.name,'component':source.component,'source_id':response['source_id'],**row}
        reference=store.trace_capture('target.log' if source.kind=='target' else 'service.log',payload,
            raw=row.get('raw_line','').encode() if not row['redacted'] else None)
        if reference is None:return {'gap':_gap(store,source,'trace_capture_unavailable')}
        store.db.execute('INSERT INTO log_capture_record VALUES (?,?,?,?)',(source.name,identity,digest,canonical(reference)));inserted+=1
    if response['gap']:
        value=_gap(store,source,response['gap']['kind'],details={'continuity_lost':response['gap']['continuity_lost']})
        if response['gap']['continuity_lost']:
            store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('log_capture_continuity_gap:'+source.name,canonical(value)))
    else:store.db.execute('DELETE FROM meta WHERE key=?',('log_capture_gap:'+source.name,))
    store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('log_capture_last_observed:'+source.name,str(time.time())))
    if response['next_cursor'] is not None:
        store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('log_capture_cursor:'+source.name,canonical(response['next_cursor'])))
    return {'rows':inserted,'cursor':response['next_cursor'],'more':response['more'],'gap':response['gap']}


async def collect_sources(store,sources,*,limit=64,maximum_bytes=131072):
    """Independent producers may run together; all state commits stay serialized."""
    if len(sources)>8 or len({source.name for source in sources})!=len(sources):raise ValueError('bounded unique log sources required')
    values=await asyncio.gather(*(collect_source(store,source,limit=limit,maximum_bytes=maximum_bytes) for source in sources),return_exceptions=True)
    result={}
    for source,value in zip(sources,values):
        result[source.name]=({'gap':_gap(store,source,'collector_unavailable',details={'error_type':type(value).__name__})}
            if isinstance(value,Exception) else value)
    return result


def report(store):
    sources=[]
    for row in store.db.execute("SELECT key,value FROM meta WHERE key LIKE 'log_capture_declaration:%' ORDER BY key"):
        name=row['key'].split(':',1)[1]
        def metadata(prefix):return json.loads(store.get_meta(prefix+name) or 'null')
        sources.append({'name':name,**json.loads(row['value']),'cursor':metadata('log_capture_cursor:'),
            'last_observed_at':metadata('log_capture_last_observed:'),
            'last_window':metadata('log_capture_last_window:'),
            'current_gap':metadata('log_capture_gap:'),'continuity_gap':metadata('log_capture_continuity_gap:')})
    return {'sources':sources,'complete':False,
        'unknowns':[{'bucket':'log_producer_availability','reason':'no sources declared or live producer installation/permission/retention gates remain unqualified'}],
        'scope':'bounded diagnostic observations; source availability, history before the declared opening, rotation/ordering gaps and live producer installation remain separately qualified'}


def configured_sources(store,config):
    """Freeze the declared capture opening once; no historical completeness claim."""
    if not config.log_target_enabled and not config.log_local_sources:return []
    opening=store.get_meta('log_capture_opening_us')
    if opening is None:
        if config.log_since_us is not None:opening=config.log_since_us;basis='explicit configuration'
        else:
            row=store.db.execute("SELECT observed_at FROM event WHERE kind='real_campaign_started' ORDER BY sequence LIMIT 1").fetchone()
            if row is None:row=store.db.execute('SELECT observed_at FROM snapshot ORDER BY id LIMIT 1').fetchone()
            if row is None:raise ValueError('capture opening lacks campaign or snapshot observation')
            opening=int(row[0]*1000000);basis='recorded campaign/snapshot opening'
        integer(opening,'frozen log opening UTC')
        store.db.execute("INSERT INTO meta VALUES ('log_capture_opening_us',?)",(str(opening),))
        store.trace_capture('log.capture.opening',{'since_us':opening,'basis':basis,
            'scope':'declared beginning only; retained producer history and every subsequent continuity interval require evidence'})
    else:
        opening=int(opening)
        if config.log_since_us is not None and config.log_since_us!=opening:raise ValueError('frozen log opening changed')
    sources=[LogSource('target-'+component,'target_window',component,config.inventory_command,opening)
        for component in ('captaind','watchmand')] if config.log_target_enabled else []
    return sources+[LogSource('service-'+component,'service',component,(),opening) for component in config.log_local_sources]
