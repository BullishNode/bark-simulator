"""Retain the deployed bridge's bounded log tails without inventing cursors.

Every capture and repeated line occurrence is preserved. A capture sequence is
local recorder ordering, never a daemon event ID or completeness watermark.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import json
import math
import time
from .model import canonical,integer
from .log_producer import checked_log
from .process import json_command

SCHEMA='''CREATE TABLE IF NOT EXISTS target_log_window(
 source TEXT NOT NULL,capture_sequence INTEGER NOT NULL,from_utc TEXT NOT NULL,
 until_utc TEXT NOT NULL,response_sha256 TEXT NOT NULL,trace_reference TEXT NOT NULL,
 PRIMARY KEY(source,capture_sequence));'''


def utc(value):
    if not isinstance(value,str) or len(value)>64:raise ValueError('bounded UTC window required')
    parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None or parsed.utcoffset()!=dt.timedelta(0):raise ValueError('UTC offset required')
    return parsed.timestamp()


def validate(request,response):
    fields={'kind','service','from_utc','until_utc','tail','max_bytes','source_bytes',
            'truncated','timed_out','lines','complete','validation_scope'}
    if not isinstance(response,dict) or set(response)!=fields:raise ValueError('bounded window shape differs')
    if any(response[key]!=request[key] for key in ('kind','service','tail','max_bytes')):raise ValueError('window request echo differs')
    if response['complete'] is not False or any(type(response[key]) is not bool for key in ('truncated','timed_out')):
        raise ValueError('tail cannot claim complete coverage')
    size=integer(response['source_bytes'],'producer source bytes')
    if size>request['max_bytes']:raise ValueError('producer exceeded source byte bound')
    if not isinstance(response['validation_scope'],str) or len(response['validation_scope'])>512:
        raise ValueError('bounded producer scope required')
    start,end=utc(response['from_utc']),utc(response['until_utc'])
    if not 0<=end-start<=request['seconds']+1:raise ValueError('producer window bounds differ')
    if not isinstance(response['lines'],list) or len(response['lines'])>request['tail'] or any(not isinstance(line,str) for line in response['lines']):
        raise ValueError('bounded returned lines required')
    if len(canonical(response).encode())>6*request['max_bytes']+8192:raise ValueError('serialized window exceeded bound')
    return start,end


async def collect_window(store,source,*,command=None,maximum_bytes=131072,now=None):
    from .log_capture import _gap
    store.db.execute(SCHEMA)
    if store.trace is None:return {'gap':_gap(store,source,'trace_capture_disabled')}
    bound=integer(maximum_bytes,'log byte bound',1)
    if not 4096<=bound<=262144:return {'gap':_gap(store,source,'unsupported_window_bound')}
    if source.component not in {'captaind','watchmand'} or not source.command:
        return {'gap':_gap(store,source,'producer_not_configured')}
    declaration={'kind':'target_window','component':source.component,'since_us':source.since_us,'protocol':'window_tail'}
    key='log_capture_declaration:'+source.name
    old=store.get_meta(key)
    if old is not None and json.loads(old)!=declaration:return {'gap':_gap(store,source,'declaration_changed')}
    started=time.time() if now is None else now
    previous=json.loads(store.get_meta('log_capture_last_window:'+source.name) or 'null')
    seconds=300
    if previous:seconds=min(86400,max(300,math.ceil(max(0,started-utc(previous['until_utc'])))+180))
    request={'kind':'logs','service':source.component,'seconds':seconds,'tail':1000,'max_bytes':bound}
    store.trace_capture('log.producer.call',{'source':source.name,'phase':'request','request':request,'caller_started_at':started})
    try:
        if command is not None:response=await command(source.command,request)
        else:
            def capture(kind):
                def callback(record):
                    raw=record['raw']
                    try:checked_log(raw.decode('utf-8'))
                    except (ValueError,UnicodeError):
                        store.trace_capture(kind,{'source':source.name,'redacted':True,'bytes':record['bytes']});return
                    store.trace_capture(kind,{'source':source.name,**{key:value for key,value in record.items() if key!='raw'}},raw=raw)
                return callback
            response=await json_command(list(source.command),request,timeout=45,
                on_stdout_raw=capture('log.producer.stdout'),on_stderr_raw=capture('log.producer.stderr'))
    except Exception as error:
        return {'gap':_gap(store,source,'producer_unavailable',details={'error_type':type(error).__name__})}
    try:start,end=validate(request,response)
    except (ValueError,TypeError,KeyError,UnicodeError,OverflowError):
        store.trace_capture('log.producer.rejected',{'source':source.name,'reason':'invalid_window_response'})
        return {'gap':_gap(store,source,'invalid_producer_response')}
    finished=time.time() if now is None else now
    lines=[]
    for index,line in enumerate(response['lines']):
        try:checked_log(line)
        except (ValueError,UnicodeError):lines.append({'line_index':index,'redacted':True,'bytes':len(line.encode())})
        else:lines.append({'line_index':index,'redacted':False,'returned_line':line})
    safe={**response,'lines':lines}
    try:checked_log(safe)
    except (ValueError,UnicodeError):return {'gap':_gap(store,source,'invalid_public_metadata')}
    gaps=['source_identity_unavailable','tail_coverage_unknown']
    if response['truncated']:gaps.append('byte_truncated')
    if response['timed_out']:gaps.append('producer_timeout')
    if len(lines)==request['tail']:gaps.append('tail_limit_reached')
    if previous and start>utc(previous['until_utc']):gaps.append('window_bound_gap')
    if previous and end<utc(previous['until_utc']):gaps.append('producer_clock_regressed')
    if not previous and start>source.since_us/1000000:gaps.append('historical_opening_gap')
    if end>finished+90 or end<started-seconds-90:gaps.append('producer_clock_mismatch')
    sequence=store.db.execute('SELECT coalesce(max(capture_sequence),0)+1 FROM target_log_window WHERE source=?',(source.name,)).fetchone()[0]
    payload={'source':source.name,'component':source.component,'capture_sequence':sequence,'request':request,'response':safe,
        'caller_started_at':started,'caller_finished_at':finished,'gaps':gaps,'producer_incarnation':None,'complete':False,
        'scope':'exact returned public window; bridge lines may be redacted/reserialized; local capture order is not a producer cursor'}
    reference=store.trace_capture('target.log.window',payload)
    if reference is None:return {'gap':_gap(store,source,'trace_capture_unavailable')}
    for line in lines:
        item={'source':source.name,'component':source.component,'capture_sequence':sequence,**line,
            'from_utc':response['from_utc'],'until_utc':response['until_utc'],'producer_incarnation':None,
            'scope':'per-capture returned occurrence; repeated lines across windows may reobserve events; no event uniqueness claim'}
        if not line['redacted']:item['line_sha256']=hashlib.sha256(line['returned_line'].encode()).hexdigest()
        if store.trace_capture('target.log',item) is None:return {'gap':_gap(store,source,'trace_capture_unavailable')}
    with store.transaction():
        store.db.execute('INSERT INTO target_log_window VALUES (?,?,?,?,?,?)',(source.name,sequence,response['from_utc'],response['until_utc'],hashlib.sha256(canonical(safe).encode()).hexdigest(),canonical(reference)))
        store.db.execute('INSERT OR IGNORE INTO meta VALUES (?,?)',(key,canonical(declaration)))
        if not previous or end>=utc(previous['until_utc']):
            store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('log_capture_last_window:'+source.name,canonical({'from_utc':response['from_utc'],'until_utc':response['until_utc']})))
        store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('log_capture_last_observed:'+source.name,str(finished)))
        store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('log_capture_gap:'+source.name,canonical({'kind':'window_coverage_unknown','source':source.name,'details':{'gaps':gaps}})))
        if any(kind in gaps for kind in ('window_bound_gap','historical_opening_gap','producer_clock_regressed','byte_truncated','producer_timeout','tail_limit_reached')):
            store.db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('log_capture_continuity_gap:'+source.name,canonical({'kind':'bounded_window_history_gap','source':source.name,'gaps':gaps})))
    return {'rows':len(lines),'capture_sequence':sequence,'trace_reference':reference,'gaps':gaps,'complete':False,'gap':None}
