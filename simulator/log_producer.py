"""Bounded read-only daemon/service log pages with explicit continuity gaps."""
from __future__ import annotations
import datetime as dt
import json
import re
from .model import canonical,integer,public_payload

MAX_ROWS=256
MAX_BYTES=262144
MAX_SCAN=4096
CURSOR_FIELDS={'source_id','utc_us','ordinal','token'}


def validate_request(value,components):
    if not isinstance(value,dict) or set(value)!={'kind','component','since_us','cursor','limit','maximum_bytes'}:
        raise ValueError('complete bounded log request required')
    if value['kind']!='logs' or value['component'] not in components:raise ValueError('unsupported log component')
    integer(value['since_us'],'declared log opening UTC')
    limit=integer(value['limit'],'log page rows',1);bound=integer(value['maximum_bytes'],'log page bytes',1024)
    if limit>MAX_ROWS or bound>MAX_BYTES:raise ValueError('log page resource bound')
    cursor=value['cursor']
    if cursor is not None:
        if not isinstance(cursor,dict) or set(cursor)-CURSOR_FIELDS or not {'source_id','utc_us','ordinal'}<=set(cursor):
            raise ValueError('invalid log cursor')
        if not isinstance(cursor['source_id'],str) or re.fullmatch('[A-Za-z0-9:._-]{1,160}',cursor['source_id']) is None:
            raise ValueError('invalid log source identity')
        integer(cursor['utc_us'],'log cursor time');integer(cursor['ordinal'],'log cursor ordinal')
        if cursor['ordinal']>MAX_SCAN:raise ValueError('log cursor timestamp bucket exceeds bound')
        if 'token' in cursor and (not isinstance(cursor['token'],str) or re.fullmatch('[A-Za-z0-9_=;:.-]{1,512}',cursor['token']) is None):
            raise ValueError('invalid native log cursor')
        if cursor['utc_us']<value['since_us']:raise ValueError('log cursor precedes declared opening')
    return value


def checked_log(value):
    """Also inspect nested JSON text; quoted structured seed fields are private."""
    public_payload(value)
    if isinstance(value,dict):
        for key,item in value.items():
            if key.lower()=='seed' and isinstance(item,str) and re.fullmatch('[0-9a-fA-F]{64}',item):
                raise ValueError('private structured seed')
            checked_log(item)
    elif isinstance(value,list):
        for item in value:checked_log(item)
    elif isinstance(value,str) and value.lstrip().startswith(('{','[')):
        try:parsed=json.loads(value)
        except ValueError:return
        checked_log(parsed)


def page_records(request,records,*,source_id,after_native_cursor=False):
    """Read a head page. Inclusive Docker replay uses ordinal at equal UTC.

    Native journal cursors already exclude old records. A missing replay bucket
    or producer generation requires an explicit continuity reset, never silent
    tailing. Record ordinals include private redactions, so they remain resumable.
    """
    request=validate_request(request,{request.get('component')})
    if not isinstance(source_id,str) or re.fullmatch('[A-Za-z0-9:._-]{1,160}',source_id) is None:raise ValueError('invalid producer identity')
    cursor=request['cursor'];rows=[];next_cursor=cursor;more=False;gap=None
    if cursor and cursor['source_id']!=source_id:
        return {'schema_version':1,'kind':'logs','component':request['component'],'source_id':source_id,'rows':[],
            'next_cursor':{'source_id':source_id,'utc_us':cursor['utc_us'],'ordinal':0},'more':True,
            'gap':{'kind':'source_replaced','continuity_lost':True}}
    last=None;ordinal=0;seen_cursor=not cursor or cursor['ordinal']==0 or after_native_cursor
    for examined,record in enumerate(records,1):
        if examined>MAX_SCAN:gap={'kind':'scan_bound','continuity_lost':False};more=True;break
        utc=integer(record['utc_us'],'log UTC')
        if last is not None and utc<last:gap={'kind':'nonmonotonic_log_order','continuity_lost':True};more=True;break
        ordinal=ordinal+1 if utc==last else (cursor['ordinal']+1 if after_native_cursor and cursor and utc==cursor['utc_us'] and last is None else 1)
        last=utc
        if utc<request['since_us']:continue
        if cursor and not after_native_cursor:
            if utc<cursor['utc_us']:continue
            if utc==cursor['utc_us'] and ordinal<=cursor['ordinal']:
                if ordinal==cursor['ordinal']:seen_cursor=True
                continue
            if not seen_cursor:
                gap={'kind':'cursor_missing','continuity_lost':True};more=True;break
        new_cursor={'source_id':source_id,'utc_us':utc,'ordinal':ordinal}
        if after_native_cursor:
            token=record.get('cursor')
            if not isinstance(token,str) or re.fullmatch('[A-Za-z0-9_=;:.-]{1,512}',token) is None:raise ValueError('native journal cursor absent')
            new_cursor['token']=token
        item={'utc_us':utc,'ordinal':ordinal,'stream':record['stream'],'cursor':new_cursor}
        if item['stream'] not in {'stdout','stderr','combined','service'}:raise ValueError('unsupported log stream')
        try:
            text=record['text']
            if not isinstance(text,str):raise ValueError('nontext log')
            checked_log(text);raw=record.get('raw_line',text);checked_log(raw)
            item.update(text=text,raw_line=raw,redacted=False)
        except (ValueError,UnicodeError):item.update(redacted=True,reason='private_or_invalid_log')
        if len(canonical(item).encode())>request['maximum_bytes']-512:
            item={'utc_us':utc,'ordinal':ordinal,'stream':record['stream'],'cursor':new_cursor,'redacted':True,'reason':'oversized_log_record'}
        if len(rows)>=request['limit'] or len(canonical(rows+[item]).encode())>request['maximum_bytes']-512:
            more=True;break
        rows.append(item);next_cursor=new_cursor
    if cursor and not seen_cursor and gap is None:
        gap={'kind':'cursor_missing','continuity_lost':True};more=True
    if gap and gap['continuity_lost'] and not rows:
        next_cursor={'source_id':source_id,'utc_us':cursor['utc_us'] if cursor else request['since_us'],'ordinal':0}
    result={'schema_version':1,'kind':'logs','component':request['component'],'source_id':source_id,'rows':rows,
        'next_cursor':next_cursor,'more':more,'gap':gap}
    checked_log(result)
    if len(canonical(result).encode())>request['maximum_bytes']:raise ValueError('serialized log page exceeds declared bound')
    return result


def journal_command(unit,cursor,limit,*,since_us=None):
    if not isinstance(unit,str) or re.fullmatch('[A-Za-z0-9@_.-]{1,120}\\.service',unit) is None:raise ValueError('declared service required')
    integer(limit,'journal rows',1)
    if limit>MAX_ROWS:raise ValueError('journal row bound')
    argv=['journalctl','--no-pager','--quiet','--output=json','--all','--unit='+unit,'--lines=+'+str(limit+1)]
    if cursor:
        if not isinstance(cursor,str) or re.fullmatch('[A-Za-z0-9_=;:.-]{1,512}',cursor) is None:raise ValueError('invalid native journal cursor')
        argv.append('--after-cursor='+cursor)
    elif since_us is not None:
        integer(since_us,'journal opening UTC');argv.append('--since=@'+str(since_us//1000000))
    return argv


def parse_journal(line):
    value=json.loads(line)
    if not isinstance(value,dict):raise ValueError('journal record object required')
    utc=integer(int(value['__REALTIME_TIMESTAMP']),'journal UTC');token=value['__CURSOR']
    if not isinstance(token,str):raise ValueError('journal cursor absent')
    return {'utc_us':utc,'cursor':token,'stream':'service','text':value.get('MESSAGE'),'raw_line':line}


def parse_docker(line):
    stamp,separator,text=line.partition(' ')
    if not separator or re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z',stamp) is None:
        raise ValueError('timestamped Docker log required')
    value=dt.datetime.fromisoformat(stamp.replace('Z','+00:00'))
    delta=value-dt.datetime(1970,1,1,tzinfo=dt.timezone.utc)
    return {'utc_us':(delta.days*86400+delta.seconds)*1000000+delta.microseconds,
        'stream':'combined','text':text,'raw_line':line}


class ProcessRecords:
    """Bounded subprocess stream; cleanup is restricted to our own child group."""
    def __init__(self,argv,parser,*,timeout=8,maximum_input_bytes=1048576):
        self.argv,self.parser=argv,parser;self.timeout=timeout;self.maximum_input_bytes=maximum_input_bytes;self.gap=None
    def __enter__(self):
        import subprocess,time
        self.process=subprocess.Popen(self.argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        self.deadline=time.monotonic()+self.timeout;return self
    def __iter__(self):
        import os,select,time
        pending=b'';size=0
        while True:
            remaining=self.deadline-time.monotonic()
            if remaining<=0:self.gap={'kind':'producer_timeout','continuity_lost':False};return
            if not select.select([self.process.stdout],[],[],remaining)[0]:
                self.gap={'kind':'producer_timeout','continuity_lost':False};return
            chunk=os.read(self.process.stdout.fileno(),65536)
            if not chunk:
                if pending:
                    self.gap={'kind':'incomplete_log_record','continuity_lost':False};return
                if self.process.wait(timeout=1):self.gap={'kind':'producer_unavailable','continuity_lost':False}
                return
            size+=len(chunk)
            if size>self.maximum_input_bytes:self.gap={'kind':'producer_input_bound','continuity_lost':False};return
            pending+=chunk
            while b'\n' in pending:
                line,pending=pending.split(b'\n',1)
                if not line:continue
                if len(line)>MAX_BYTES:self.gap={'kind':'oversized_source_record','continuity_lost':False};return
                try:record=self.parser(line.decode('utf-8'))
                except (ValueError,UnicodeError,KeyError,TypeError):
                    self.gap={'kind':'invalid_source_record','continuity_lost':False};return
                yield record
            if len(pending)>MAX_BYTES:self.gap={'kind':'oversized_source_record','continuity_lost':False};return
    def __exit__(self,*args):
        import os,signal,subprocess
        if self.process.poll() is None:
            try:os.killpg(self.process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:os.killpg(self.process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                self.process.wait(timeout=1)
        self.process.stdout.close()


def collect_journal(request,units):
    request=validate_request(request,set(units));cursor=request['cursor'];token=cursor.get('token') if cursor else None
    if cursor and cursor['ordinal'] and token is None:raise ValueError('native journal token required for continuation')
    source='journal:'+units[request['component']]
    with ProcessRecords(journal_command(units[request['component']],token,request['limit'],since_us=request['since_us']),parse_journal) as records:
        result=page_records(request,records,source_id=source,after_native_cursor=True)
        if records.gap:result['gap']=records.gap;result['more']=True
        return result


def collect_docker(request,containers,*,run=None):
    """Fixed Docker inspect/logs calls only; request selects a declared alias."""
    import subprocess,hashlib
    request=validate_request(request,set(containers));container=containers[request['component']]
    if not isinstance(container,str) or re.fullmatch('[A-Za-z0-9_.-]{1,128}',container) is None:raise ValueError('invalid declared container')
    execute=subprocess.run if run is None else run
    inspected=execute(['sudo','-n','docker','inspect','--format','{{json .Id}} {{json .State.StartedAt}}',container],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,check=True)
    if len(inspected.stdout)>2048:raise ValueError('Docker identity response bound')
    pieces=inspected.stdout.decode().split()
    if len(pieces)!=2:raise ValueError('Docker public source identity absent')
    identifier,started=(json.loads(piece) for piece in pieces)
    if re.fullmatch('[0-9a-f]{64}',identifier) is None or not isinstance(started,str) or re.fullmatch('[0-9TZ:.-]{20,40}',started) is None:
        raise ValueError('invalid Docker public identity')
    source='docker:'+hashlib.sha256((identifier+started).encode()).hexdigest()
    cursor=request['cursor'];since=cursor['utc_us'] if cursor else request['since_us']
    # Replay the entire timestamp bucket. --tail would select the newest end and
    # skip unseen backlog. A bounded reader takes the first complete records.
    argv=['sudo','-n','docker','logs','--timestamps','--since='+str(max(0,since//1000000-1)),'--tail=all',container]
    with ProcessRecords(argv,parse_docker) as records:
        result=page_records(request,records,source_id=source)
        if records.gap:result['gap']=records.gap;result['more']=True
        return result
