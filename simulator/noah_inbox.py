"""Source-pinned authenticated pull inbox; fetching never executes a job."""
from __future__ import annotations

import hashlib
import json
import math
import re
import uuid

from .model import canonical,integer
from .noah import _hex,_reference

SPOOL_SHA256='409d5c2331f36a678a7fd4a6bcefcf613acfd99020fc235105cf5ed0e3c8342a'
NGINX_SHA256='4bf092c6772888edbf44da03bb6e6203a58ab2646163e06cfb1f83ff78025dc0'
SCHEMA='''CREATE TABLE IF NOT EXISTS noah_inbox_token(
 actor TEXT PRIMARY KEY,artifact TEXT NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS noah_inbox_cursor(actor TEXT PRIMARY KEY,cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS noah_inbox(
 actor TEXT NOT NULL,cursor INTEGER NOT NULL,digest TEXT NOT NULL,
 artifact TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(actor,cursor));'''


class NoahTokenProvider:
    """Private login callback with an auditable immutable transport declaration."""
    def __init__(self,inbox,actor):self.inbox=inbox;self.actor=actor
    def declaration(self):
        self.inbox._ready(self.actor)
        return {'protocol':'opaque_native_auth','actor':self.actor,'qualification':self.inbox.qualification}
    async def __call__(self,bearer):return await self.inbox.token(self.actor,bearer)


class NoahInbox:
    def __init__(self,adapter,qualification):
        self.adapter=adapter;self.store=adapter.store;self.qualification=qualification
        self.store.db.executescript(SCHEMA)

    def provider(self,actor):return NoahTokenProvider(self,actor)

    def _ready(self,actor):
        self.adapter._phone(actor,require_online=True,enrollment=True)
        observed=_reference(self.store,self.qualification,'noah.phone.transport')
        expected={'verified':True,'method':'independent_transport_audit',
            'https_origin':self.adapter.manifest['origin']['https_origin'],
            'spool_source_sha256':SPOOL_SHA256,'nginx_sha256':NGINX_SHA256,
            'token_mode':'opaque_native_auth','pull_path':'/test/phone/pushes','token_path':'/test/phone/token'}
        if set(observed)!={*expected,'backend_manifest_sha256'} or any(observed.get(k)!=v for k,v in expected.items()):
            raise ValueError('independent phone transport contract differs')
        _hex(observed['backend_manifest_sha256'])
        encoded=canonical(observed);key='noah_phone_transport'
        previous=self.store.get_meta(key)
        if previous is not None and previous!=encoded:raise ValueError('immutable phone transport changed')
        if previous is None:
            with self.store.transaction():
                self.store.db.execute('INSERT INTO meta VALUES (?,?)',(key,encoded))
                self.store._event('noah_phone_transport_declared',{'qualification':self.qualification,
                    'contract_sha256':hashlib.sha256(encoded.encode()).hexdigest(),'qualification_limit':'authenticated transport only'})

    async def token(self,actor,bearer):
        """Private callback for enrollment, before register_push_token."""
        self._ready(actor)
        if not isinstance(bearer,str) or not bearer or len(bearer.encode())>8000:raise ValueError('bounded native login bearer required')
        reply=await self.adapter._request('POST','/test/phone/token',{'cursor':0,'limit':20},bearer,actor=actor,enrollment=True)
        token=reply.get('push_token')
        if set(reply)!={'push_token'} or not isinstance(token,str) or re.fullmatch(r'ExpoPushToken\[[A-Za-z0-9_-]{1,100}\]',token) is None:
            raise ValueError('native-authenticated device token differs')
        digest=hashlib.sha256(token.encode()).hexdigest()
        artifact=self.adapter.protect('inbox.token',{'push_token':token},actor=actor)
        with self.store.transaction():
            row=self.store.db.execute('SELECT digest FROM noah_inbox_token WHERE actor=?',(actor,)).fetchone()
            if row and row['digest']!=digest:raise ValueError('immutable private device token changed')
            self.store.db.execute('INSERT OR IGNORE INTO noah_inbox_token VALUES (?,?,?)',(actor,canonical(artifact),digest))
            self.store._event('noah_phone_token_observed',{'actor':actor,'token_sha256':digest,'artifact':artifact})
        return token

    def _token(self,actor):
        row=self.store.db.execute('SELECT * FROM noah_inbox_token WHERE actor=?',(actor,)).fetchone()
        if row is None:raise ValueError('native phone token not privately enrolled')
        document=self.adapter.read_protected(json.loads(row['artifact']),kind='inbox.token',actor=actor)
        token=document['payload']['push_token']
        if not isinstance(token,str) or hashlib.sha256(token.encode()).hexdigest()!=row['digest']:raise ValueError('private token hash differs')
        return token

    def cursor(self,actor):
        row=self.store.db.execute('SELECT cursor FROM noah_inbox_cursor WHERE actor=?',(actor,)).fetchone()
        return row['cursor'] if row else 0

    def pending(self,actor):
        return [dict(row) for row in self.store.db.execute("SELECT cursor,digest,artifact,state FROM noah_inbox WHERE actor=? AND state='pending' ORDER BY cursor",(actor,))]

    def original(self,actor,cursor):
        row=self.store.db.execute('SELECT * FROM noah_inbox WHERE actor=? AND cursor=?',(actor,cursor)).fetchone()
        if row is None:raise ValueError('captured original record missing')
        document=self.adapter.read_protected(json.loads(row['artifact']),kind='inbox.record',actor=actor)
        record=document['payload']['decoded_original_record']
        if hashlib.sha256(canonical(record).encode()).hexdigest()!=row['digest'] or record['cursor']!=cursor:
            raise ValueError('captured original record hash differs')
        return record

    async def pull(self,actor,*,limit=20):
        self._ready(actor);integer(limit,'phone page limit',1)
        if limit>20:raise ValueError('phone page limit exceeds source bound')
        session=self.adapter._sessions.get(actor)
        if session is None or session[1]<=self.adapter.clock():raise ValueError('native login session absent or expired')
        token=self._token(actor);before=self.cursor(actor)
        page=await self.adapter._request('POST','/test/phone/pushes',{'cursor':before,'limit':limit},session[0],actor=actor,enrollment=True)
        if (set(page)!={'records','cursor','has_more','scope'} or not isinstance(page['records'],list)
                or len(page['records'])>limit or type(page['has_more']) is not bool):raise ValueError('bounded original phone page required')
        after=integer(page['cursor'],'returned phone cursor',0)
        if after>=2**63:raise ValueError('returned cursor exceeds source bound')
        staged=[];previous=before
        for record in page['records']:
            artifact=self.adapter.protect('inbox.record',{'decoded_original_record':record,
                'representation':'actual decoded original spool record; HTTP response bytes retained separately'},actor=actor)
            if not isinstance(record,dict) or set(record)!={'cursor','ticket','accepted_at','payload'}:raise ValueError('original record fields differ')
            cursor=integer(record['cursor'],'original row cursor',previous+1)
            if cursor>=2**63 or not isinstance(record['ticket'],str) or str(uuid.UUID(record['ticket']))!=record['ticket']:
                raise ValueError('original cursor or provider ticket invalid')
            stamp=record['accepted_at']
            if type(stamp) not in (int,float) or not math.isfinite(stamp) or stamp<0:raise ValueError('original accepted time invalid')
            envelope=record['payload']
            if not isinstance(envelope,dict) or envelope.get('to')!=[token]:raise ValueError('original record belongs to another device')
            digest=hashlib.sha256(canonical(record).encode()).hexdigest();staged.append((cursor,digest,artifact));previous=cursor
        if after!=previous or (page['has_more'] and not staged):raise ValueError('phone cursor or continuation differs from captured records')
        with self.store.transaction():
            # An overlapping consumer must not race the durable page boundary.
            if self.cursor(actor)!=before:raise ValueError('phone cursor changed during fetch; held original page retained')
            for cursor,digest,artifact in staged:
                self.store.db.execute("INSERT INTO noah_inbox VALUES (?,?,?,?,'pending')",(actor,cursor,digest,canonical(artifact)))
                self.store._event('noah_original_phone_record',{'actor':actor,'cursor':cursor,'record_sha256':digest,
                    'artifact':artifact,'state':'pending','qualification':'transport received; no native job or financial outcome'})
            self.store.db.execute('INSERT INTO noah_inbox_cursor VALUES (?,?) ON CONFLICT(actor) DO UPDATE SET cursor=excluded.cursor',(actor,after))
            self.store._event('noah_phone_cursor',{'actor':actor,'before':before,'after':after,'records':len(staged)})
        return {'cursor':after,'has_more':page['has_more'],'records':len(staged),'outcome_verified':False}
