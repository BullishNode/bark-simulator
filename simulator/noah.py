"""Owned Noah protocol boundary with explicit readiness and once-only intents.

Authentication material stays in private memory/transport. Payment outcomes need
independent client, node and chain evidence; a backend or SDK ACK cannot qualify
them. No operation discovers an origin, funds a phone or opens an absent wallet.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import time
from urllib.parse import urlencode,urlsplit
import uuid

from .model import SIGNET_GENESIS,canonical,integer,public_payload
from .process import decode_object,json_command
from .trace import readonly,verify_partition

NOAH_COMMIT='8e68ba5c3f032d9fd55e2f2f1f2af1441395eff0'
SECTIONS=('origin','source','chain','phones','forwarder','capital')
MAX_RESPONSE=2*1024*1024
MAX_PROTECTED=8*1024*1024
SCHEMA='''CREATE TABLE IF NOT EXISTS noah_intent(
 id TEXT PRIMARY KEY,intent TEXT NOT NULL,state TEXT NOT NULL,payment_hash TEXT UNIQUE,
 proof TEXT,result TEXT,updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS noah_push(
 actor TEXT NOT NULL,transaction_id TEXT NOT NULL,amount_msat INTEGER NOT NULL,
 state TEXT NOT NULL,payment_hash TEXT,invoice_digest TEXT,PRIMARY KEY(actor,transaction_id));'''


def _digest(value):return hashlib.sha256(value.encode()).hexdigest()


def _hex(value,length=64):
    if not isinstance(value,str) or re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is None:
        raise ValueError('noncanonical public hash')
    return value


def _pubkey(value):
    if not isinstance(value,str) or re.fullmatch('(02|03)[0-9a-f]{64}',value) is None:raise ValueError('invalid public identity')
    return value


def _origin(value):
    parsed=urlsplit(value)
    if (parsed.scheme!='https' or parsed.username or parsed.password or not parsed.hostname
            or parsed.hostname in {'noahwallet.io','www.noahwallet.io','second.tech'}
            or parsed.hostname.endswith(('.noahwallet.io','.second.tech'))
            or parsed.path or parsed.query or parsed.fragment or parsed.port not in (None,443)):
        raise ValueError('exact owned HTTPS origin required')
    if value!='https://'+parsed.hostname:raise ValueError('canonical owned origin required')
    return parsed.hostname


def _reference(store,reference,kind,*,actor=None):
    if not isinstance(reference,dict) or set(reference)!={'partition','seq','hash'}:raise ValueError('checked trace reference required')
    name=reference['partition']
    if not isinstance(name,str) or re.fullmatch(r'trace-\d{4}-\d\d-\d\d\.sqlite',name) is None:raise ValueError('invalid trace partition')
    integer(reference['seq'],'evidence sequence',1);_hex(reference['hash'])
    path=store.root/name
    if path.is_symlink() or not path.is_file():raise ValueError('missing evidence partition')
    verify_partition(path)
    connection=readonly(path)
    try:row=connection.execute('SELECT * FROM trace WHERE seq=?',(reference['seq'],)).fetchone()
    finally:connection.close()
    if row is None or row['hash']!=reference['hash'] or row['kind']!=kind or row['actor']!=actor:
        raise ValueError('evidence reference identity differs')
    return json.loads(row['payload'])


def _checked_manifest(manifest,*,enrollment=False):
    if not isinstance(manifest,dict) or set(manifest)!={'schema_version',*SECTIONS,'evidence'} or manifest['schema_version']!=1:
        raise ValueError('complete readiness manifest required')
    public_payload(manifest)
    origin=manifest['origin'];domain=_origin(origin['https_origin'])
    if origin['lnurl_domain']!=domain:raise ValueError('LNURL domain differs from owned origin')
    _hex(origin['ca_sha256'])
    source=manifest['source']
    if source['noah_commit']!=NOAH_COMMIT:raise ValueError('Noah source pin differs')
    for key in ('transport_patch_sha256','binary_sha256'):_hex(source[key])
    if 'image_sha256' in source:_hex(source['image_sha256'])
    if 'invoice_verifier_sha256' in source:_hex(source['invoice_verifier_sha256'])
    if set(source['healthy_services'])!={'backend','postgres','redis','expo'}:raise ValueError('backend service readiness missing')
    chain=manifest['chain']
    if chain['network']!='signet' or chain['genesis']!=SIGNET_GENESIS:raise ValueError('signet identity required')
    _pubkey(chain['server_pubkey']);_pubkey(chain['lightning_node_pubkey'])
    for key in ('captaind_commit','phone_sdk_commit','forwarder_sdk_commit'):_hex(chain[key],40)
    if len({chain[key] for key in ('captaind_commit','phone_sdk_commit','forwarder_sdk_commit')})!=1:
        raise ValueError('fork server and SDK pins differ')
    phones=manifest['phones']
    if not isinstance(phones,list) or not 1<=len(phones)<=200:raise ValueError('bounded declared phones required')
    actors=set();names=set();addresses=set()
    for phone in phones:
        if (set(phone)!={'actor','username','auth_pubkey','ark_address','mailbox_id','fallback_script'}
                or re.fullmatch('noah-phone-[A-Za-z0-9_-]{1,64}',phone['actor']) is None
                or re.fullmatch('[a-z0-9_.-]{2,64}',phone['username']) is None):raise ValueError('new immutable phone identity required')
        _pubkey(phone['auth_pubkey']);_pubkey(phone['mailbox_id'])
        if not isinstance(phone['ark_address'],str) or not phone['ark_address']:raise ValueError('registered Ark destination missing')
        if not isinstance(phone['fallback_script'],str) or re.fullmatch('[0-9a-f]{2,20000}',phone['fallback_script']) is None:
            raise ValueError('fallback script missing')
        if phone['actor'] in actors or phone['username'] in names or phone['ark_address'] in addresses:raise ValueError('duplicate phone identity or destination')
        actors.add(phone['actor']);names.add(phone['username']);addresses.add(phone['ark_address'])
    forwarder=manifest['forwarder']
    if type(forwarder['enabled']) is not bool or type(forwarder['ready']) is not bool:raise ValueError('forwarding mode must be explicit')
    if forwarder['enabled']:
        if not forwarder['ready'] or not isinstance(forwarder['identity'],str) or not forwarder['identity'].startswith('noah-forwarder-'):
            raise ValueError('forwarder not independently ready')
        if forwarder.get('barkd_url')!='http://noah-barkd-signet.internal:3000':raise ValueError('owned pinned signet forwarding route required')
        _pubkey(forwarder.get('auth_pubkey'));_pubkey(forwarder.get('mailbox_id'))
        if not isinstance(forwarder.get('fallback_script'),str) or re.fullmatch('[0-9a-f]{2,20000}',forwarder['fallback_script']) is None:
            raise ValueError('forwarder fallback record evidence missing')
    elif forwarder['identity'] is not None or forwarder['ready']:raise ValueError('disabled forwarder identity differs')
    capital=manifest['capital']
    if re.fullmatch('noah-capital-[A-Za-z0-9_-]{1,80}',capital['allocation_id']) is None:raise ValueError('separate explicit Noah allocation required')
    minimum=0 if enrollment else 1
    total=integer(capital['principal_sat'],'declared Noah principal',minimum)
    for key in ('per_action_fee_sat','campaign_fee_sat'):integer(capital[key],key,minimum)
    if capital['per_action_fee_sat']>capital['campaign_fee_sat']:raise ValueError('per-action fee exceeds campaign cap')
    allocations=capital['actor_principal_sat']
    if not isinstance(allocations,dict) or not actors<=set(allocations):raise ValueError('phone capital declaration missing')
    if forwarder['enabled'] and forwarder['identity'] not in allocations:raise ValueError('separate forwarder capital missing')
    if any(re.fullmatch('noah-(phone|payer|forwarder)-[A-Za-z0-9_-]{1,64}',actor) is None for actor in allocations):
        raise ValueError('old simulator capital cannot be reassigned')
    if sum(integer(value,'actor principal',minimum) for value in allocations.values())>total:raise ValueError('allocation exceeds capital')
    if set(manifest['evidence'])!=set(SECTIONS):raise ValueError('independent readiness observations missing')
    return manifest


class HTTPSNoahTransport:
    """Exact owned origin, verified TLS, no redirects or token-bearing diagnostics."""
    def __init__(self,origin,*,ca_file=None):
        self.host=_origin(origin);self.origin=origin
        ca_file=ca_file or ssl.get_default_verify_paths().cafile
        if not ca_file:raise ValueError('pinned CA trust bundle missing')
        self.ca_sha256=_digest_bytes(Path(ca_file).read_bytes())
        self.context=ssl.create_default_context(cafile=ca_file)
    async def __call__(self,method,url,body=None,bearer=None):
        if method not in {'GET','POST'} or not url.startswith(self.origin+'/'):raise ValueError('owned route required')
        parsed=urlsplit(url)
        if parsed.scheme!='https' or parsed.hostname!=self.host or parsed.netloc!=self.host or parsed.fragment:
            raise ValueError('request origin differs')
        encoded=None if body is None else canonical(body).encode()
        if encoded is not None and len(encoded)>192*1024:raise ValueError('request bound exceeded')
        headers={'Accept':'application/json'}
        if body is not None:headers['Content-Type']='application/json'
        if bearer is not None:headers['Authorization']='Bearer '+bearer
        def exchange():
            connection=http.client.HTTPSConnection(self.host,timeout=55,context=self.context)
            try:
                connection.request(method,parsed.path+('?' +parsed.query if parsed.query else ''),encoded,headers)
                response=connection.getresponse();raw=response.read(MAX_RESPONSE+1)
                headers=list(response.getheaders())
                if response.status!=200 or len(raw)>MAX_RESPONSE:raise _PrivateHTTPError(response.status,headers,raw)
                try:decoded=decode_object(raw.decode())
                except (ValueError,UnicodeError,RuntimeError):raise _PrivateHTTPError(response.status,headers,raw) from None
                return _ObservedReply(decoded,{'status':response.status,'headers':headers,
                    'body_base64':base64.b64encode(raw).decode(),'representation':'exact HTTP application response body'})
            finally:connection.close()
        return await asyncio.to_thread(exchange)


class NativeInvoiceVerifier:
    """Pin an offline verifier binary; it accepts only a public invoice and policy."""
    def __init__(self,path,sha256):
        self.path=Path(path);self.sha256=_hex(sha256)
    async def __call__(self,invoice,amount,metadata,network,now):
        if self.path.is_symlink() or _digest_bytes(self.path.read_bytes())!=self.sha256:raise ValueError('native verifier pin differs')
        observations=[]
        def capture(stream):
            def append(record):observations.append({'stream':stream,**{key:value for key,value in record.items() if key!='raw'},
                'body_base64':base64.b64encode(record['raw']).decode()})
            return append
        try:
            result=await json_command([str(self.path)],{'invoice':invoice,'amount_msat':amount,'metadata':metadata,'network':network,'now':int(now)},timeout=10,
                on_stdout_raw=capture('stdout'),on_stderr_raw=capture('stderr'))
        except Exception as error:raise _PrivateVerifierError(observations,type(error).__name__) from None
        public_payload(result);return _ObservedReply(result,{'streams':observations,'representation':'actual native public checker output'})


class _ObservedReply(dict):
    def __init__(self,value,observation):super().__init__(value);self.observation=observation


class _PrivateHTTPError(ValueError):
    def __init__(self,status,headers,raw):
        super().__init__('owned backend request refused or bounded')
        self.observation={'status':status,'headers':headers,'body_base64':base64.b64encode(raw).decode(),
            'truncated':len(raw)>MAX_RESPONSE,'representation':'actual HTTP error body'}


class _PrivateVerifierError(ValueError):
    def __init__(self,observations,kind):
        super().__init__('native invoice compatibility check failed')
        self.observation={'streams':observations,'error_type':kind}


def _digest_bytes(value):return hashlib.sha256(value).hexdigest()


class NoahAdapter:
    def __init__(self,store,manifest,*,transport=None,invoice_verifier=None,clock=time.time):
        self.store,self.manifest,self.clock=store,manifest,clock
        self.transport,self.invoice_verifier=transport,invoice_verifier
        self._sessions={}  # Private bearer memory; never serialized into evidence.
        store.db.executescript(SCHEMA)

    def readiness(self,*,enrollment=False):
        try:
            _checked_manifest(self.manifest,enrollment=enrollment)
            if self.store.get_meta('mode')=='live':
                if (not isinstance(self.transport,HTTPSNoahTransport) or self.transport.origin!=self.manifest['origin']['https_origin']
                        or self.transport.ca_sha256!=self.manifest['origin']['ca_sha256']
                        or not self.transport.context.check_hostname or self.transport.context.verify_mode!=ssl.CERT_REQUIRED
                        or (not enrollment and (not isinstance(self.invoice_verifier,NativeInvoiceVerifier)
                        or self.invoice_verifier.sha256!=self.manifest['source'].get('invoice_verifier_sha256')))):
                    raise ValueError('live TLS/native verification prerequisites differ')
            for section in SECTIONS:
                data=_reference(self.store,self.manifest['evidence'][section],'noah.readiness.'+section)
                if (set(data)!={'observed','verified','method'} or data['verified'] is not True
                        or data['method']!='independent_observation' or data['observed']!=self.manifest[section]):
                    raise ValueError('independent readiness observation differs')
            encoded=canonical(self.manifest);key='noah_enrollment_manifest' if enrollment else 'noah_readiness_manifest'
            old=self.store.get_meta(key)
            if old is not None and old!=encoded:raise ValueError('immutable readiness declaration changed')
            if old is None:
                with self.store.transaction():
                    self.store.db.execute('INSERT INTO meta VALUES (?,?)',(key,encoded))
                    self.store._event('noah_enrollment_declared' if enrollment else 'noah_readiness_declared',{'manifest_sha256':_digest(encoded),'evidence':self.manifest['evidence'],
                        'qualification':'recorded independent prerequisites; genuine journey qualification remains separate'})
            return {'status':'ready_for_enrollment' if enrollment else 'ready_for_dispatch','manifest_sha256':_digest(encoded),'complete':False}
        except (ValueError,TypeError,KeyError,OSError):
            return {'status':'unqualified','reason':'readiness manifest or independently checked identity/capital evidence missing or changed','complete':False}

    def _ready(self,*,enrollment=False):
        expected='ready_for_enrollment' if enrollment else 'ready_for_dispatch'
        if self.readiness(enrollment=enrollment)['status']!=expected:raise ValueError('Noah readiness unqualified')
        if self.store.get_meta('paused'):raise ValueError('campaign paused')

    def protect(self,kind,payload,*,actor=None,action_id=None):
        """Retain private observations on this host; public records hold refs only."""
        if re.fullmatch('[a-z][a-z0-9_.-]{0,79}',kind) is None:raise ValueError('invalid protected observation kind')
        directory=self.store.root/'noah-protected';directory.mkdir(mode=0o700,exist_ok=True)
        if directory.is_symlink() or directory.stat().st_mode&0o077:raise ValueError('protected artifact directory is not private')
        utc=dt.datetime.fromtimestamp(self.clock(),dt.timezone.utc).isoformat()
        document={'schema_version':1,'utc':utc,'kind':kind,'actor':actor,'action_id':action_id,'payload':payload}
        encoded=canonical(document).encode()
        if len(encoded)>MAX_PROTECTED:raise ValueError('protected observation exceeds bound')
        path=directory/(uuid.uuid4().hex+'.json')
        descriptor=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(descriptor,'wb') as out:out.write(encoded);out.flush();os.fsync(out.fileno())
        reference={'path':'noah-protected/'+path.name,'sha256':_digest_bytes(encoded),'bytes':len(encoded),
            'utc':utc,'kind':kind,'actor':actor,'action_id':action_id}
        self.store.event('noah_protected_artifact',reference)
        return reference

    def read_protected(self,reference,*,kind,actor=None,action_id=None):
        """Only private auditors may dereference; never send the result to logs."""
        if (not isinstance(reference,dict) or set(reference)!={'path','sha256','bytes','utc','kind','actor','action_id'}
                or re.fullmatch(r'noah-protected/[0-9a-f]{32}\.json',reference.get('path','')) is None
                or (reference['kind'],reference['actor'],reference['action_id'])!=(kind,actor,action_id)):
            raise ValueError('protected reference context differs')
        _hex(reference['sha256']);integer(reference['bytes'],'protected bytes',1)
        path=self.store.root/reference['path']
        if path.is_symlink() or path.parent.is_symlink() or path.stat().st_mode&0o077:raise ValueError('protected artifact replaced or exposed')
        if reference['bytes']>MAX_PROTECTED or path.stat().st_size!=reference['bytes']:raise ValueError('protected artifact size differs')
        encoded=path.read_bytes()
        if _digest_bytes(encoded)!=reference['sha256']:raise ValueError('protected artifact hash differs')
        document=decode_object(encoded.decode())
        if (document['schema_version']!=1 or document['utc']!=reference['utc']
                or (document['kind'],document['actor'],document['action_id'])!=(kind,actor,action_id)):
            raise ValueError('protected artifact identity differs')
        return document

    def _phone(self,actor,*,require_online=False,enrollment=False):
        self._ready(enrollment=enrollment)
        found=[p for p in self.manifest['phones'] if p['actor']==actor]
        if len(found)!=1:raise ValueError('recipient not declared')
        row=self.store.db.execute('SELECT online,details FROM actor WHERE id=?',(actor,)).fetchone()
        if require_online and row is None:raise ValueError('phone has not been created by its owning controller')
        if require_online and row is not None:
            detail=json.loads(row['details'])
            if not row['online'] or detail.get('absence') or detail.get('permanent_absence') or detail.get('realism_pending_absence'):
                raise ValueError('phone is absent; no wallet or private enrollment call allowed')
        return found[0]

    async def _request(self,method,path,body=None,bearer=None,*,actor=None,action_id=None,enrollment=False):
        self._ready(enrollment=enrollment)
        if self.transport is None:raise ValueError('owned transport not configured')
        if isinstance(self.transport,HTTPSNoahTransport) and self.store.get_meta('mode')!='live':raise ValueError('synthetic state cannot contact an owned live backend')
        url=self.manifest['origin']['https_origin']+path
        reference=self.protect('http.request',{'method':method,'url':url,'body':body,'bearer':bearer,
            'representation':'actual decoded outgoing protocol request'},actor=actor,action_id=action_id)
        self.store.trace_capture('noah.http.request',{'artifact':reference},actor=actor,action_id=action_id)
        try:response=await self.transport(method,url,body,bearer)
        except Exception as error:
            reference=self.protect('http.error',getattr(error,'observation',{'error_type':type(error).__name__,'available_error_text':str(error)}),actor=actor,action_id=action_id)
            self.store.trace_capture('noah.http.error',{'artifact':reference},actor=actor,action_id=action_id)
            raise
        reference=self.protect('http.response',getattr(response,'observation',{'decoded_response':response,
            'representation':'actual returned decoded protocol object; wire bytes unavailable'}),actor=actor,action_id=action_id)
        self.store.trace_capture('noah.http.response',{'artifact':reference},actor=actor,action_id=action_id)
        return response

    async def enroll(self,actor,signer,expo_token,*,expiry):
        phone=self._phone(actor,require_online=True,enrollment=True);now=int(self.clock());integer(expiry,'mailbox expiry',now+1)
        if expiry>now+90*86400 or not isinstance(expo_token,str) or re.fullmatch(r'(Expo|Exponent)PushToken\[[A-Za-z0-9_-]{1,100}\]',expo_token) is None:
            raise ValueError('Expo token or mailbox expiry invalid')
        challenge=await self._request('GET','/v0/getk1',actor=actor,enrollment=True)
        k1=challenge.get('k1');match=re.fullmatch(r'[0-9a-f]{64}_([0-9]{1,20})',k1 or '')
        if challenge.get('tag')!='login' or not match or not 0<=now-int(match[1])<=600:
            raise ValueError('invalid issued login challenge')
        # Private signer output is never passed to trace/event capture.
        try:material=await signer(k1,expiry)
        except Exception as error:
            reference=self.protect('signer.error',{'error_type':type(error).__name__,'available_error_text':str(error)},actor=actor)
            self.store.trace_capture('noah.signer.error',{'artifact':reference},actor=actor)
            raise
        reference=self.protect('signer.response',material,actor=actor)
        self.store.trace_capture('noah.signer.response',{'artifact':reference},actor=actor)
        if (set(material)!={'key','sig','mailbox_id','expiry','encoded'} or material['key']!=phone['auth_pubkey']
                or material['mailbox_id']!=phone['mailbox_id'] or material['expiry']!=expiry
                or not isinstance(material['sig'],str) or re.fullmatch(r'30[0-9a-f]{136,144}',material['sig']) is None
                or not isinstance(material['encoded'],str) or re.fullmatch(r'[0-9a-f]{210}',material['encoded']) is None):
            raise ValueError('private wallet enrollment material differs')
        login=await self._request('POST','/v0/auth/login',{key:material[key] for key in ('key','sig')}|{'k1':k1},actor=actor,enrollment=True)
        token=login.get('access_token')
        if login.get('token_type')!='Bearer' or not isinstance(token,str) or not token or integer(login.get('expires_in_seconds'),'token lifetime',1)>259200:
            raise ValueError('login did not issue a bounded bearer')
        registered=await self._request('POST','/v0/register',{'ln_address':phone['username']+'@'+self.manifest['origin']['lnurl_domain'],
            'ark_address':phone['ark_address'],'device_info':None},token,actor=actor,enrollment=True)
        if registered.get('status')!='OK' or registered.get('lightning_address')!=phone['username']+'@'+self.manifest['origin']['lnurl_domain']:
            raise ValueError('authenticated registration differs')
        for path,body in (('/v0/register_push_token',{'push_token':expo_token}),('/v0/mailbox/authorize',{key:material[key] for key in ('mailbox_id','expiry','encoded')})):
            if (await self._request('POST',path,body,token,actor=actor,enrollment=True)).get('success') is not True:raise ValueError('phone authorization not accepted')
        info=await self._request('POST','/v0/user_info',{},token,actor=actor,enrollment=True)
        if info.get('lightning_address')!=registered['lightning_address'] or info.get('user_status')!='active':raise ValueError('authenticated identity differs')
        self.store.event('noah_phone_enrolled',{'actor':actor,'auth_pubkey':phone['auth_pubkey'],'ark_address':phone['ark_address'],
            'mailbox_id':phone['mailbox_id'],'mailbox_grant_sha256':_digest(material['encoded']),'expiry':expiry,
            'qualification':'authenticated enrollment only; no payment or ownership outcome'})
        self._sessions[actor]=(token,self.clock()+login['expires_in_seconds'])
        return {'state':'enrolled','actor':actor,'authenticated_identity':phone['auth_pubkey']}

    async def submit_invoice(self,actor,body):
        self._phone(actor,require_online=True)
        if not isinstance(body,dict) or set(body)!={'transaction_id','invoice'} or not isinstance(body['invoice'],str):
            raise ValueError('original invoice submission fields missing')
        row=self.store.db.execute('SELECT * FROM noah_push WHERE actor=? AND transaction_id=?',(actor,body['transaction_id'])).fetchone()
        if (row is None or row['state']!='dispatched' or row['invoice_digest']!=_digest(body['invoice']) or not row['payment_hash']):
            raise ValueError('invoice does not match an unsubmitted original phone request')
        session=self._sessions.get(actor)
        if session is None or session[1]<=self.clock():raise ValueError('private bearer expired or absent; explicit real login required')
        with self.store.transaction():
            self.store.db.execute("UPDATE noah_push SET state='submission_started' WHERE actor=? AND transaction_id=?",(actor,body['transaction_id']))
            self.store._event('noah_phone_submission_started',{'actor':actor,'transaction_ref_sha256':_digest(body['transaction_id']),
                'invoice_sha256':row['invoice_digest'],'payment_hash':row['payment_hash']})
        return await self._request('POST','/v0/lnurlp/submit_invoice',body,session[0],actor=actor)

    def intent(self,identifier):
        row=self.store.db.execute('SELECT * FROM noah_intent WHERE id=?',(identifier,)).fetchone()
        if row is None:raise ValueError('unknown immutable payment intent')
        intent=json.loads(row['intent']);proof=json.loads(row['proof']) if row['proof'] else None
        recorded=self.store.db.execute("SELECT payload FROM event WHERE kind='noah_payment_intent' AND json_extract(payload,'$.intent_id')=?",(identifier,)).fetchall()
        if len(recorded)!=1 or json.loads(recorded[0]['payload'])!={'intent_id':identifier,**intent}:
            raise ValueError('frozen intent differs from its immutable journal')
        if proof is not None:
            frozen=self.store.db.execute("SELECT payload FROM event WHERE kind='noah_intent_state' AND json_extract(payload,'$.intent_id')=? AND json_extract(payload,'$.state')='invoice_frozen'",(identifier,)).fetchall()
            if len(frozen)!=1 or json.loads(frozen[0]['payload']).get('proof')!=proof or row['payment_hash']!=proof.get('payment_hash'):
                raise ValueError('frozen invoice proof/hash differs from its immutable journal')
        return {**dict(row),'intent':intent,'proof':proof,'result':json.loads(row['result']) if row['result'] else None}

    def _payer(self,actor,identifier):
        row=self.store.db.execute('SELECT online,details FROM actor WHERE id=?',(actor,)).fetchone()
        if row is None or not row['online']:raise ValueError('declared payer is not an online created actor')
        detail=json.loads(row['details'])
        if detail.get('absence') or detail.get('permanent_absence') or detail.get('realism_pending_absence'):
            raise ValueError('payer is disappearing or permanently absent')
        busy=self.store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND id!=? AND (state IN ('dispatched','outcome_unknown') OR (state='queued' AND operation NOT IN ('snapshot','address'))) LIMIT 1",(actor,identifier)).fetchone()
        if busy:raise ValueError('payer has another pending native operation')

    def _state(self,identifier,state,*,proof=None,result=None):
        if result is not None:public_payload(result)
        with self.store.transaction():
            self.store.db.execute('UPDATE noah_intent SET state=?,proof=coalesce(?,proof),payment_hash=coalesce(?,payment_hash),result=?,updated_at=? WHERE id=?',
                (state,canonical(proof) if proof else None,proof.get('payment_hash') if proof else None,canonical(result) if result is not None else None,self.clock(),identifier))
            self.store._event('noah_intent_state',{'intent_id':identifier,'state':state,'proof':proof,'result':result})
        return self.intent(identifier)

    async def negotiate(self,identifier,payer,recipient,amount_msat,*,binding=None,ark_server=None):
        phone=self._phone(recipient);integer(amount_msat,'LNURL amount in millisatoshis',1000)
        if amount_msat%1000 or amount_msat>1000000000:raise ValueError('exact bounded whole-sat amount required')
        if not isinstance(identifier,str) or re.fullmatch('[A-Za-z0-9_-]{1,100}',identifier) is None:raise ValueError('invalid immutable intent id')
        capital=self.manifest['capital']
        if re.fullmatch('noah-payer-[A-Za-z0-9_-]{1,64}',payer) is None or payer not in capital['actor_principal_sat']:
            raise ValueError('separately allocated payer missing')
        if amount_msat//1000+capital['per_action_fee_sat']>capital['actor_principal_sat'][payer]:raise ValueError('payment exceeds declared actor capital')
        if ark_server is not None and ark_server!=self.manifest['chain']['server_pubkey']:raise ValueError('Ark server key mismatch')
        intended={'payer':payer,'recipient':recipient,'recipient_identity':phone,'amount_msat':amount_msat,
            'maximum_fee_sat':capital['per_action_fee_sat'],'allocation_id':capital['allocation_id'],
            'transport':'ark_lnurl' if ark_server else 'lightning','ark_server':ark_server}
        encoded=canonical(intended)
        row=self.store.db.execute('SELECT intent FROM noah_intent WHERE id=?',(identifier,)).fetchone()
        if row:
            if row['intent']!=encoded:raise ValueError('immutable payment intent changed')
            return self.intent(identifier)
        self._payer(payer,identifier)
        busy=self.store.db.execute("SELECT 1 FROM noah_intent WHERE json_extract(intent,'$.payer')=? AND state IN ('negotiating','invoice_requested','invoice_frozen','dispatched','outcome_unknown') LIMIT 1",(payer,)).fetchone()
        if busy:raise ValueError('payer has a prior unresolved Noah intent')
        fee_used=self.store.db.execute("SELECT coalesce(sum(json_extract(intent,'$.maximum_fee_sat')),0) FROM noah_intent WHERE state!='compatibility_failure'").fetchone()[0]
        if fee_used+capital['per_action_fee_sat']>capital['campaign_fee_sat']:raise ValueError('declared Noah fee campaign exhausted')
        with self.store.transaction():
            self.store.db.execute('INSERT INTO noah_intent VALUES (?,?,?,NULL,NULL,NULL,?)',(identifier,encoded,'negotiating',self.clock()))
            self.store._event('noah_payment_intent',{'intent_id':identifier,**intended})
        path='/.well-known/lnurlp/'+phone['username'];query={} if ark_server is None else {'ark':ark_server}
        try:
            first=await self._request('GET',path+('?' +urlencode(query) if query else ''),actor=payer,action_id=identifier)
            expected=self.manifest['origin']['https_origin']+path
            if first.get('callback')!=expected or first.get('tag')!='payRequest':raise ValueError('same owned LNURL callback required')
            if not integer(first.get('minSendable'),'minimum msat',1)<=amount_msat<=integer(first.get('maxSendable'),'maximum msat',1):
                raise ValueError('amount outside advertised LNURL bounds')
            metadata=first.get('metadata')
            if not isinstance(metadata,str) or len(metadata.encode())>65536:raise ValueError('bounded metadata bytes required')
            pairs=json.loads(metadata)
            if not isinstance(pairs,list) or any(not isinstance(pair,list) or len(pair)!=2 or not all(isinstance(v,str) for v in pair) for pair in pairs):
                raise ValueError('invalid LNURL metadata')
            if [pair for pair in pairs if pair[0]=='text/identifier']!=[['text/identifier',phone['username']+'@'+self.manifest['origin']['lnurl_domain']]]:
                raise ValueError('metadata recipient differs')
            self.store.event('noah_lnurl_parameters',{'intent_id':identifier,'metadata':metadata,'metadata_sha256':_digest(metadata),
                'callback':expected,'min_sendable_msat':first['minSendable'],'max_sendable_msat':first['maxSendable'],'observed_at':self.clock()})
            self._state(identifier,'invoice_requested')
            reply=await self._request('GET',path+'?'+urlencode({'amount':amount_msat,**query}),actor=payer,action_id=identifier)
            if ark_server is not None:
                if first.get('ark')!=phone['ark_address'] or reply.get('ark')!=phone['ark_address'] or reply.get('pr')!='':
                    raise ValueError('negotiated Ark recipient differs')
                result=self._state(identifier,'ark_negotiated',result={'destination':phone['ark_address'],'lightning_credit':False})
                return {**result,'transport':'ark_lnurl'}
            invoice=reply.get('pr')
            if not isinstance(invoice,str) or not invoice or len(invoice.encode())>65536 or self.invoice_verifier is None:raise ValueError('actual invoice verifier required')
            try:proof=await self.invoice_verifier(invoice,amount_msat,metadata,'signet',self.clock())
            except Exception as error:
                reference=self.protect('invoice.verifier.error',getattr(error,'observation',{'error_type':type(error).__name__,'available_error_text':str(error)}),actor=payer,action_id=identifier)
                self.store.trace_capture('noah.invoice.verifier.error',{'artifact':reference},actor=payer,action_id=identifier)
                raise ValueError('native invoice compatibility failed') from None
            reference=self.protect('invoice.verifier.response',getattr(proof,'observation',{'actual_decoded_proof':proof}),actor=payer,action_id=identifier)
            self.store.trace_capture('noah.invoice.verifier.response',{'artifact':reference},actor=payer,action_id=identifier)
            public_payload(proof)
            expected_proof={'amount_msat':amount_msat,'network':'signet','metadata_sha256':_digest(metadata),
                'invoice_sha256':_digest(invoice),'signature_checked':True,'node_pubkey':self.manifest['chain']['lightning_node_pubkey']}
            if (not isinstance(proof,dict) or set(proof)!=set(expected_proof)|{'expires_at','payment_hash'}
                    or any(proof.get(key)!=value for key,value in expected_proof.items()) or integer(proof.get('expires_at'),'invoice expiry')<=self.clock()):
                raise ValueError('invoice signature/network/amount/expiry/metadata mismatch')
            _hex(proof.get('payment_hash'))
            if callable(binding):binding=await binding(proof)
            recipient_proof=_reference(self.store,binding,'noah.recipient.invoice',actor=recipient)
            matching={'actor':recipient,'auth_pubkey':phone['auth_pubkey'],'ark_address':phone['ark_address'],
                'payment_hash':proof['payment_hash'],'invoice_sha256':proof['invoice_sha256'],'amount_msat':amount_msat,'registered_destination_checked':True}
            if any(recipient_proof.get(key)!=value for key,value in matching.items()) or recipient_proof.get('source') not in {'device','forwarder'}:
                raise ValueError('independent intended-recipient invoice binding missing')
            if recipient_proof['source']=='forwarder' and not self.manifest['forwarder']['enabled']:raise ValueError('undeclared forwarding route')
            invoice_root=self.store.root/'noah-invoices';invoice_root.mkdir(mode=0o700,exist_ok=True)
            if invoice_root.is_symlink():raise ValueError('invoice artifact directory is not private')
            artifact=invoice_root/(identifier+'.txt')
            fd=os.open(artifact,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'w') as out:out.write(invoice);out.flush();os.fsync(out.fileno())
            self.store.trace_capture('noah.invoice.validated',{'intent_id':identifier,'proof':proof,'recipient_evidence':binding})
            return self._state(identifier,'invoice_frozen',proof={**proof,'recipient_evidence':binding})
        except (TimeoutError,ConnectionError,OSError):
            return self._state(identifier,'outcome_unknown',result={'stage':'LNURL request','reason':'reply unavailable; no replacement invoice or payment retry'})
        except (ValueError,TypeError,KeyError):
            self._state(identifier,'compatibility_failure',result={'stage':'invoice/recipient compatibility','reason':'contract or independent proof failed; no payment dispatched'})
            raise ValueError('Noah LNURL/invoice compatibility failed') from None

    def payment_request(self,identifier):
        self._ready();row=self.intent(identifier)
        if row['state']!='invoice_frozen' or row['intent']['transport']!='lightning':raise ValueError('no dispatchable frozen Lightning intent')
        proof=row['proof']
        self._payer(row['intent']['payer'],identifier)
        if proof['expires_at']<=self.clock():raise ValueError('frozen invoice expired; never replace automatically')
        artifact=self.store.root/'noah-invoices'/(identifier+'.txt')
        if artifact.is_symlink():raise ValueError('frozen invoice artifact replaced')
        if artifact.stat().st_mode&0o077:raise ValueError('frozen invoice artifact is not private')
        invoice=artifact.read_text()
        if _digest(invoice)!=proof['invoice_sha256']:raise ValueError('frozen invoice bytes changed')
        return {'operation':'pay_invoice','action_id':identifier,'actor':row['intent']['payer'],
            'args':{'invoice':invoice,'amount_sat':row['intent']['amount_msat']//1000,'payment_hash':row['payment_hash']},
            'maximum_fee_sat':row['intent']['maximum_fee_sat']}

    async def dispatch(self,identifier,submit):
        row=self.intent(identifier)
        if row['state'] in {'dispatched','outcome_unknown'}:return row
        request=self.payment_request(identifier)
        self._state(identifier,'dispatched',result={'payment_hash':row['payment_hash'],'economic_retry_allowed':False})
        try:
            self.protect('native.request',request,actor=row['intent']['payer'],action_id=identifier)
            response=await submit(request)
            self.protect('native.response',response,actor=row['intent']['payer'],action_id=identifier)
            if response.get('payment_hash')!=row['payment_hash']:raise ValueError('native payment hash differs')
        except Exception as error:
            self.protect('native.error',{'error_type':type(error).__name__,'available_error_text':str(error)},actor=row['intent']['payer'],action_id=identifier)
            return self._state(identifier,'outcome_unknown',result={'payment_hash':row['payment_hash'],'reason':'payment reply absent or invalid; only same-hash reconciliation permitted'})
        # ACK/paid flag is not a signed recipient outcome or independent fee proof.
        return self._state(identifier,'outcome_unknown',result={'payment_hash':row['payment_hash'],'native_ack':True,'reason':'independent receipt/refund and fee proof required'})

    async def reconcile(self,identifier,query_status):
        row=self.intent(identifier)
        if row['state'] not in {'dispatched','outcome_unknown'} or not row['payment_hash']:return row
        self.protect('native.status.request',{'payment_hash':row['payment_hash'],'read_only':True},actor=row['intent']['payer'],action_id=identifier)
        try:result=await query_status(row['payment_hash'])
        except Exception as error:
            self.protect('native.status.error',{'error_type':type(error).__name__,'available_error_text':str(error)},actor=row['intent']['payer'],action_id=identifier)
            raise
        self.protect('native.status.response',result,actor=row['intent']['payer'],action_id=identifier)
        if not isinstance(result,dict) or result.get('payment_hash')!=row['payment_hash']:raise ValueError('status response is for another immutable hash')
        state=result.get('state')
        if state not in {'pending','succeeded','failed','unknown'}:raise ValueError('unsupported independent payment state')
        self.store.event('noah_payment_status',{'intent_id':identifier,'payment_hash':row['payment_hash'],'node_state':state,
            'qualification':'node status alone does not prove intended recipient collection/refund, final ownership or fees'})
        return row

    async def consume_push(self,actor,envelope,expo_token,*,invoice,claim,submit=None,delivery_bytes=None):
        if not isinstance(actor,str) or re.fullmatch('noah-phone-[A-Za-z0-9_-]{1,64}',actor) is None:raise ValueError('invalid declared phone label')
        if delivery_bytes is None:
            payload={'decoded_original':envelope,'representation':'actual decoded original transport object; wire bytes unavailable'}
        else:
            if not isinstance(delivery_bytes,bytes) or len(delivery_bytes)>MAX_RESPONSE:raise ValueError('bounded original delivery bytes required')
            payload={'body_base64':base64.b64encode(delivery_bytes).decode(),'representation':'exact original delivery body'}
        reference=self.protect('original.push',payload,actor=actor)
        self.store.trace_capture('noah.original.push',{'artifact':reference},actor=actor)
        if delivery_bytes is not None and decode_object(delivery_bytes.decode())!=envelope:raise ValueError('original delivery body differs')
        self._phone(actor,require_online=True)
        data=_expo_data(envelope,expo_token);kind=data.get('notification_type')
        if kind=='lightning_invoice_request':
            transaction=data['transaction_id'];amount=data['amount']
        elif kind=='lightning_claim_request':transaction='claim-'+data['payment_hash'];amount=data['amount_sat']*1000
        else:raise ValueError('original push requires separate qualified handler')
        row=self.store.db.execute('SELECT * FROM noah_push WHERE actor=? AND transaction_id=?',(actor,transaction)).fetchone()
        if row:
            if row['amount_msat']!=amount:raise ValueError('original push immutable amount changed')
            return {'state':row['state'],'payment_hash':row['payment_hash'],'outcome_verified':False}
        with self.store.transaction():
            self.store.db.execute("INSERT INTO noah_push VALUES (?,?,?,'dispatched',NULL,NULL)",(actor,transaction,amount))
            self.store._event('noah_original_push_intent',{'actor':actor,'notification_type':kind,'transaction_ref_sha256':_digest(transaction),'amount_msat':amount,'original_payload':reference})
        async def freeze_invoice(value):
            try:created=await invoice(value)
            except Exception as error:
                self.protect('phone.invoice.error',{'error_type':type(error).__name__,'available_error_text':str(error)},actor=actor)
                raise
            invoice_reference=self.protect('phone.invoice.response',created,actor=actor)
            payment_hash=_hex(created.get('payment_hash'));actual=created.get('invoice')
            if not isinstance(actual,str) or not actual:raise ValueError('actual phone invoice missing')
            digest=_digest(actual)
            with self.store.transaction():
                self.store.db.execute('UPDATE noah_push SET payment_hash=?,invoice_digest=? WHERE actor=? AND transaction_id=?',(payment_hash,digest,actor,transaction))
                self.store._event('noah_phone_invoice_created',{'actor':actor,'transaction_ref_sha256':_digest(transaction),'amount_msat':amount,'payment_hash':payment_hash,'invoice_sha256':digest,'artifact':invoice_reference})
            return created
        if submit is None:
            async def submit(body):return await self.submit_invoice(actor,body)
        async def observed_submit(body):
            self.protect('phone.submission.request',body,actor=actor)
            try:result=await submit(body)
            except Exception as error:
                self.protect('phone.submission.error',{'error_type':type(error).__name__,'available_error_text':str(error)},actor=actor)
                raise
            self.protect('phone.submission.response',result,actor=actor)
            return result
        async def observed_claim():
            try:result=await claim()
            except Exception as error:
                self.protect('phone.claim.error',{'error_type':type(error).__name__,'available_error_text':str(error)},actor=actor)
                raise
            self.protect('phone.claim.response',result,actor=actor)
            return result
        try:result=await consume_expo_push(envelope,expo_token,invoice=freeze_invoice,submit=observed_submit,claim=observed_claim)
        except Exception:result={'state':'outcome_unknown','outcome_verified':False}
        with self.store.transaction():
            self.store.db.execute('UPDATE noah_push SET state=? WHERE actor=? AND transaction_id=?',(result['state'],actor,transaction))
            self.store._event('noah_original_push_result',{'actor':actor,'transaction_ref_sha256':_digest(transaction),**result})
        return result


def _expo_data(envelope,expo_token):
    if not isinstance(envelope,dict) or envelope.get('to') not in ([expo_token],expo_token):raise ValueError('original Expo recipient differs')
    data=envelope.get('data')
    if isinstance(data,str):data=decode_object(data)
    if not isinstance(data,dict):raise ValueError('original Expo data missing')
    kind=data.get('notification_type')
    if kind=='lightning_invoice_request':
        if set(data)!={'notification_type','transaction_id','amount'}:raise ValueError('original invoice push fields differ')
        transaction=data['transaction_id']
        if not isinstance(transaction,str) or str(uuid.UUID(transaction))!=transaction:raise ValueError('invalid original transaction id')
        amount=integer(data['amount'],'original push amount msat',1000)
        if amount%1000 or amount>1000000000:raise ValueError('cannot truncate original push millisatoshis')
    elif kind=='lightning_claim_request':
        if set(data)!={'notification_type','payment_hash','amount_sat'}:raise ValueError('original claim push fields differ')
        _hex(data['payment_hash']);integer(data['amount_sat'],'original claim amount',1)
    else:raise ValueError('push kind needs its original separately qualified handler')
    return data


async def consume_expo_push(envelope,expo_token,*,invoice,submit,claim):
    """Original Expo payload parity; invoice submission does not auto-claim.

    The owning controller must supply actor-presence/once-only operation guards.
    No synthetic notification is substituted for the captured original data.
    """
    data=_expo_data(envelope,expo_token)
    kind=data.get('notification_type')
    if kind=='lightning_invoice_request':
        if set(data)!={'notification_type','transaction_id','amount'}:raise ValueError('original invoice push fields differ')
        transaction=data['transaction_id']
        if not isinstance(transaction,str) or str(uuid.UUID(transaction))!=transaction:raise ValueError('invalid original transaction id')
        amount=integer(data['amount'],'original push amount msat',1000)
        if amount%1000 or amount>1000000000:raise ValueError('cannot truncate original push millisatoshis')
        created=await invoice(amount//1000)
        actual=created.get('invoice')
        if not isinstance(actual,str) or not actual:raise ValueError('native invoice not issued')
        if (await submit({'transaction_id':transaction,'invoice':actual})).get('success') is not True:raise ValueError('invoice submission not accepted')
        return {'state':'invoice_submitted','payment_hash':created.get('payment_hash'),'outcome_verified':False}
    if kind=='lightning_claim_request':
        if set(data)!={'notification_type','payment_hash','amount_sat'}:raise ValueError('original claim push fields differ')
        _hex(data['payment_hash']);integer(data['amount_sat'],'original claim amount',1)
        await claim()
        return {'state':'claim_called','payment_hash':data['payment_hash'],'outcome_verified':False}
    raise ValueError('push kind needs its original separately qualified handler')
