"""Private enrollment boundary; payment dispatch remains a separate gate.

The qualification reference is an independent local audit result. It is not
the server's upgrade manifest, and cannot substitute for checking that manifest.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re
import sqlite3

from .model import canonical,integer
from .noah import _hex,_reference
from .process import json_command

SCHEMA='''CREATE TABLE IF NOT EXISTS noah_control(
 id TEXT PRIMARY KEY,actor TEXT NOT NULL,intent TEXT NOT NULL,state TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS noah_control_actor_hold ON noah_control(actor)
 WHERE state IN ('started','outcome_unknown');'''


class NoahController:
    """Once-only phone setup through a qualified, private native executable."""
    def __init__(self,adapter,helper,helper_sha256,qualification):
        self.adapter=adapter;self.store=adapter.store
        self.helper=Path(helper);self.helper_sha256=_hex(helper_sha256)
        self.qualification=qualification
        self.store.db.executescript(SCHEMA)

    def _qualified(self,actor):
        phone=self.adapter._phone(actor,require_online=True,enrollment=True)
        observation=_reference(self.store,self.qualification,'noah.native.qualification')
        expected={'schema_version':1,'verified':True,'method':'independent_native_sdk_audit',
            'manifest_sha256':hashlib.sha256(canonical(self.adapter.manifest).encode()).hexdigest(),
            'network':'signet','server_pubkey':self.adapter.manifest['chain']['server_pubkey'],
            'sdk_commit':self.adapter.manifest['chain']['phone_sdk_commit'],
            'helper_sha256':self.helper_sha256,'protocol':'noah-private-v1'}
        if set(observation)!={*expected,'wallets'} or any(observation.get(key)!=value for key,value in expected.items()):
            raise ValueError('independent native qualification differs')
        wallets=observation['wallets']
        if not isinstance(wallets,dict) or actor not in wallets:raise ValueError('declared private phone wallet missing')
        wallet=Path(wallets[actor])
        # New wallet locations must be independently declared, not aliases for
        # an original client or a recovery wallet. Never infer from a balance.
        if not wallet.is_absolute() or wallet.name!=actor or not wallet.is_dir():raise ValueError('new phone wallet path differs')
        if any(path.is_symlink() for path in (wallet,*wallet.parents)):raise ValueError('phone wallet path is aliased')
        if (not self.helper.is_absolute() or self.helper.is_symlink() or not self.helper.is_file()
                or hashlib.sha256(self.helper.read_bytes()).hexdigest()!=self.helper_sha256):
            raise ValueError('private native helper pin differs')
        busy=self.store.db.execute("SELECT 1 FROM action WHERE actor_id=? AND (state IN ('dispatched','outcome_unknown') OR (state='queued' AND operation NOT IN ('snapshot','address'))) LIMIT 1",(actor,)).fetchone()
        if busy:raise ValueError('phone has a pending native operation')
        return phone,wallet

    def _start(self,identifier,actor,intent):
        if not isinstance(identifier,str) or re.fullmatch('[A-Za-z0-9_-]{1,100}',identifier) is None:
            raise ValueError('explicit immutable setup id required')
        encoded=canonical(intent)
        with self.store.transaction():
            existing=self.store.db.execute('SELECT * FROM noah_control WHERE id=?',(identifier,)).fetchone()
            if existing:
                if existing['actor']!=actor or existing['intent']!=encoded:raise ValueError('immutable phone setup changed')
                raise ValueError('phone setup already attempted; independent reconciliation required')
            try:self.store.db.execute("INSERT INTO noah_control VALUES (?,?,?,'started')",(identifier,actor,encoded))
            except sqlite3.IntegrityError:raise ValueError('phone has an unresolved private operation') from None
            self.store._event('noah_control_started',{'id':identifier,'actor':actor,'intent':intent})

    def _finish(self,identifier,actor,state):
        with self.store.transaction():
            self.store.db.execute('UPDATE noah_control SET state=? WHERE id=?',(state,identifier))
            self.store._event('noah_control_result',{'id':identifier,'actor':actor,'state':state,
                'qualification':'private enrollment only; no economic outcome'})

    async def _material(self,identifier,actor,k1,expiry):
        _,wallet=self._qualified(actor)
        request={'protocol':'noah-private-v1','operation':'enrollment_material','actor':actor,
            'action_id':identifier,'wallet_path':str(wallet),'k1':k1,'expiry_unix':expiry,
            'expected_server_pubkey':self.adapter.manifest['chain']['server_pubkey']}
        self.adapter.protect('native.request',request,actor=actor,action_id=identifier)
        def capture(stream):
            def record(value):
                self.adapter.protect('native.'+stream,{**{k:v for k,v in value.items() if k!='raw'},
                    'body_base64':base64.b64encode(value['raw']).decode()},actor=actor,action_id=identifier)
            return record
        try:
            result=await json_command([str(self.helper)],request,timeout=120,
                on_stdout_raw=capture('stdout'),on_stderr_raw=capture('stderr'))
        except Exception as error:
            self.adapter.protect('native.error',{'error_type':type(error).__name__,'available_error_text':str(error)},
                actor=actor,action_id=identifier)
            raise ValueError('private native operation interrupted; retained for reconciliation') from None
        self.adapter.protect('native.response',result,actor=actor,action_id=identifier)
        if (set(result)!={'protocol','operation','actor','action_id','material'}
                or result['protocol']!='noah-private-v1' or result['operation']!='enrollment_material'
                or result['actor']!=actor or result['action_id']!=identifier):
            raise ValueError('private native enrollment response context differs')
        return result['material']

    async def enroll(self,identifier,actor,expo_token,*,expiry):
        self._qualified(actor);integer(expiry,'mailbox expiry',int(self.adapter.clock())+1)
        if expiry>self.adapter.clock()+90*86400 or not isinstance(expo_token,str):raise ValueError('bounded enrollment declaration required')
        intent={'operation':'enroll','expiry':expiry,'expo_token_sha256':hashlib.sha256(expo_token.encode()).hexdigest(),
            'manifest_sha256':hashlib.sha256(canonical(self.adapter.manifest).encode()).hexdigest(),
            'qualification':self.qualification,'helper_sha256':self.helper_sha256}
        self._start(identifier,actor,intent)
        async def signer(k1,expiry):return await self._material(identifier,actor,k1,expiry)
        try:result=await self.adapter.enroll(actor,signer,expo_token,expiry=expiry)
        except BaseException as error:
            # Preserve cancellation as well as lost native/HTTP replies. The
            # durable lease remains held; restart must never repeat this intent.
            self.adapter.protect('controller.error',{'error_type':type(error).__name__,'available_error_text':str(error)},
                actor=actor,action_id=identifier)
            self._finish(identifier,actor,'outcome_unknown')
            if not isinstance(error,Exception):raise
            raise ValueError('phone setup unresolved; independent reconciliation required') from None
        self._finish(identifier,actor,'completed')
        return result
