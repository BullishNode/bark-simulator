"""Owned pull persistence tests; no native job or payment is executed."""
import copy
import unittest

import test_noah_adapter as fixtures


class NoahInboxTests(unittest.IsolatedAsyncioTestCase):
    setUp=fixtures.NoahAdapterTests.setUp
    tearDown=fixtures.NoahAdapterTests.tearDown
    adapter=fixtures.NoahAdapterTests.adapter

    def inbox(self):
        from simulator.noah_inbox import NoahInbox
        self.manifest['source']['phone_transport']={'spool_source_sha256':'35'*32,'nginx_sha256':'36'*32}
        self.manifest['evidence']['source']=self.store.trace_capture('noah.readiness.source',{'observed':copy.deepcopy(self.manifest['source']),'verified':True,'method':'independent_observation'})
        adapter=self.adapter();adapter._sessions['actor-41']=('private-noah-session',2000)
        proof={'verified':True,'method':'independent_transport_audit','https_origin':self.manifest['origin']['https_origin'],
            **self.manifest['source']['phone_transport'],'backend_manifest_sha256':'34'*32,
            'token_mode':'opaque_native_auth','pull_path':'/test/phone/pushes','token_path':'/test/phone/token'}
        reference=self.store.trace_capture('noah.phone.transport',proof)
        return NoahInbox(adapter,reference),adapter

    def page(self):
        return {'records':[{'cursor':7,'ticket':'00000000-0000-4000-8000-000000000009','accepted_at':999.5,
            'payload':{'to':['ExpoPushToken[private-phone-token]'],'data':fixtures.canonical({
                'notification_type':'maintenance','challenge':'original-private-maintenance-challenge'})}}],
            'cursor':7,'has_more':False,'scope':'transport only; no job completion or payment credit'}

    async def test_original_payload_persists_before_cursor_and_restart_never_credits_fetch(self):
        inbox,adapter=self.inbox();calls=[]
        async def reply(method,url,body,bearer):
            calls.append((url,body,bearer))
            if url.endswith('/token'):return {'push_token':'ExpoPushToken[private-phone-token]'}
            return self.page()
        adapter.transport=reply
        self.assertEqual('ExpoPushToken[private-phone-token]',await inbox.token('actor-41','private-noah-session'))
        result=await inbox.pull('actor-41')
        self.assertEqual({'cursor':0,'limit':20},calls[-1][1]);self.assertEqual('private-noah-session',calls[-1][2])
        self.assertEqual(7,result['cursor']);self.assertFalse(result['outcome_verified'])
        pending=inbox.pending('actor-41');self.assertEqual(1,len(pending))
        record=inbox.original('actor-41',7)
        self.assertEqual(self.page()['records'][0],record)
        public=' '.join(row['payload'] for row in self.store.db.execute('SELECT payload FROM event'))
        for secret in ('private-phone-token','original-private-maintenance-challenge','private-noah-session'):self.assertNotIn(secret,public)
        from simulator.noah_inbox import NoahInbox
        reopened=NoahInbox(adapter,inbox.qualification)
        self.assertEqual(7,reopened.cursor('actor-41'));self.assertEqual(1,len(reopened.pending('actor-41')))
        self.assertEqual(0,self.store.db.execute('SELECT count(*) FROM action').fetchone()[0])

    async def test_foreign_payload_or_cursor_lie_never_advances(self):
        inbox,adapter=self.inbox()
        async def token(*args):return {'push_token':'ExpoPushToken[private-phone-token]'}
        adapter.transport=token;await inbox.token('actor-41','private-noah-session')
        for field in ('recipient','cursor'):
            value=self.page()
            if field=='recipient':value['records'][0]['payload']['to']=['ExpoPushToken[foreign]']
            else:value['cursor']=99
            async def reply(*args):return value
            adapter.transport=reply
            with self.assertRaises(ValueError):await inbox.pull('actor-41')
            self.assertEqual(0,inbox.cursor('actor-41'));self.assertEqual([],inbox.pending('actor-41'))

    async def test_absent_phone_expired_session_and_missing_transport_proof_never_fetch(self):
        inbox,adapter=self.inbox()
        async def forbidden(*args):self.fail('unqualified HTTP request')
        adapter.transport=forbidden
        adapter._sessions['actor-41']=('secret',999)
        with self.assertRaises(ValueError):await inbox.pull('actor-41')
        adapter._sessions['actor-41']=('secret',2000);self.store.set_online('actor-41',False)
        with self.assertRaises(ValueError):await inbox.pull('actor-41')
        self.store.set_online('actor-41',True);inbox.qualification=None
        with self.assertRaises(ValueError):await inbox.pull('actor-41')

    async def test_authenticated_opaque_token_is_obtained_between_register_and_native_registration(self):
        adapter=self.adapter();paths=[]
        async def transport(method,url,body,bearer):
            paths.append(url.rsplit('/',1)[-1])
            if url.endswith('/getk1'):return {'tag':'login','k1':'aa'*32+'_1000'}
            if url.endswith('/auth/login'):return {'access_token':'private-login','token_type':'Bearer','expires_in_seconds':1000}
            if url.endswith('/register'):return {'status':'OK','lightning_address':'alice@noah.fixture.example'}
            if url.endswith('/user_info'):return {'lightning_address':'alice@noah.fixture.example','user_status':'active'}
            if url.endswith('/register_push_token'):self.assertEqual({'push_token':'ExpoPushToken[opaque]'},body)
            return {'success':True}
        async def provider(bearer):self.assertEqual('private-login',bearer);paths.append('token-provider');return 'ExpoPushToken[opaque]'
        async def signer(k1,expiry):return {'key':fixtures.PUB,'sig':'30'+'aa'*70,'mailbox_id':fixtures.PUB,'expiry':expiry,'encoded':fixtures.PUB+'11'*72}
        adapter.transport=transport
        result=await adapter.enroll('actor-41',signer,provider,expiry=1500)
        self.assertEqual('enrolled',result['state'])
        self.assertEqual(['getk1','login','register','token-provider','register_push_token','authorize','user_info'],paths)

    async def test_partial_invalid_page_and_transport_error_do_not_lose_pending_cursor(self):
        inbox,adapter=self.inbox()
        async def issue(*args):return {'push_token':'ExpoPushToken[private-phone-token]'}
        adapter.transport=issue;await inbox.token('actor-41','private-noah-session')
        value=self.page();second=copy.deepcopy(value['records'][0]);second['cursor']=8
        second['payload']['to']=['ExpoPushToken[foreign]'];value['records'].append(second);value['cursor']=8
        async def malformed(*args):return value
        adapter.transport=malformed
        with self.assertRaises(ValueError):await inbox.pull('actor-41')
        self.assertEqual(0,inbox.cursor('actor-41'));self.assertEqual([],inbox.pending('actor-41'))
        async def outage(*args):raise TimeoutError('private-transport-outage')
        adapter.transport=outage
        with self.assertRaises(TimeoutError):await inbox.pull('actor-41')
        self.assertEqual(0,inbox.cursor('actor-41'));self.assertEqual([],inbox.pending('actor-41'))

    async def test_transport_source_drift_and_modified_original_artifact_are_held(self):
        inbox,adapter=self.inbox()
        async def replies(method,url,body,bearer):
            if url.endswith('/token'):return {'push_token':'ExpoPushToken[private-phone-token]'}
            return self.page()
        adapter.transport=replies;await inbox.token('actor-41','private-noah-session');await inbox.pull('actor-41')
        import json
        original=json.loads(inbox.pending('actor-41')[0]['artifact'])
        artifact=self.store.root/original['path'];artifact.write_text('{}')
        with self.assertRaises(ValueError):inbox.original('actor-41',7)
        observed={'verified':True,'method':'independent_transport_audit','https_origin':self.manifest['origin']['https_origin'],
            'spool_source_sha256':'ff'*32,'nginx_sha256':'ee'*32,'backend_manifest_sha256':'34'*32,
            'token_mode':'opaque_native_auth','pull_path':'/test/phone/pushes','token_path':'/test/phone/token'}
        inbox.qualification=self.store.trace_capture('noah.phone.transport',observed)
        with self.assertRaises(ValueError):await inbox.pull('actor-41')
