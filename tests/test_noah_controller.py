"""Private controller tests; no backend or SDK journey is qualified here."""
import copy
import asyncio
import hashlib
import json
import unittest
from unittest.mock import patch

import test_noah_adapter as fixtures
PUB=fixtures.PUB


class NoahBootstrapTests(unittest.IsolatedAsyncioTestCase):
    setUp=fixtures.NoahAdapterTests.setUp
    tearDown=fixtures.NoahAdapterTests.tearDown
    adapter=fixtures.NoahAdapterTests.adapter

    def unfunded(self):
        self.manifest['capital'].update(principal_sat=0,per_action_fee_sat=0,campaign_fee_sat=0,
            actor_principal_sat={'noah-phone-01':0})
        self.manifest['evidence']['capital']=self.store.trace_capture('noah.readiness.capital',{
            'observed':copy.deepcopy(self.manifest['capital']),'verified':True,'method':'independent_observation'})

    async def test_unfunded_new_phone_can_enroll_but_cannot_negotiate_or_execute_push(self):
        self.unfunded()
        async def reply(method,url,body,bearer):
            if url.endswith('/getk1'):return {'tag':'login','k1':'aa'*32+'_1000'}
            if url.endswith('/auth/login'):return {'access_token':'private-bearer','token_type':'Bearer','expires_in_seconds':1000}
            if url.endswith('/register'):return {'status':'OK','lightning_address':'alice@noah.fixture.example'}
            if url.endswith('/user_info'):return {'lightning_address':'alice@noah.fixture.example','user_status':'active'}
            return {'success':True}
        async def signer(challenge,expiry):return {'key':PUB,'sig':'30'+'aa'*70,'mailbox_id':PUB,'expiry':expiry,'encoded':PUB+'11'*72}
        adapter=self.adapter(reply)
        self.assertEqual('unqualified',adapter.readiness()['status'])
        result=await adapter.enroll('noah-phone-01',signer,'ExpoPushToken[phone]',expiry=1500)
        self.assertEqual('enrolled',result['state'])
        self.assertEqual(6,len(self.calls))
        with self.assertRaises(ValueError):await adapter.negotiate('pay-unfunded','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        async def forbidden(*args):self.fail('unfunded native economic operation')
        with self.assertRaises(ValueError):await adapter.consume_push('noah-phone-01',{
            'to':['ExpoPushToken[phone]'],'data':{'notification_type':'lightning_claim_request','payment_hash':'ab'*32,'amount_sat':5000}},
            'ExpoPushToken[phone]',invoice=forbidden,claim=forbidden)

    async def test_unfunded_bootstrap_still_requires_independent_pins_and_actor_presence(self):
        self.unfunded();self.manifest['evidence']['chain']['hash']='00'*32
        async def forbidden(*args):self.fail('unqualified wallet or HTTP call')
        with self.assertRaises(ValueError):await self.adapter(forbidden).enroll('noah-phone-01',forbidden,'ExpoPushToken[phone]',expiry=1500)
        self.assertEqual([],self.calls)

    def test_two_declared_phones_cannot_share_auth_mailbox_or_fallback_identity(self):
        from simulator.noah import NoahAdapter
        for shared in ('auth_pubkey','mailbox_id','fallback_script'):
            declaration=copy.deepcopy(self.manifest)
            phone=copy.deepcopy(declaration['phones'][0])
            phone.update(actor='noah-phone-02',username='bob',ark_address='tark-fixture-bob',
                auth_pubkey='03'+'22'*32,mailbox_id='03'+'33'*32,fallback_script='0014'+'44'*20)
            phone[shared]=declaration['phones'][0][shared];declaration['phones'].append(phone)
            declaration['capital']['actor_principal_sat']['noah-phone-02']=10000;declaration['capital']['principal_sat']=30000
            for section in ('phones','capital'):
                declaration['evidence'][section]=self.store.trace_capture('noah.readiness.'+section,{
                    'observed':copy.deepcopy(declaration[section]),'verified':True,'method':'independent_observation'})
            adapter=NoahAdapter(self.store,declaration,clock=lambda:1000)
            self.assertEqual('unqualified',adapter.readiness(enrollment=True)['status'],shared)


class NoahPrivateControllerTests(unittest.IsolatedAsyncioTestCase):
    setUp=fixtures.NoahAdapterTests.setUp
    tearDown=fixtures.NoahAdapterTests.tearDown
    adapter=fixtures.NoahAdapterTests.adapter

    def controller(self,qualified=True):
        from simulator.noah_controller import NoahController
        adapter=self.adapter();helper=self.root/'helper';helper.write_bytes(b'unit-test-helper')
        digest=hashlib.sha256(helper.read_bytes()).hexdigest()
        wallet=self.root/'phones'/'noah-phone-01';wallet.mkdir(parents=True)
        observation={'schema_version':1,'verified':True,'method':'independent_native_sdk_audit',
            'manifest_sha256':hashlib.sha256(fixtures.canonical(self.manifest).encode()).hexdigest(),
            'network':'signet','server_pubkey':PUB,'sdk_commit':fixtures.SDK,
            'helper_sha256':digest,'protocol':'noah-private-v1','wallets':{'noah-phone-01':str(wallet)}}
        reference=self.store.trace_capture('noah.native.qualification',observation) if qualified else None
        return NoahController(adapter,helper,digest,reference),adapter,helper

    async def test_missing_native_qualification_never_launches_or_contacts_backend(self):
        controller,adapter,helper=self.controller(False)
        with patch('simulator.noah_controller.json_command',side_effect=AssertionError('native launch')):
            with self.assertRaises(ValueError):await controller.enroll('setup-1','noah-phone-01','ExpoPushToken[phone]',expiry=1500)
        self.assertEqual([],self.calls)

    async def test_lost_private_reply_is_durable_and_never_replayed(self):
        controller,adapter,helper=self.controller()
        # GET k1 happens only after all native qualification and presence checks.
        async def replies(*args):return {'tag':'login','k1':'aa'*32+'_1000'}
        adapter.transport=replies
        calls=[]
        async def lost(argv,request,**kwargs):
            calls.append(request)
            kwargs['on_stderr_raw']({'raw':b'private-helper-diagnostic','bytes':25,'truncated':False})
            raise TimeoutError('private-untrusted-error')
        with patch('simulator.noah_controller.json_command',side_effect=lost):
            with self.assertRaises(ValueError):await controller.enroll('setup-1','noah-phone-01','ExpoPushToken[phone]',expiry=1500)
            from simulator.noah_controller import NoahController
            reopened=NoahController(adapter,helper,controller.helper_sha256,controller.qualification)
            with self.assertRaises(ValueError):await reopened.enroll('setup-1','noah-phone-01','ExpoPushToken[phone]',expiry=1500)
            with self.assertRaises(ValueError):await reopened.enroll('setup-2','noah-phone-01','ExpoPushToken[phone]',expiry=1500)
        self.assertEqual(1,len(calls))
        public=' '.join(row['payload'] for row in self.store.db.execute('SELECT payload FROM event'))
        self.assertNotIn('private-helper-diagnostic',public);self.assertNotIn('private-untrusted-error',public)
        artifacts=list((self.store.root/'noah-protected').glob('*.json'))
        self.assertTrue(any('private-helper-diagnostic' in p.read_text() or 'cHJpdmF0ZS1oZWxwZXItZGlhZ25vc3RpYw==' in p.read_text() for p in artifacts))

    async def test_same_actor_overlap_and_absence_do_not_launch(self):
        controller,adapter,helper=self.controller()
        entered=asyncio.Event();release=asyncio.Event();calls=[]
        async def blocked(*args,**kwargs):calls.append(True);entered.set();await release.wait();raise TimeoutError()
        adapter.enroll=blocked
        first=asyncio.create_task(controller.enroll('setup-1','noah-phone-01','ExpoPushToken[phone]',expiry=1500))
        await asyncio.wait_for(entered.wait(),2)
        with self.assertRaises(ValueError):await controller.enroll('setup-2','noah-phone-01','ExpoPushToken[phone]',expiry=1500)
        release.set()
        with self.assertRaises(ValueError):await first
        self.assertEqual([True],calls)
        self.store.set_online('noah-phone-01',False)
        with self.assertRaises(ValueError):await controller.enroll('setup-3','noah-phone-01','ExpoPushToken[phone]',expiry=1500)
        self.assertEqual([True],calls)

    async def test_binary_or_qualification_context_drift_holds_before_launch(self):
        controller,adapter,helper=self.controller();helper.write_bytes(b'replaced')
        with self.assertRaises(ValueError):await controller.enroll('setup-1','noah-phone-01','ExpoPushToken[phone]',expiry=1500)
        self.assertEqual([],self.calls)

    async def test_successful_private_helper_is_context_bound_and_has_no_public_secret(self):
        controller,adapter,helper=self.controller()
        token='private-enrollment-bearer';sig='30'+'aa'*70;grant=PUB+'11'*72
        async def replies(method,url,body,bearer):
            if url.endswith('/getk1'):return {'tag':'login','k1':'aa'*32+'_1000'}
            if url.endswith('/auth/login'):return {'access_token':token,'token_type':'Bearer','expires_in_seconds':1000}
            if url.endswith('/register'):return {'status':'OK','lightning_address':'alice@noah.fixture.example'}
            if url.endswith('/user_info'):return {'lightning_address':'alice@noah.fixture.example','user_status':'active'}
            return {'success':True}
        adapter.transport=replies
        async def native(argv,request,**kwargs):
            self.assertEqual([str(helper)],argv)
            self.assertEqual(str(self.root/'phones'/'noah-phone-01'),request['wallet_path'])
            self.assertEqual(PUB,request['expected_server_pubkey'])
            result={k:request[k] for k in ('protocol','operation','actor','action_id')}
            result['material']={'key':PUB,'sig':sig,'mailbox_id':PUB,'expiry':1500,'encoded':grant}
            raw=json.dumps(result).encode();kwargs['on_stdout_raw']({'raw':raw,'bytes':len(raw),'truncated':False,'exit_code':0})
            return result
        with patch('simulator.noah_controller.json_command',side_effect=native):
            result=await controller.enroll('setup-1','noah-phone-01','ExpoPushToken[phone]',expiry=1500)
        self.assertEqual('enrolled',result['state'])
        self.assertEqual('completed',self.store.db.execute('SELECT state FROM noah_control').fetchone()[0])
        public=' '.join(row['payload'] for row in self.store.db.execute('SELECT payload FROM event'))
        for secret in (token,sig,grant,'ExpoPushToken[phone]'):self.assertNotIn(secret,public)

    async def test_cancelled_setup_leaves_durable_hold(self):
        controller,adapter,helper=self.controller();entered=asyncio.Event()
        async def blocked(*args,**kwargs):entered.set();await asyncio.Future()
        adapter.enroll=blocked
        task=asyncio.create_task(controller.enroll('setup-cancel','noah-phone-01','ExpoPushToken[phone]',expiry=1500))
        await asyncio.wait_for(entered.wait(),2);task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual('outcome_unknown',self.store.db.execute('SELECT state FROM noah_control').fetchone()[0])
        with self.assertRaises(ValueError):await controller.enroll('setup-next','noah-phone-01','ExpoPushToken[phone]',expiry=1500)


class NoahCancelledObservationTests(unittest.IsolatedAsyncioTestCase):
    setUp=fixtures.NoahAdapterTests.setUp
    tearDown=fixtures.NoahAdapterTests.tearDown
    adapter=fixtures.NoahAdapterTests.adapter

    async def test_cancelled_http_waiter_preserves_late_private_reply_until_drained(self):
        entered=asyncio.Event();release=asyncio.Event()
        async def late(*args):entered.set();await release.wait();return {'private_phone_body':'late-private-reply'}
        adapter=self.adapter(late)
        task=asyncio.create_task(adapter._request('POST','/v0/user_info',{},'private-bearer',actor='noah-phone-01'))
        await asyncio.wait_for(entered.wait(),2);task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(1,adapter.pending_observations)
        release.set();await adapter.drain_observations()
        self.assertEqual(0,adapter.pending_observations)
        artifacts=[json.loads(p.read_text()) for p in (self.store.root/'noah-protected').glob('*.json')]
        replies=[item for item in artifacts if item['kind']=='http.response']
        self.assertEqual({'private_phone_body':'late-private-reply'},replies[0]['payload']['decoded_response'])
        public=' '.join(row['payload'] for row in self.store.db.execute('SELECT payload FROM event'))
        self.assertNotIn('late-private-reply',public);self.assertNotIn('private-bearer',public)

    async def test_cancelled_http_waiter_preserves_late_private_error_without_reissuing(self):
        entered=asyncio.Event();release=asyncio.Event();calls=[]
        async def late(*args):calls.append(True);entered.set();await release.wait();raise TimeoutError('private-late-http-diagnostic')
        adapter=self.adapter(late)
        task=asyncio.create_task(adapter._request('POST','/v0/user_info',{},'private-bearer',actor='noah-phone-01'))
        await asyncio.wait_for(entered.wait(),2);task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        release.set();await adapter.drain_observations()
        self.assertEqual([True],calls);self.assertEqual(0,adapter.pending_observations)
        artifacts=[json.loads(p.read_text()) for p in (self.store.root/'noah-protected').glob('*.json')]
        errors=[item for item in artifacts if item['kind']=='http.error']
        self.assertEqual('private-late-http-diagnostic',errors[0]['payload']['available_error_text'])
        public=' '.join(row['payload'] for row in self.store.db.execute('SELECT payload FROM event'))
        self.assertNotIn('private-late-http-diagnostic',public)

