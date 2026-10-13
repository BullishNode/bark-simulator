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
        async def blocked(*args):calls.append(True);entered.set();await release.wait();raise TimeoutError()
        adapter.enroll=blocked
        first=asyncio.create_task(controller.enroll('setup-1','noah-phone-01','ExpoPushToken[phone]',expiry=1500))
        await entered.wait()
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

