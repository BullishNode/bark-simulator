"""Private controller tests; no backend or SDK journey is qualified here."""
import copy
import unittest

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

