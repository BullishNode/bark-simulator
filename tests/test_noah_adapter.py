"""Protocol and persistence tests; these do not qualify backend/payment journeys."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from simulator.model import SIGNET_GENESIS, canonical
from simulator.store import Store

PIN='8e68ba5c3f032d9fd55e2f2f1f2af1441395eff0'
SDK='d47c6a4d115b30bf56219d69251fa9238d13f32d'
PUB='02'+'11'*32
HASH='ab'*32


def manifest(store):
    value={'schema_version':1,
        'origin':{'https_origin':'https://noah.fixture.example','lnurl_domain':'noah.fixture.example','ca_sha256':'12'*32},
        'source':{'noah_commit':PIN,'transport_patch_sha256':'13'*32,'binary_sha256':'14'*32,'healthy_services':['backend','postgres','redis','expo']},
        'chain':{'network':'signet','genesis':SIGNET_GENESIS,'server_pubkey':PUB,'lightning_node_pubkey':PUB,'captaind_commit':SDK,'phone_sdk_commit':SDK,'forwarder_sdk_commit':SDK},
        'phones':[{'actor':'noah-phone-01','username':'alice','auth_pubkey':PUB,'ark_address':'tark-fixture-address','mailbox_id':PUB,'fallback_script':'0014'+'22'*20}],
        'forwarder':{'enabled':False,'identity':None,'ready':False},
        'capital':{'allocation_id':'noah-capital-fixture-1','principal_sat':20000,'actor_principal_sat':{'noah-payer-01':10000,'noah-phone-01':10000},'per_action_fee_sat':1000,'campaign_fee_sat':5000},
        'evidence':{}}
    for section in ('origin','source','chain','phones','forwarder','capital'):
        value['evidence'][section]=store.trace_capture('noah.readiness.'+section,{'observed':copy.deepcopy(value[section]),'verified':True,'method':'independent_observation'})
    return value


class NoahAdapterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.store=Store(self.root/'state','synthetic',5000);self.store.attach_trace()
        self.store.actor('noah-phone-01','noah-phone');self.store.actor('noah-payer-01','noah-payer')
        self.manifest=manifest(self.store);self.calls=[];self.phone=self.manifest['phones'][0]
        self.metadata=canonical([['text/identifier','alice@noah.fixture.example'],['text/plain','Paying satoshis to alice@noah.fixture.example']])
        self.first={'callback':'https://noah.fixture.example/.well-known/lnurlp/alice','minSendable':1000,'maxSendable':1000000000,'metadata':self.metadata,'tag':'payRequest','commentAllowed':280}
        self.invoice='fixture-public-invoice-not-a-real-bolt11'
        self.proof={'payment_hash':HASH,'invoice_sha256':hashlib.sha256(self.invoice.encode()).hexdigest(),'amount_msat':5000000,'network':'signet','expires_at':2000,'metadata_sha256':hashlib.sha256(self.metadata.encode()).hexdigest(),'signature_checked':True,'node_pubkey':PUB}
        self.binding=self.store.trace_capture('noah.recipient.invoice',{'actor':self.phone['actor'],'auth_pubkey':PUB,'ark_address':self.phone['ark_address'],'payment_hash':HASH,'invoice_sha256':self.proof['invoice_sha256'],'amount_msat':5000000,'source':'device','registered_destination_checked':True},actor=self.phone['actor'])
    def tearDown(self):
        self.store.close();self.tmp.cleanup()
    def adapter(self,reply=None):
        from simulator.noah import NoahAdapter
        async def transport(method,url,body=None,bearer=None):
            self.calls.append((method,url,copy.deepcopy(body),bearer))
            if reply:return await reply(method,url,body,bearer)
            if 'amount=' in url:return {'pr':self.invoice,'routes':[],'ark':self.phone['ark_address']}
            return copy.deepcopy(self.first)
        async def verify(invoice,amount,metadata,network,now):return copy.deepcopy(self.proof)
        return NoahAdapter(self.store,self.manifest,transport=transport,invoice_verifier=verify,clock=lambda:1000)
    async def test_missing_manifest_blocks_before_any_request(self):
        from simulator.noah import NoahAdapter
        adapter=NoahAdapter(self.store,None,transport=lambda *a,**kw:self.fail('network request'),clock=lambda:1000)
        self.assertEqual('unqualified',adapter.readiness()['status'])
        with self.assertRaises(ValueError):await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
    async def test_real_two_step_contract_uses_same_path_and_exact_msat(self):
        adapter=self.adapter()
        result=await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        self.assertEqual('invoice_frozen',result['state'])
        self.assertEqual(['https://noah.fixture.example/.well-known/lnurlp/alice','https://noah.fixture.example/.well-known/lnurlp/alice?amount=5000000'],[row[1] for row in self.calls])
        self.assertNotIn('ark=',self.calls[-1][1])
        self.assertEqual(HASH,result['payment_hash'])
        self.assertEqual(5000,adapter.payment_request('payment-1')['args']['amount_sat'])
    async def test_foreign_callback_rejected_without_fetching_it(self):
        self.first['callback']='https://noahwallet.io/.well-known/lnurlp/alice'
        with self.assertRaises(ValueError):await self.adapter().negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        self.assertEqual(1,len(self.calls))
    async def test_metadata_hash_failure_records_compatibility_hold_and_never_dispatches(self):
        self.proof['metadata_sha256']='ff'*32
        adapter=self.adapter()
        with self.assertRaises(ValueError):await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        with self.assertRaises(ValueError):adapter.payment_request('payment-1')
        self.assertEqual('compatibility_failure',adapter.intent('payment-1')['state'])
    async def test_other_user_valid_invoice_binding_is_refused(self):
        wrong=self.store.trace_capture('noah.recipient.invoice',{'actor':'noah-phone-mallory','auth_pubkey':PUB,'ark_address':self.phone['ark_address'],'payment_hash':HASH,'invoice_sha256':self.proof['invoice_sha256'],'amount_msat':5000000,'source':'device','registered_destination_checked':True},actor='noah-phone-mallory')
        with self.assertRaises(ValueError):await self.adapter().negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=wrong)
    async def test_fractional_sat_refused_instead_of_truncated(self):
        with self.assertRaises(ValueError):await self.adapter().negotiate('payment-1','noah-payer-01','noah-phone-01',5000001,binding=self.binding)
        self.assertEqual([],self.calls)
    async def test_timeout_keeps_intent_and_does_not_request_replacement_invoice(self):
        async def timeout(method,url,body,bearer):
            if 'amount=' in url:raise TimeoutError()
            return self.first
        adapter=self.adapter(timeout)
        result=await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        self.assertEqual('outcome_unknown',result['state']);self.assertIsNone(result['payment_hash'])
        await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        self.assertEqual(2,len(self.calls))
        with self.assertRaises(ValueError):await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',6000000,binding=self.binding)
    async def test_lost_payment_reply_is_once_only_across_reopen_and_hash_reconcile(self):
        adapter=self.adapter();await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        paid=[]
        async def lost(request):paid.append(request);raise TimeoutError()
        await adapter.dispatch('payment-1',lost)
        self.assertEqual('outcome_unknown',adapter.intent('payment-1')['state'])
        self.store.close();self.store=Store(self.root/'state','synthetic',5000);self.store.attach_trace();adapter=self.adapter()
        await adapter.dispatch('payment-1',lost);self.assertEqual(1,len(paid))
        queries=[]
        async def status(payment_hash):queries.append(payment_hash);return {'payment_hash':payment_hash,'state':'pending'}
        await adapter.reconcile('payment-1',status);self.assertEqual([HASH],queries)
        self.assertEqual('outcome_unknown',adapter.intent('payment-1')['state'])
    async def test_node_paid_ack_is_not_independently_qualified_recipient_collection(self):
        adapter=self.adapter();await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        async def submit(request):return {'payment_hash':HASH,'paid':True}
        await adapter.dispatch('payment-1',submit)
        self.assertEqual('outcome_unknown',adapter.intent('payment-1')['state'])
        async def status(payment_hash):return {'payment_hash':payment_hash,'state':'succeeded'}
        await adapter.reconcile('payment-1',status)
        self.assertEqual('outcome_unknown',adapter.intent('payment-1')['state'])
    async def test_unknown_payer_hold_prevents_another_invoice_request(self):
        adapter=self.adapter();await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        async def lost(request):raise TimeoutError()
        await adapter.dispatch('payment-1',lost)
        with self.assertRaises(ValueError):await adapter.negotiate('payment-2','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        self.assertEqual(2,len(self.calls))
    async def test_gone_recipient_protocol_uses_existing_binding_without_wallet_call(self):
        self.store.actor('noah-phone-01','noah-phone');self.store.set_online('noah-phone-01',False)
        adapter=self.adapter()
        result=await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        self.assertEqual('invoice_frozen',result['state'])
        async def signer(*args):self.fail('absent phone signing call')
        with self.assertRaises(ValueError):await adapter.enroll('noah-phone-01',signer,'ExpoPushToken[phone]',expiry=1500)
        self.assertFalse(self.store.online('noah-phone-01'))
    async def test_manifest_or_evidence_drift_holds(self):
        adapter=self.adapter();self.assertEqual('ready_for_dispatch',adapter.readiness()['status'])
        changed=copy.deepcopy(self.manifest);changed['capital']['per_action_fee_sat']=2000
        from simulator.noah import NoahAdapter
        self.assertEqual('unqualified',NoahAdapter(self.store,changed,clock=lambda:1000).readiness()['status'])
        self.manifest['evidence']['chain']['hash']='00'*32
        self.assertEqual('unqualified',adapter.readiness()['status'])
    async def test_original_actors_or_old_allocation_never_qualify(self):
        from simulator.noah import NoahAdapter
        for mutate in ('actor','allocation'):
            changed=copy.deepcopy(self.manifest)
            if mutate=='actor':changed['phones'][0]['actor']='actor-09'
            else:changed['capital']['allocation_id']='owner-renewal-2026-10-12-traffic-2'
            self.assertEqual('unqualified',NoahAdapter(self.store,changed,clock=lambda:1000).readiness()['status'])
    async def test_same_server_ark_negotiation_has_separate_transport_no_ln_credit(self):
        self.first['ark']=self.phone['ark_address']
        async def reply(method,url,body,bearer):
            if 'amount=' in url:return {'pr':'','routes':[],'ark':self.phone['ark_address']}
            return self.first
        adapter=self.adapter(reply)
        result=await adapter.negotiate('ark-1','noah-payer-01','noah-phone-01',5000000,ark_server=PUB)
        self.assertEqual('ark_negotiated',result['state']);self.assertEqual('ark_lnurl',result['transport'])
        self.assertTrue(all('ark='+PUB in row[1] for row in self.calls));self.assertIsNone(result['payment_hash'])
        with self.assertRaises(ValueError):adapter.payment_request('ark-1')
    async def test_journal_intent_and_frozen_proof_drift_hold_dispatch(self):
        adapter=self.adapter();await adapter.negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        row=adapter.intent('payment-1');altered=copy.deepcopy(row['intent']);altered['maximum_fee_sat']+=1
        self.store.db.execute('UPDATE noah_intent SET intent=? WHERE id=?',(canonical(altered),'payment-1'))
        with self.assertRaises(ValueError):adapter.payment_request('payment-1')
        self.store.db.execute('UPDATE noah_intent SET intent=? WHERE id=?',(canonical(row['intent']),'payment-1'))
        altered=copy.deepcopy(row['proof']);altered['payment_hash']='ff'*32
        self.store.db.execute('UPDATE noah_intent SET proof=?,payment_hash=? WHERE id=?',(canonical(altered),altered['payment_hash'],'payment-1'))
        with self.assertRaises(ValueError):adapter.payment_request('payment-1')
    async def test_absent_payer_and_dispatched_original_action_hold(self):
        self.store.actor('noah-payer-01','noah-payer');self.store.set_online('noah-payer-01',False)
        with self.assertRaises(ValueError):await self.adapter().negotiate('payment-1','noah-payer-01','noah-phone-01',5000000,binding=self.binding)
        self.assertEqual([],self.calls)
    async def test_native_verifier_rejects_each_wrong_public_field(self):
        baseline=copy.deepcopy(self.proof)
        for field,value in [('signature_checked',False),('network','bitcoin'),('amount_msat',5001000),('expires_at',999),('node_pubkey','03'+'33'*32),('invoice_sha256','ff'*32)]:
            self.proof=copy.deepcopy(baseline);self.proof[field]=value
            with self.assertRaises(ValueError):await self.adapter().negotiate('invalid-'+field,'noah-payer-01','noah-phone-01',5000000,binding=self.binding)


class NoahEnrollmentTests(unittest.IsolatedAsyncioTestCase):
    setUp=NoahAdapterTests.setUp
    tearDown=NoahAdapterTests.tearDown
    adapter=NoahAdapterTests.adapter
    async def test_login_registration_and_signed_grant_do_not_enter_public_journal(self):
        k1='aa'*32+'_1000';token='test-private-bearer-value';sig='30'+'aa'*70;encoded=PUB+'11'*72
        async def replies(method,url,body,bearer):
            if url.endswith('/getk1'):return {'tag':'login','k1':k1}
            if url.endswith('/auth/login'):
                self.assertEqual({'key':PUB,'sig':sig,'k1':k1},body)
                return {'access_token':token,'token_type':'Bearer','expires_at':'2030-01-01T00:00:00Z','expires_in_seconds':259200}
            self.assertEqual(token,bearer)
            if url.endswith('/register'):return {'status':'OK','event':'REGISTERED','lightning_address':'alice@noah.fixture.example','user_status':'active'}
            if url.endswith('/user_info'):return {'lightning_address':'alice@noah.fixture.example','user_status':'active'}
            return {'success':True}
        async def signer(challenge,expiry):
            self.assertEqual(k1,challenge)
            return {'key':PUB,'sig':sig,'mailbox_id':PUB,'expiry':expiry,'encoded':encoded}
        adapter=self.adapter(replies)
        result=await adapter.enroll('noah-phone-01',signer,'ExpoPushToken[phone-01]',expiry=1500)
        self.assertEqual('enrolled',result['state'])
        self.assertEqual(['/v0/getk1','/v0/auth/login','/v0/register','/v0/register_push_token','/v0/mailbox/authorize','/v0/user_info'],[row[1].split('noah.fixture.example')[1] for row in self.calls])
        journal=' '.join(row['payload'] for row in self.store.db.execute('SELECT payload FROM event'))
        for secret in (token,sig,encoded,'ExpoPushToken[phone-01]'):self.assertNotIn(secret,journal)
    async def test_bad_k1_never_sent_to_vulnerable_login(self):
        async def replies(*args):return {'tag':'login','k1':'maintenance:last_round_timestamp'}
        async def signer(*args):self.fail('unexpected signing')
        with self.assertRaises(ValueError):await self.adapter(replies).enroll('noah-phone-01',signer,'ExpoPushToken[phone-01]',expiry=1500)
        self.assertEqual(1,len(self.calls))
    async def test_original_push_submission_uses_private_enrollment_session_and_known_invoice(self):
        token='private-session-for-original-push';k1='aa'*32+'_1000';transaction='00000000-0000-4000-8000-000000000002'
        async def replies(method,url,body,bearer):
            if url.endswith('/getk1'):return {'tag':'login','k1':k1}
            if url.endswith('/auth/login'):return {'access_token':token,'token_type':'Bearer','expires_at':'2030-01-01T00:00:00Z','expires_in_seconds':259200}
            self.assertEqual(token,bearer)
            if url.endswith('/register'):return {'status':'OK','lightning_address':'alice@noah.fixture.example','user_status':'active'}
            if url.endswith('/user_info'):return {'lightning_address':'alice@noah.fixture.example','user_status':'active'}
            if url.endswith('/submit_invoice'):self.assertEqual({'transaction_id':transaction,'invoice':self.invoice},body)
            return {'success':True}
        async def signer(challenge,expiry):return {'key':PUB,'sig':'30'+'aa'*70,'mailbox_id':PUB,'expiry':expiry,'encoded':PUB+'11'*72}
        adapter=self.adapter(replies);await adapter.enroll('noah-phone-01',signer,'ExpoPushToken[phone]',expiry=1500)
        async def invoice(amount):return {'invoice':self.invoice,'payment_hash':HASH}
        async def claim():self.fail('unexpected claim')
        envelope={'to':['ExpoPushToken[phone]'],'data':canonical({'notification_type':'lightning_invoice_request','transaction_id':transaction,'amount':5000000})}
        result=await adapter.consume_push('noah-phone-01',envelope,'ExpoPushToken[phone]',invoice=invoice,claim=claim)
        self.assertEqual('invoice_submitted',result['state'])
        with self.assertRaises(ValueError):await adapter.submit_invoice('noah-phone-01',{'transaction_id':transaction,'invoice':'different-invoice'})
        with self.assertRaises(ValueError):await adapter.submit_invoice('noah-phone-01',{'transaction_id':'00000000-0000-4000-8000-000000000003','invoice':self.invoice})
        journal=' '.join(row['payload'] for row in self.store.db.execute('SELECT payload FROM event'))
        self.assertNotIn(token,journal)


class NoahForwarderReadinessTests(unittest.IsolatedAsyncioTestCase):
    setUp=NoahAdapterTests.setUp
    tearDown=NoahAdapterTests.tearDown
    adapter=NoahAdapterTests.adapter
    def observe_changed(self,section):
        self.manifest['evidence'][section]=self.store.trace_capture('noah.readiness.'+section,{'observed':copy.deepcopy(self.manifest[section]),'verified':True,'method':'independent_observation'})
    async def test_enabled_forwarder_requires_exact_owned_route_identity_record_and_own_capital(self):
        self.manifest['forwarder']={'enabled':True,'identity':'noah-forwarder-01','ready':True,
            'barkd_url':'http://noah-barkd-signet.internal:3000','auth_pubkey':PUB,'mailbox_id':PUB,'fallback_script':'0014'+'33'*20}
        self.observe_changed('forwarder')
        self.assertEqual('unqualified',self.adapter().readiness()['status'])
        self.manifest['capital']['actor_principal_sat']['noah-forwarder-01']=5000;self.manifest['capital']['principal_sat']=25000;self.observe_changed('capital')
        self.manifest['forwarder']['barkd_url']='http://stock-bark.internal:3000';self.observe_changed('forwarder')
        self.assertEqual('unqualified',self.adapter().readiness()['status'])
        self.manifest['forwarder']['barkd_url']='http://noah-barkd-signet.internal:3000';self.manifest['forwarder']['mailbox_id']=None;self.observe_changed('forwarder')
        self.assertEqual('unqualified',self.adapter().readiness()['status'])
        self.manifest['forwarder']['mailbox_id']=PUB;self.observe_changed('forwarder')
        self.assertEqual('ready_for_dispatch',self.adapter().readiness()['status'])


class NoahPushTests(unittest.IsolatedAsyncioTestCase):
    async def test_original_expo_payload_submits_exact_invoice_without_auto_claim(self):
        from simulator.noah import consume_expo_push
        calls=[];transaction='00000000-0000-4000-8000-000000000001'
        original=canonical({'notification_type':'lightning_invoice_request','transaction_id':transaction,'amount':5000000})
        async def invoice(amount_sat):calls.append(('invoice',amount_sat));return {'invoice':'native-invoice','payment_hash':HASH}
        async def submit(body):calls.append(('submit',body));return {'success':True}
        async def claim():self.fail('invoice handler must not bypass later claim push')
        result=await consume_expo_push({'to':['ExpoPushToken[phone]'],'data':original},'ExpoPushToken[phone]',invoice=invoice,submit=submit,claim=claim)
        self.assertEqual([('invoice',5000),('submit',{'transaction_id':transaction,'invoice':'native-invoice'})],calls)
        self.assertEqual('invoice_submitted',result['state'])
    async def test_fractional_original_push_or_wrong_expo_token_never_calls_wallet(self):
        from simulator.noah import consume_expo_push
        async def fail(*args):self.fail('unsafe wallet call')
        for payload in ({'to':['ExpoPushToken[wrong]'],'data':canonical({'notification_type':'lightning_claim_request','payment_hash':HASH,'amount_sat':5000})},{'to':['ExpoPushToken[phone]'],'data':canonical({'notification_type':'lightning_invoice_request','transaction_id':'00000000-0000-4000-8000-000000000001','amount':5000001})}):
            with self.assertRaises(ValueError):await consume_expo_push(payload,'ExpoPushToken[phone]',invoice=fail,submit=fail,claim=fail)
    async def test_claim_is_separate_original_push_and_has_no_invoice_creation(self):
        from simulator.noah import consume_expo_push
        async def fail(*args):self.fail('unexpected invoice request')
        claimed=[]
        async def claim():claimed.append(True);return {'actual_claim_evidence':'fixture-only'}
        result=await consume_expo_push({'to':['ExpoPushToken[phone]'],'data':canonical({'notification_type':'lightning_claim_request','payment_hash':HASH,'amount_sat':5000})},'ExpoPushToken[phone]',invoice=fail,submit=fail,claim=claim)
        self.assertEqual([True],claimed);self.assertEqual('claim_called',result['state']);self.assertFalse(result['outcome_verified'])


class NoahDurablePushTests(unittest.IsolatedAsyncioTestCase):
    setUp=NoahAdapterTests.setUp
    tearDown=NoahAdapterTests.tearDown
    adapter=NoahAdapterTests.adapter
    async def test_original_duplicate_push_never_creates_another_invoice_after_lost_submit(self):
        adapter=self.adapter();self.store.actor('noah-phone-01','noah-phone')
        transaction='00000000-0000-4000-8000-000000000001';calls=[]
        envelope={'to':['ExpoPushToken[phone]'],'data':canonical({'notification_type':'lightning_invoice_request','transaction_id':transaction,'amount':5000000})}
        async def invoice(amount):calls.append(('invoice',amount));return {'invoice':self.invoice,'payment_hash':HASH}
        async def submit(body):calls.append(('submit',body));raise TimeoutError()
        async def claim():self.fail('automatic claim')
        result=await adapter.consume_push('noah-phone-01',envelope,'ExpoPushToken[phone]',invoice=invoice,submit=submit,claim=claim)
        self.assertEqual('outcome_unknown',result['state'])
        await adapter.consume_push('noah-phone-01',envelope,'ExpoPushToken[phone]',invoice=invoice,submit=submit,claim=claim)
        self.assertEqual(2,len(calls))
        changed=copy.deepcopy(envelope);changed['data']=canonical({'notification_type':'lightning_invoice_request','transaction_id':transaction,'amount':6000000})
        with self.assertRaises(ValueError):await adapter.consume_push('noah-phone-01',changed,'ExpoPushToken[phone]',invoice=invoice,submit=submit,claim=claim)
    async def test_absent_phone_does_not_consume_original_push_with_wallet_callbacks(self):
        adapter=self.adapter();self.store.actor('noah-phone-01','noah-phone');self.store.set_online('noah-phone-01',False)
        async def fail(*args):self.fail('absent wallet call')
        with self.assertRaises(ValueError):await adapter.consume_push('noah-phone-01',{'to':['ExpoPushToken[phone]'],'data':canonical({'notification_type':'lightning_claim_request','payment_hash':HASH,'amount_sat':5000})},'ExpoPushToken[phone]',invoice=fail,submit=fail,claim=fail)


class NoahCoverageTests(unittest.TestCase):
    def test_all_required_catalogue_rows_remain_unqualified_without_real_runs(self):
        from simulator.noah_coverage import coverage
        result=coverage(None)
        self.assertEqual(13,len(result['scenarios']));self.assertEqual(12,len(result['lnurl_journeys']))
        self.assertTrue(all(row['status']=='unqualified' for row in result['scenarios']+result['lnurl_journeys']))
        self.assertIn('5→50→200',result['scenarios'][11]['required'])
        self.assertIn('S3',result['scenarios'][10]['required'])
        self.assertIn('mid-swap',result['scenarios'][12]['required'])
