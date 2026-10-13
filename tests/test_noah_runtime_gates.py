"""Regressions for actual adapter integration gates; no live journey credit."""
import copy
import unittest

import test_noah_adapter as fixtures
import test_noah_inbox as inboxfixtures

SERVER='7596c0dc1005c619c4c9528f9e408f005ed7793c'

class NativeActorGates(unittest.IsolatedAsyncioTestCase):
    setUp=fixtures.NoahAdapterTests.setUp
    tearDown=fixtures.NoahAdapterTests.tearDown
    def test_fresh_native_actor_identifiers_are_accepted_without_aliases(self):
        from simulator.noah import NoahAdapter
        value=copy.deepcopy(self.manifest)
        value['phones'][0]['actor']='actor-41'
        value['capital']['actor_principal_sat']={'actor-41':10000,'actor-241':10000}
        self.store.actor('actor-41','noah-phone');self.store.actor('actor-241','noah-payer')
        for section in ('phones','capital'):
            value['evidence'][section]=self.store.trace_capture('noah.readiness.'+section,{
                'observed':copy.deepcopy(value[section]),'verified':True,'method':'independent_observation'})
        adapter=NoahAdapter(self.store,value,clock=lambda:1000)
        self.assertEqual('ready_for_dispatch',adapter.readiness()['status'])
        self.assertFalse(self.store.ordinary_actor_available('actor-41'))

class UpdatedInboxGates(unittest.IsolatedAsyncioTestCase):
    setUp=fixtures.NoahAdapterTests.setUp
    tearDown=fixtures.NoahAdapterTests.tearDown
    adapter=fixtures.NoahAdapterTests.adapter
    inbox=inboxfixtures.NoahInboxTests.inbox
    async def test_qualified_new_nginx_configuration_is_used_not_stale_constant(self):
        inbox,adapter=self.inbox()
        self.manifest['source']['phone_transport']={'spool_source_sha256':'45'*32,'nginx_sha256':'46'*32}
        self.manifest['evidence']['source']=self.store.trace_capture('noah.readiness.source',{
            'observed':copy.deepcopy(self.manifest['source']),'verified':True,'method':'independent_observation'})
        proof={'verified':True,'method':'independent_transport_audit','https_origin':self.manifest['origin']['https_origin'],
            **self.manifest['source']['phone_transport'],'backend_manifest_sha256':'34'*32,
            'token_mode':'opaque_native_auth','pull_path':'/test/phone/pushes','token_path':'/test/phone/token'}
        inbox.qualification=self.store.trace_capture('noah.phone.transport',proof)
        inbox._ready('actor-41')

class CompatibleEpochGates(unittest.IsolatedAsyncioTestCase):
    setUp=fixtures.NoahAdapterTests.setUp
    tearDown=fixtures.NoahAdapterTests.tearDown
    def test_qualified_unchanged_protocol_server_upgrade_can_keep_exact_sdk(self):
        from simulator.noah import NoahAdapter
        value=copy.deepcopy(self.manifest);value['chain']['captaind_commit']=SERVER
        value['chain']['server_binary_sha256']='37'*32
        value['source']['driver_binary_sha256']='38'*32
        value['evidence']['source']=self.store.trace_capture('noah.readiness.source',{'observed':copy.deepcopy(value['source']),'verified':True,'method':'independent_observation'})
        proof={'verified':True,'method':'independent_protocol_compatibility_audit',
            'chain':copy.deepcopy(value['chain']), 'live_identity_checked':True,
            'server_binary_sha256':'37'*32,'driver_binary_sha256':'38'*32,
            'source_sha256':{name:{'server':'39'*32,'sdk':'39'*32} for name in ('bark','lib','server-rpc')}}
        value['chain']['compatibility']=self.store.trace_capture('noah.protocol.compatibility',proof)
        value['evidence']['chain']=self.store.trace_capture('noah.readiness.chain',{
            'observed':copy.deepcopy(value['chain']),'verified':True,'method':'independent_observation'})
        adapter=NoahAdapter(self.store,value,clock=lambda:1000)
        self.assertEqual('ready_for_dispatch',adapter.readiness()['status'])

    def test_changed_rpc_or_unchecked_live_identity_never_qualifies_compatibility(self):
        from simulator.noah import NoahAdapter
        for changed in ('rpc','live','binary'):
            value=copy.deepcopy(self.manifest);value['chain'].update(captaind_commit=SERVER,server_binary_sha256='37'*32)
            value['source']['driver_binary_sha256']='38'*32
            proof={'verified':True,'method':'independent_protocol_compatibility_audit','chain':copy.deepcopy(value['chain']),
                'live_identity_checked':True,'server_binary_sha256':'37'*32,'driver_binary_sha256':'38'*32,
                'source_sha256':{name:{'server':'39'*32,'sdk':'39'*32} for name in ('bark','lib','server-rpc')}}
            if changed=='rpc':proof['source_sha256']['server-rpc']['server']='40'*32
            elif changed=='live':proof['live_identity_checked']=False
            else:proof['driver_binary_sha256']='41'*32
            value['chain']['compatibility']=self.store.trace_capture('noah.protocol.compatibility',proof)
            for section in ('chain','source'):
                value['evidence'][section]=self.store.trace_capture('noah.readiness.'+section,{'observed':copy.deepcopy(value[section]),'verified':True,'method':'independent_observation'})
            self.assertEqual('unqualified',NoahAdapter(self.store,value,clock=lambda:1000).readiness()['status'])

class TwoHundredPhoneIdentities(unittest.IsolatedAsyncioTestCase):
    setUp=fixtures.NoahAdapterTests.setUp
    tearDown=fixtures.NoahAdapterTests.tearDown
    def test_two_hundred_unique_native_phones_include_three_digit_ids(self):
        from simulator.noah import NoahAdapter
        value=copy.deepcopy(self.manifest);value['phones']=[];value['capital']['actor_principal_sat']={'actor-241':10000}
        for index in range(41,241):
            key=f'{index:064x}'
            phone={'actor':f'actor-{index:02d}','username':f'phone{index}','auth_pubkey':'02'+key,
                'ark_address':f'tark-unique-fixture-{index}','mailbox_id':'03'+key,'fallback_script':'0014'+f'{index:040x}'}
            value['phones'].append(phone);value['capital']['actor_principal_sat'][phone['actor']]=10000
        value['capital']['principal_sat']=2010000
        for section in ('phones','capital'):
            value['evidence'][section]=self.store.trace_capture('noah.readiness.'+section,{'observed':copy.deepcopy(value[section]),'verified':True,'method':'independent_observation'})
        self.assertEqual('ready_for_dispatch',NoahAdapter(self.store,value,clock=lambda:1000).readiness()['status'])
