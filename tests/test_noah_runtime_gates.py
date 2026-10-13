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
