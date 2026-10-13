"""Scoped socket tests preserve HTTPS hostname verification without networking."""
import io
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock,patch


class NoahTLSTests(unittest.IsolatedAsyncioTestCase):
    async def test_declared_ip_mapping_preserves_hostname_sni_and_http_host(self):
        from simulator.noah import HTTPSNoahTransport
        transport=HTTPSNoahTransport('https://noah-signet.test',resolve_to='170.75.167.47')
        self.assertTrue(transport.context.check_hostname)
        self.assertEqual(ssl.CERT_REQUIRED,transport.context.verify_mode)
        class Socket:
            sent=b''
            def setsockopt(self,*args):pass
            def sendall(self,value):self.sent+=bytes(value)
            def makefile(self,*args):return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{"ok": true}')
            def close(self):pass
        sock=Socket();context=MagicMock();context.wrap_socket.return_value=sock
        transport.context=context
        with patch('simulator.noah.socket.create_connection',return_value=sock) as connect:
            result=await transport('POST','https://noah-signet.test/test/phone/pushes',{'cursor':0,'limit':20},'private-bearer')
        self.assertEqual({'ok':True},result)
        self.assertEqual(('170.75.167.47',443),connect.call_args.args[0])
        context.wrap_socket.assert_called_once_with(sock,server_hostname='noah-signet.test')
        self.assertIn(b'Host: noah-signet.test\r\n',sock.sent)
        self.assertNotIn(b'Host: 170.75.167.47',sock.sent)

    async def test_invalid_mapping_and_foreign_request_are_refused_before_socket(self):
        from simulator.noah import HTTPSNoahTransport
        for value in ('noahwallet.io','170.75.167.47:443','170.075.167.47',''):
            with self.assertRaises(ValueError):HTTPSNoahTransport('https://noah-signet.test',resolve_to=value)
        transport=HTTPSNoahTransport('https://noah-signet.test',resolve_to='170.75.167.47')
        with patch('simulator.noah.socket.create_connection',side_effect=AssertionError('foreign socket')):
            with self.assertRaises(ValueError):await transport('GET','https://noahwallet.io/test/phone/pushes')

    def test_live_mapping_must_match_independent_origin_observation(self):
        import copy
        import test_noah_adapter as fixtures
        from simulator.store import Store
        from simulator.noah import HTTPSNoahTransport,NoahAdapter
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory)/'state','live',5000);store.attach_trace()
            try:
                declaration=fixtures.manifest(store)
                transport=HTTPSNoahTransport(declaration['origin']['https_origin'],resolve_to='170.75.167.47')
                declaration['origin'].update(ca_sha256=transport.ca_sha256,resolve_to='170.75.167.47')
                declaration['evidence']['origin']=store.trace_capture('noah.readiness.origin',{
                    'verified':True,'method':'independent_observation','observed':copy.deepcopy(declaration['origin'])})
                adapter=NoahAdapter(store,declaration,transport=transport)
                self.assertEqual('ready_for_enrollment',adapter.readiness(enrollment=True)['status'])
                transport.resolve_to='170.75.167.48'
                self.assertEqual('unqualified',adapter.readiness(enrollment=True)['status'])
                transport.resolve_to='170.75.167.47';transport.context.check_hostname=False
                self.assertEqual('unqualified',adapter.readiness(enrollment=True)['status'])
            finally:store.close()
