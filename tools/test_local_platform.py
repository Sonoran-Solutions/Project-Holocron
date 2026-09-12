"""Regression checks for the observed local shard-directory protocol."""
import contextlib
import http.client
import importlib.util
import io
import json
from pathlib import Path
import threading
import unittest
from http.server import ThreadingHTTPServer


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('local_platform', ROOT / 'local-platform.py')
platform = importlib.util.module_from_spec(spec)
spec.loader.exec_module(platform)
FIXTURE = ROOT / 'fixtures/platform-responses.json'


class PlatformTests(unittest.TestCase):
    def test_shard_schema_and_address(self):
        responses = json.loads(FIXTURE.read_text())
        shards = responses['/gamepad/shardlist']['shards']
        self.assertTrue(shards)
        for shard in shards:
            for field in ('name', 'host'):
                self.assertIsInstance(shard[field], str)
            self.assertIs(type(shard['isup']), bool)
            for field in ('queuewait', 'loadlevel', 'timezone', 'focusid'):
                self.assertIs(type(shard[field]), int)
            # The outer address parser removes the final service component;
            # the transport parser must still receive a host AND port.
            endpoint, service = shard['host'].rsplit(':', 1)
            host, port = endpoint.rsplit(':', 1)
            self.assertEqual(host, 'localhost')
            self.assertEqual(int(port), 7979)
            self.assertEqual(service, 'castlehilltest')

    def test_routes_and_query_redaction(self):
        with ThreadingHTTPServer(('127.0.0.1', 0), platform.PlatformHandler) as server:
            server.responses = FIXTURE
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            output = io.StringIO()
            worker.start()
            try:
                with contextlib.redirect_stdout(output):
                    for path, expected in (
                        ('/gamepad/lastshard?token=TEST_SECRET', 200),
                        ('/gamepad/shardlist?token=TEST_SECRET', 200),
                        ('/unimplemented?token=TEST_SECRET', 501),
                    ):
                        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
                        try:
                            connection.request('GET', path)
                            response = connection.getresponse()
                            self.assertEqual(response.status, expected)
                            self.assertEqual(response.getheader('Connection'), 'close')
                            self.assertIsInstance(json.loads(response.read()), dict)
                        finally:
                            connection.close()
                self.assertNotIn('TEST_SECRET', output.getvalue())
            finally:
                server.shutdown()
                worker.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
