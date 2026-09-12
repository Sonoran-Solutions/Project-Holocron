#!/usr/bin/env python3
"""Local HTTPS shard directory for the isolated client experiment.

Only the two observed GET routes are implemented. Response field names/types
are traced from ClientServices::receivedShardList in the inspected executable.
Other routes return 501 so missing protocol work remains visible.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
from urllib.parse import urlsplit


class PlatformHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass  # Base implementation includes full query strings.

    def do_GET(self):
        path = urlsplit(self.path).path
        try:
            responses = json.loads(self.server.responses.read_text())
            response = responses.get(path)
            status = 200 if response is not None else 501
            body = json.dumps(response if response is not None else {'error': 'Not implemented'}).encode()
        except (OSError, ValueError):
            status, body = 500, b'{"error":"Invalid local response configuration"}'
        print(f'GET {path!r} -> {status}', flush=True)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):
        print(f'POST {urlsplit(self.path).path!r} -> 501', flush=True)
        self.send_error(501, 'Not implemented')
        self.close_connection = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tls-cert', required=True)
    parser.add_argument('--tls-key', required=True)
    parser.add_argument('--responses', required=True, type=Path)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.tls_cert, args.tls_key)
    with ThreadingHTTPServer(('127.0.0.1', 7978), PlatformHandler) as server:
        server.responses = args.responses
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print('Local HTTPS platform listening on 127.0.0.1:7978', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()
