#!/usr/bin/env python3
"""Loopback-only platform request identification, not a platform emulator.

Use only inside the isolated test namespace with dummy credentials. Logs request
method/path (not query, headers or body). Never forwards a request or fakes success.
"""
import socket
import argparse
import ssl
from urllib.parse import urlsplit


def describe_tls_client_hello(data):
    """Return only non-secret TLS routing metadata from one complete record."""
    if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
        return 'TLS record (not a complete ClientHello)'
    hello_end = min(len(data), 9 + int.from_bytes(data[6:9], 'big'))
    cursor = 9 + 2 + 32  # handshake header, legacy version, random
    if cursor >= hello_end:
        return 'TLS ClientHello (truncated)'
    session_len = data[cursor]
    cursor += 1 + session_len
    if cursor + 2 > hello_end:
        return 'TLS ClientHello (truncated)'
    cipher_len = int.from_bytes(data[cursor:cursor + 2], 'big')
    cursor += 2 + cipher_len
    if cursor >= hello_end:
        return 'TLS ClientHello (truncated)'
    compression_len = data[cursor]
    cursor += 1 + compression_len
    hostname = None
    versions = []
    if cursor + 2 <= hello_end:
        extensions_end = min(hello_end, cursor + 2 + int.from_bytes(data[cursor:cursor + 2], 'big'))
        cursor += 2
        while cursor + 4 <= extensions_end:
            kind = int.from_bytes(data[cursor:cursor + 2], 'big')
            size = int.from_bytes(data[cursor + 2:cursor + 4], 'big')
            value = data[cursor + 4:cursor + 4 + size]
            cursor += 4 + size
            if kind == 0 and len(value) >= 5:  # SNI extension
                name_len = int.from_bytes(value[3:5], 'big')
                hostname = value[5:5 + name_len].decode('ascii', errors='replace')
            elif kind == 43 and value:  # supported_versions extension
                versions = [f'{value[i]:02x}{value[i + 1]:02x}' for i in range(1, len(value) - 1, 2)]
    details = f'TLS ClientHello legacy={data[9]:02x}{data[10]:02x}'
    if versions:
        details += f' versions={",".join(versions)}'
    if hostname:
        details += f' sni={hostname!r}'
    return details


def describe(data):
    first = data.split(b'\r\n', 1)[0].split(b' ')
    if len(first) == 3 and first[0] in (b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS'):
        path = urlsplit(first[1].decode('ascii', errors='replace')).path
        return f'HTTP {first[0].decode()} path={path!r}'
    if data[:2] == b'\x16\x03':
        return describe_tls_client_hello(data)
    if data[:2] == b'\x15\x03':
        return 'TLS alert (HTTP path not visible)'
    return f'Unidentified protocol; first-byte={data[0]:02x}' if data else 'Connection closed without data'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tls-cert')
    parser.add_argument('--tls-key')
    args = parser.parse_args()
    context = None
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 7978))
        listener.listen(4)
        print('Platform diagnostic listening on 127.0.0.1:7978; no shard-list implementation.', flush=True)
        while True:
            connection, _ = listener.accept()
            if context:
                connection.settimeout(10)
                try:
                    connection = context.wrap_socket(connection, server_side=True)
                except (ssl.SSLError, TimeoutError, ConnectionError) as error:
                    connection.close()
                    print(f'TLS negotiation failed: {type(error).__name__}', flush=True)
                    continue
            with connection:
                connection.settimeout(10)
                try:
                    data = bytearray(connection.recv(5))
                    if data[:1] == b'\x16' and len(data) == 5:
                        record_length = int.from_bytes(data[3:5], 'big')
                        while len(data) < min(8192, 5 + record_length):
                            part = connection.recv(min(1024, 5 + record_length - len(data)))
                            if not part:
                                break
                            data.extend(part)
                    while len(data) < 8192 and b'\r\n' not in data and data[:1] != b'\x16':
                        part = connection.recv(min(1024, 8192 - len(data)))
                        if not part:
                            break
                        data.extend(part)
                    description = describe(bytes(data))
                    print(description, flush=True)
                    if description.startswith('HTTP '):
                        connection.sendall(b'HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                except (TimeoutError, ConnectionError) as error:
                    print(type(error).__name__, flush=True)


if __name__ == '__main__':
    main()
