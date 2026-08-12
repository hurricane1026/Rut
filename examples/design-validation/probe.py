#!/usr/bin/env python3
import argparse
import concurrent.futures
import http.client
import socket


def keepalive(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request("GET", "/health")
    first = conn.getresponse()
    first.read()
    assert first.status == 204, first.status
    local_port = conn.sock.getsockname()[1]
    conn.request("GET", "/health")
    second = conn.getresponse()
    second.read()
    assert second.status == 204, second.status
    assert conn.sock.getsockname()[1] == local_port
    conn.close()


def concurrency(port, count):
    def one(_):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/health")
        response = conn.getresponse()
        response.read()
        conn.close()
        return response.status

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(count, 16)) as pool:
        statuses = list(pool.map(one, range(count)))
    assert statuses == [204] * count, statuses


def pipeline(port):
    request = (
        "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n"
        "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    ).encode()
    chunks = []
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(request)
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"".join(chunks).count(b"HTTP/1.1 204 No Content") == 2:
                break
    response = b"".join(chunks)
    assert response.count(b"HTTP/1.1 204 No Content") == 2, response.decode("latin1")


def websocket(port):
    request = (
        "GET /ws HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    ).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        conn.sendall(request)
        response = conn.recv(4096)
    text = response.decode("latin1")
    assert text.startswith("HTTP/1.1 101 "), text
    assert "sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=" in text.lower(), text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("probe", choices=("keepalive", "pipeline", "concurrency", "websocket"))
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--count", type=int, default=32)
    args = parser.parse_args()
    if args.probe == "keepalive":
        keepalive(args.port)
    elif args.probe == "pipeline":
        pipeline(args.port)
    elif args.probe == "concurrency":
        concurrency(args.port, args.count)
    else:
        websocket(args.port)


if __name__ == "__main__":
    main()
