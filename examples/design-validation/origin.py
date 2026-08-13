#!/usr/bin/env python3
import argparse
import base64
import hashlib
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            connection_tokens = {
                token.strip().lower()
                for value in self.headers.get_all("Connection", [])
                for token in value.split(",")
            }
            if (
                "upgrade" not in connection_tokens
                or self.headers.get("Sec-WebSocket-Version") != "13"
            ):
                self.send_error(400, "Invalid WebSocket upgrade")
                return
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            header = self.rfile.read(2)
            if len(header) != 2:
                self.close_connection = True
                return
            length = header[1] & 0x7F
            if (header[1] & 0x80) == 0 or length >= 126:
                self.close_connection = True
                return
            mask = self.rfile.read(4)
            payload = self.rfile.read(length)
            if len(mask) != 4 or len(payload) != length:
                self.close_connection = True
                return
            decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            self.wfile.write(bytes((0x81, len(decoded))) + decoded)
            self.wfile.flush()
            self.close_connection = True
            return

        if self.path == "/health" and self.server.health_file:
            healthy = Path(self.server.health_file).read_text().strip() == "up"
            body = b"up" if healthy else b"down"
            self.send_response(200 if healthy else 503)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/oversized":
            body = b"x" * 17000
        elif self.path == "/rewritten":
            body = f"{self.path}|{self.headers.get('X-Inject', '')}".encode()
        else:
            body = b"origin-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Origin", "local")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        response = self.path.encode() + b"|" + body
        self.send_response(200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--client-ca")
    parser.add_argument("--health-file")
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), OriginHandler)
    server.health_file = args.health_file
    if args.cert or args.key:
        if not args.cert or not args.key:
            parser.error("--cert and --key must be provided together")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        if args.client_ca:
            context.load_verify_locations(args.client_ca)
            context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
