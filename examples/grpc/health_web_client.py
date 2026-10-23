"""Check the local Health endpoint over HTTP/1.1 gRPC-Web; standard library only."""
import argparse
import base64
import http.client
import ssl
from urllib.parse import urlsplit


ORIGIN = "http://127.0.0.1:8080"
PATH = "/grpc.health.v1.Health/Check"


def decode_response(body, text):
    if text:
        body = base64.b64decode(body, validate=True)
    messages = []
    trailers = None
    while body:
        assert len(body) >= 5, "truncated envelope"
        flags = body[0]
        size = int.from_bytes(body[1:5], "big")
        assert len(body) >= 5 + size, "truncated payload"
        payload, body = body[5:5 + size], body[5 + size:]
        assert trailers is None, "envelope after terminal trailers"
        if flags == 0:
            messages.append(payload)
        else:
            assert flags == 0x80, flags
            trailers = dict(line.split(":", 1) for line in payload.decode("ascii").split("\r\n") if line)
    assert trailers is not None, "missing terminal trailers"
    return messages, {name: value.strip() for name, value in trailers.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:50052")
    parser.add_argument("--mode", choices=("binary", "text"), default="binary")
    parser.add_argument("--ca", help="CA file for an HTTPS listener")
    args = parser.parse_args()
    target = urlsplit(args.url)
    if target.scheme == "https":
        connection = http.client.HTTPSConnection(
            target.hostname, target.port, timeout=5,
            context=ssl.create_default_context(cafile=args.ca),
        )
    else:
        assert target.scheme == "http", "expected http:// or https://"
        connection = http.client.HTTPConnection(target.hostname, target.port, timeout=5)
    try:
        connection.request("OPTIONS", PATH, headers={
            "Origin": ORIGIN, "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-grpc-web",
        })
        response = connection.getresponse()
        response.read()
        assert response.status == 204
        assert response.getheader("Access-Control-Allow-Origin") == ORIGIN
        assert "POST" in response.getheader("Access-Control-Allow-Methods", "")
        for text in (args.mode == "text",):
            mode = "application/grpc-web-text" if text else "application/grpc-web"
            for suffix in ("", "+proto"):
                for payload, status in (
                    (b"", "0"),
                    (b"\x0a\x15grpc.health.v1.Health", "0"),
                    (b"\x0a\x11example.BatchEcho", "5"),
                    (b"\x80", "3"),
                    (b"", "0"),  # Success after errors on the same connection.
                ):
                    body = b"\x00" + len(payload).to_bytes(4, "big") + payload
                    if text:
                        body = base64.b64encode(body)
                    connection.request("POST", PATH, body, {
                        "Content-Type": mode + suffix, "X-Grpc-Web": "1", "Origin": ORIGIN,
                    })
                    response = connection.getresponse()
                    result = response.read()
                    assert response.status == 200, (response.status, result)
                    assert response.getheader("Content-Type") in (mode, mode + "+proto"), (response.getheaders(), result)
                    assert response.getheader("Access-Control-Allow-Origin") == ORIGIN
                    messages, trailers = decode_response(result, text)
                    assert trailers["grpc-status"] == status, trailers
                    assert messages == ([b"\x08\x01"] if status == "0" else []), messages
        print("gRPC-Web health: CORS, SERVING, NOT_FOUND, INVALID_ARGUMENT, reuse passed")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
