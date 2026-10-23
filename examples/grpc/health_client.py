"""Exercise grpc-health.rut with the existing optional grpcio example SDK."""
import argparse

import grpc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="127.0.0.1:50052")
    parser.add_argument("--ca", help="PEM CA for a TLS listener (target hostname must match)")
    args = parser.parse_args()
    # Generic SDK calls use standard protobuf wire bytes without generated stubs.
    options = (("grpc.enable_http_proxy", 0),)
    if args.ca:
        with open(args.ca, "rb") as certificate:
            credentials = grpc.ssl_channel_credentials(certificate.read())
        channel = grpc.secure_channel(args.target, credentials, options=options)
    else:
        channel = grpc.insecure_channel(args.target, options=options)
    with channel:
        grpc.channel_ready_future(channel).result(timeout=10)
        check = channel.unary_unary(
            "/grpc.health.v1.Health/Check",
            request_serializer=lambda value: value,
            response_deserializer=lambda value: value,
        )
        for request in (b"", b"\x0a\x00", b"\x0a\x15grpc.health.v1.Health", b"\x10\x01"):
            # Omitted/explicit empty service, the advertised service, and an unknown field.
            response, call = check.with_call(request, timeout=5)
            assert response == b"\x08\x01", response
            assert call.code() == grpc.StatusCode.OK, call.code()
        for request, expected in (
            (b"\x0a\x07missing", grpc.StatusCode.NOT_FOUND),
            (b"\x0a\x11example.BatchEcho", grpc.StatusCode.NOT_FOUND),
            (b"\x80", grpc.StatusCode.INVALID_ARGUMENT),
            (b"\x0a\x01\xff", grpc.StatusCode.INVALID_ARGUMENT),
        ):
            try:
                check(request, timeout=5)
            except grpc.RpcError as error:
                assert error.code() == expected, error
            else:
                raise AssertionError(f"expected {expected}")
        # Failed calls must leave the connection reusable.
        assert check(b"", timeout=5) == b"\x08\x01"
    print("health Check: SERVING, NOT_FOUND, INVALID_ARGUMENT, and reuse passed")


if __name__ == "__main__":
    main()
