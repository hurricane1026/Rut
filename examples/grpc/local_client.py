"""Run against `rut 50052 examples/grpc-local.rut --backend epoll --shards 1`."""
import sys
import grpc

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:50052"
    # grpcio handles envelopes; the generic serializer supplies raw protobuf.
    payload = bytes.fromhex("0a070a03527574107b")
    with grpc.insecure_channel(target, options=(("grpc.enable_http_proxy", 0),)) as channel:
        grpc.channel_ready_future(channel).result(timeout=10)
        call = channel.unary_unary("/example.BatchEcho/Unary",
                                  request_serializer=lambda value: value,
                                  response_deserializer=lambda value: value)
        result, info = call.with_call(payload, timeout=5)
        assert result == payload
        assert info.code() == grpc.StatusCode.OK
        assert call(b"", timeout=5) == b""
        try:
            call(b"\x80", timeout=5)
        except grpc.RpcError as error:
            assert error.code() == grpc.StatusCode.INTERNAL, error
        else:
            raise AssertionError("malformed protobuf was accepted")
        assert call(payload, timeout=5) == payload
    print("unary protobuf echo, INTERNAL error, and connection reuse passed")

if __name__ == "__main__":
    main()
