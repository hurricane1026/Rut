"""Exercise all four RPC shapes through Rut, including interactive streaming."""
import argparse
import queue
from pathlib import Path

import grpc
import echo_pb2
import echo_pb2_grpc


def check_metadata(call):
    assert ("example-bin", b"\x00\x01\xff") in call.initial_metadata()
    assert ("example-trailer", "complete") in call.trailing_metadata()
    assert call.code() == grpc.StatusCode.OK


def exercise(channel):
    grpc.channel_ready_future(channel).result(timeout=10)
    stub = echo_pb2_grpc.EchoStub(channel)
    # Larger than either hop's initial flow-control window.
    text = "hello via rut " * 20000
    response, call = stub.Unary.with_call(echo_pb2.Message(text=text), timeout=10)
    assert response.text == text
    check_metadata(call)
    print("unary: large message and binary metadata OK")

    call = stub.ServerStream(echo_pb2.Message(text="hello"), timeout=10)
    assert [message.text for message in call] == ["hello:0", "hello:1", "hello:2"]
    check_metadata(call)
    print("server streaming: OK")

    response, call = stub.ClientStream.with_call(
        (echo_pb2.Message(text=str(i)) for i in range(3)), timeout=10
    )
    assert response.text == "0|1|2"
    check_metadata(call)
    print("client streaming: OK")

    # Send the next request only after receiving a response. This proves the
    # gateway forwards bidirectionally before request END_STREAM.
    pending = queue.Queue()

    def requests():
        while True:
            text = pending.get()
            if text is None:
                return
            yield echo_pb2.Message(text=text)

    call = stub.Chat(requests(), timeout=10)
    try:
        for text in ("first", "second", "third"):
            pending.put(text)
            assert next(call).text == text
        pending.put(None)
        assert list(call) == []
        check_metadata(call)
    finally:
        pending.put(None)
        call.cancel()
    print("bidirectional streaming before request completion: OK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="127.0.0.1:50052")
    parser.add_argument("--ca", type=Path, help="Trust this PEM certificate for TLS")
    args = parser.parse_args()
    if args.ca:
        channel = grpc.secure_channel(
            args.target, grpc.ssl_channel_credentials(args.ca.read_bytes())
        )
    else:
        channel = grpc.insecure_channel(args.target)
    with channel:
        exercise(channel)


if __name__ == "__main__":
    main()
