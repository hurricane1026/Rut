"""A standard gRPC backend for the Rut gateway example (h2c on loopback)."""
import argparse
from concurrent import futures

import grpc
import echo_pb2
import echo_pb2_grpc


class Echo(echo_pb2_grpc.EchoServicer):
    def metadata(self, context):
        context.send_initial_metadata((("example-bin", b"\x00\x01\xff"),))
        context.set_trailing_metadata((("example-trailer", "complete"),))

    def Unary(self, request, context):
        self.metadata(context)
        return request

    def ServerStream(self, request, context):
        self.metadata(context)
        for index in range(3):
            yield echo_pb2.Message(text=f"{request.text}:{index}")

    def ClientStream(self, requests, context):
        self.metadata(context)
        return echo_pb2.Message(text="|".join(request.text for request in requests))

    def Chat(self, requests, context):
        self.metadata(context)
        for request in requests:
            yield request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1:50051")
    args = parser.parse_args()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    echo_pb2_grpc.add_EchoServicer_to_server(Echo(), server)
    if not server.add_insecure_port(args.listen):
        raise RuntimeError(f"Cannot listen on {args.listen}")
    server.start()
    print(f"gRPC backend listening on {args.listen}", flush=True)
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(2).wait()


if __name__ == "__main__":
    main()
