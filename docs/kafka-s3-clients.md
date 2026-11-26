# Kafka and S3 clients in Rut

## Kafka

The [Kafka library](../lib/clients/kafka.rut) implements ApiVersions v0,
single-topic Metadata v4, and single-partition ListOffsets v1. Metadata skips
automatic topic creation. The library returns binary response bodies for
ApiVersions and Metadata. For ListOffsets it checks the returned topic and
partition and exposes the 64-bit offset as decimal text. Pass `true` to
`listOffset` for the earliest available offset or `false` for the latest.

Run the [Kafka example](../examples/kafka-client.rut) against a broker that
supports these protocol versions. Point the example at the partition leader
for the ListOffsets request. It uses one TCP connection per HTTP request.

```sh
export KAFKA_ENDPOINT='{"address":"127.0.0.1","port":9092}'
export KAFKA_TOPIC='orders'
build/src/rut 8080 examples/kafka-client.rut --backend epoll --shards 1
curl --fail http://127.0.0.1:8080/versions --output versions.bin
curl --fail http://127.0.0.1:8080/metadata --output metadata.bin
curl --fail http://127.0.0.1:8080/offset/0
```

The endpoint can use verified TLS through the [TCP policy](net-clients.md#endpoint-configuration).
Keep one request in flight per connection and close the connection after a
failed exchange. A response frame can hold up to 8192 bytes, including the
correlation ID. Each socket operation has a one-second deadline. This profile
covers protocol discovery, metadata and offsets. Producing, fetching, consumer
groups, SASL and automatic leader selection are outside its scope.

## S3

The [S3 library](../lib/clients/s3.rut) sends GetObject, PutObject,
DeleteObject and ListObjectsV2 requests over verified HTTPS. Provide one fixed
endpoint policy per operation through `S3_GET_ENDPOINT`, `S3_PUT_ENDPOINT`,
`S3_DELETE_ENDPOINT` and `S3_LIST_ENDPOINT`. Generate the presigned URLs with
the corresponding HTTP methods. The signed headers must be compatible with
the request emitted by the client. Prefer URLs that sign only `host`.

Each environment value has this shape:

```json
{
  "address": "192.0.2.20",
  "port": 443,
  "serverName": "bucket.s3.us-east-1.amazonaws.com",
  "caFile": "/path/to/ca-bundle.pem",
  "path": "/object%20name?X-Amz-Algorithm=AWS4-HMAC-SHA256&..."
}
```

Use the URL hostname for `serverName`, a reachable IPv4 address for
`address`, and copy the encoded path and query verbatim into `path`.
The encoded path and query together must fit within 1023 bytes. A non-default
port is included in the HTTP Host header. Configure a
ListObjectsV2 URL with `list-type=2` and any desired signed list parameters.
Refresh the configured URL and reload the program before the signature
expires. Keep the signed URL private.

With all four policies configured, run the
[S3 example](../examples/s3-client.rut):

```sh
build/src/rut 8080 examples/s3-client.rut --backend epoll --shards 1
curl --fail http://127.0.0.1:8080/object
curl --fail -X PUT --data-binary 'hello' http://127.0.0.1:8080/object
curl --fail http://127.0.0.1:8080/objects
curl --fail -X DELETE http://127.0.0.1:8080/object
```

PUT accepts up to 4096 bytes of UTF-8, subject to the request JSON envelope
limit. GET returns text and LIST returns one XML page. Both share the
`httpCall` response JSON limit of 8192 bytes, including its metadata and
escaped body. This profile uses externally signed URLs and fixed paths.
Keep the examples local or add caller authorization before exposing them.
