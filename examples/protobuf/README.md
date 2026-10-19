# Built-in protobuf compiler

Run from the repository root:

```bash
./build/src/rut examples/protobuf.rut --port 8080 --backend epoll
```

The sibling `rut-compile` reads `message.proto`, generates an internal message
type and emits field-specific LLVM IR as part of the handler. Deployment and
ordinary builds require no protoc, Python protobuf package, generated bindings
or protobuf runtime library. Source schemas are needed when compiling/reloading;
compiled handlers retain no descriptor or file-path lookup on the request path.

For example, POST the bytes `0a 03 52 75 74 10 7b` to `/protobuf` to encode
`Message { text: "Rut", id: 123 }`; the response contains the same protobuf
payload. The HTTP example demonstrates the codec; it does not add gRPC envelopes,
service dispatch or HTTP/JSON transcoding. The response currently uses the
ordinary response builder's default content type.

```swift
// Type inferred from the schema, including 64-bit integer fields.
guard let message = protobuf.decode("protobuf/message.proto", "example.Message", req.body) else {
    return 400
}
guard let bytes = protobuf.encode("protobuf/message.proto", "example.Message", message) else {
    return 500
}
```

Both operations return optional values. Decode failures include malformed wire
input, invalid UTF-8 for `string`, oversized messages and request Arena exhaustion.
Absent proto3 scalar fields receive their default values; the final correctly
typed duplicate scalar value wins. Unknown fields and known fields with another
wire type are skipped for supported wire types (0, 1, 2, 5); deprecated group
wire types are rejected. Unknown fields are not retained when encoding. Encoding
omits singular default values and emits fields in increasing tag order for inferred types.
Views returned to the program own their bytes through the request Arena.

The first executable subset supports at most eight fields per message:
`string`/`bytes`, `bool`, `int32`/`sint32`/`sfixed32`,
`int64`/`sint64`/`sfixed64`, and `uint32`/`fixed32`, plus acyclic singular embedded messages. The latter scalar types two infer signed
Rut `i64` fields while enforcing the unsigned 32-bit range on encoding. Message
payloads are limited to 8 KiB and intermediate owned bytes to 256 KiB. Imports
resolve under the root proto file's directory; imports cannot be absolute or
contain empty, `.` or `..` path components. Package declarations must precede
message/service declarations. File/source/declaration budgets are bounded.

Embedded fields infer nested structs; access them with ordinary member access
(e.g. `let text = message.child.text`). Each message has at most eight fields and
at most eight nested edges are supported. Recursive schemas are rejected.
Duplicate submessages merge, but each wire occurrence must be independently
well-formed. Absent messages expose recursively default-valued structs; message
presence is not exposed, and re-encoding defaults emits empty embedded messages.
Repeated supported scalar and acyclic message fields infer immutable `[T]` arrays. Read `.count`,
`.isEmpty` or optional `.first`; typed `let` aliases preserve the element type.
Arrays do not grow or expose mutation/indexing/iteration. Each array is limited
to 512 elements and the request Arena to 4,096 array elements plus the existing
256 KiB value-memory budget. Repeated numeric scalar values may be packed/unpacked on input;
encoding emits unpacked occurrences and preserves defaults/empty elements.
Repeated message elements are native structs; `guard let entry = batch.entries.first`
unwraps the optional before ordinary field access. All elements and descendants
are validated before decode returns. Each contiguous slot allocation must also fit
one 16 KiB Arena slice minus its block header; oversized slot regions fail decode.
Array-bearing routes with `wait`
are rejected until collection suspension ownership is implemented. Floating point, uint64/fixed64, oneof/optional presence,
maps, extensions/defaults, reserved declarations, custom options, public/weak
imports, proto2 and editions are rejected. Source string escapes currently cover
quotes and backslashes only. Proto2 needs separate presence/default/required
semantics before it can be enabled. No implicit protobuf JSON mapping is provided
by the general-purpose `json` operations.

`examples/protobuf-nested.rut` shows `example.Envelope` with a nested `Message`.
POST `0a 07 0a 03 52 75 74 10 7b` to `/protobuf/nested` for a roundtrip of
`child.text = "Rut"` and `child.id = 123`; ordinary member access reads the
nested values. Inputs are raw protobuf payloads, without gRPC envelopes.

`examples/protobuf-repeated.rut` shows `example.Batch` with immutable scalar
arrays. POST `0a 03 01 02 00 12 01 78 12 00` to `/protobuf/repeated`;
the response is `08 01 08 02 08 00 12 01 78 12 00`. The packed values
`[1, 2, 0]` become unpacked occurrences; both string elements (`"x"`, `""`)
are preserved.

`examples/protobuf-messages.rut` shows `example.MessageBatch` with repeated
`Message` structs. POST `0a 07 0a 03 52 75 74 10 7b` to `/protobuf/messages`
for a roundtrip. Child repeated arrays and singular embedded messages share the
same request budgets. This extends the payload codec; HTTP/JSON transcoding and
service dispatch remain separate work.


`examples/protobuf-framed.rut` composes `grpc.unframe` and `grpc.frame` with the
message-array codec. For the example above, prepend `00 00 00 00 09` to the raw
payload and POST it to `/protobuf/framed`; the same framed message is returned.
Exactly one uncompressed envelope is accepted, with at most 8 KiB of payload.
Malformed framing returns HTTP 400; invalid protobuf returns HTTP 422. This is a
byte-codec demonstration, not a native gRPC endpoint: service dispatch,
`application/grpc` response headers and `grpc-status` trailers are not generated.


Proto3 enum fields are numeric `i32` values in Rut; repeated enum fields are
immutable `[i32]`. Unknown numbers and negative values round-trip. The schema
supports nested/imported enums and `option allow_alias = true`; the first declared
number must be zero. Rut symbolic enum constants, enum JSON mapping, reserved enum
declarations and custom enum options are not exposed. See
[`tests/protobuf/enum.proto`](../../tests/protobuf/enum.proto) for a unary RPC schema.
