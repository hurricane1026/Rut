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
omits default values and emits fields in increasing tag order for inferred types.
Views returned to the program own their bytes through the request Arena.

The first executable subset supports at most eight singular fields per message:
`string`/`bytes`, `bool`, `int32`/`sint32`/`sfixed32`,
`int64`/`sint64`/`sfixed64`, and `uint32`/`fixed32`. The latter two infer signed
Rut `i64` fields while enforcing the unsigned 32-bit range on encoding. Message
payloads are limited to 8 KiB and intermediate owned bytes to 256 KiB. Imports
resolve under the root proto file's directory; imports cannot be absolute or
contain empty, `.` or `..` path components. Package declarations must precede
message/service declarations. File/source/declaration budgets are bounded.

Repeated/embedded message shapes can be parsed but cannot yet be bound to the
executable codec. Floating point, uint64/fixed64, enums, oneof/optional presence,
maps, extensions/defaults, reserved declarations, custom options, public/weak
imports, proto2 and editions are rejected. Source string escapes currently cover
quotes and backslashes only. Proto2 needs separate presence/default/required
semantics before it can be enabled. No implicit protobuf JSON mapping is provided
by the general-purpose `json` operations.
