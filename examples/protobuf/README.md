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
maps, extensions/defaults, custom options, weak imports, proto2 and editions are
rejected. Source strings accept adjacent single/double quoted literals, standard character,
octal/hex byte and Unicode escapes. Paired UTF-16 surrogates within a literal
are combined; unpaired surrogates, invalid scalars and unknown escapes are rejected.
Import path guards apply to the decoded concatenated value. Proto2 needs separate
presence/default/required semantics before it can be enabled. No implicit protobuf JSON mapping is provided
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
number must be zero. Rut symbolic enum constants, enum JSON mapping and custom enum options are not exposed. See
[`tests/protobuf/enum.proto`](../../tests/protobuf/enum.proto) for a unary RPC schema.


Message and enum schemas may use `reserved` names/numbers, ranges and `to max`.
The compiler rejects reusing a reserved name or number, duplicate names and
overlapping ranges. Reserved enum numbers can still arrive as unknown numeric
values in proto3 messages. See [`reserved.proto`](../../tests/protobuf/reserved.proto).

`import public` re-exports message and enum types through import chains, including
RPC request/response references. Ordinary imports expose only the imported file
and its public exports; private transitive imports remain invisible. Duplicate
imports share a dependency entry; a public occurrence marks that entry public.
Import cycles and existing file/depth/byte budgets still apply.

Standard file-level generator metadata is accepted (not executed):
`java_package`, `java_outer_classname`, `java_multiple_files`,
`java_generate_equals_and_hash`, `java_string_check_utf8`, `go_package`,
`cc_generic_services`, `java_generic_services`, `py_generic_services`, `deprecated`,
`cc_enable_arenas`, `objc_class_prefix`, `csharp_namespace`, `swift_prefix`,
`php_class_prefix`, `php_namespace`, legacy `php_generic_services`,
`php_metadata_namespace`, `ruby_package`, and `optimize_for` (`SPEED`,
`CODE_SIZE`, `LITE_RUNTIME`). `php_generic_services` is retained for source
files from older protoc releases (FileOptions field 42); current FileOptions
descriptor schemas reserve that field. Names are unique per file, strings
support the escapes/concatenation above, and values must have the correct
string/bool/enum type. Unknown/custom and editions `features` options remain
rejected. These options do not enable new codecs or language generators.


Field generator hints `ctype` (`STRING`, `CORD`, `STRING_PIECE`), `jstype`
(`JS_NORMAL`, `JS_STRING`, `JS_NUMBER`), and the boolean `lazy`,
`unverified_lazy`, `deprecated`, `debug_redact` are accepted in field option
lists alongside `packed` and `json_name`. Values are type-checked and each
option may appear once per field. These hints do not change Rut's eager wire
codec, field carriers, or logging behavior. Unknown/custom, weak-field and
editions options remain unsupported.


RPC method bodies accept `option deprecated = true/false;` and
`option idempotency_level = IDEMPOTENCY_UNKNOWN/NO_SIDE_EFFECTS/IDEMPOTENT;`.
For example:

```proto
rpc Get(Request) returns (Response) {
  option idempotency_level = NO_SIDE_EFFECTS;
}
```

These standard declarations no longer prevent loading the containing `.proto`.
The compiler schema retains the deprecation flag and idempotency level for unary
and streaming methods, including methods in imported files. Values must have the
correct bool/enum spelling and each option may occur once per method. Empty RPC
bodies and semicolon-only declarations remain valid. Unknown/custom/editions
method options are still rejected by the source parser. Service bodies accept
`option deprecated = true/false;` once per service. The schema copies this flag
to each method as `service_deprecated`, independently of method deprecation;
options may appear before or after RPC declarations, including in empty services.
Other service options remain unsupported in source. Descriptor input validates
the boolean wire type/value and rejects duplicate service options.
The metadata does not enable retries, change the configured retry policy, alter
RPC routing, generate bindings or change payload encoding.

The internal source schema loader accepts proto3 `optional`, for example
`optional int32 count = 1;`, and retains its synthetic-oneof metadata just like
the descriptor loader. This is schema support: executable DSL encode/decode
still reject optional-presence fields until their value representation is wired
through the compiler. Real oneofs and maps remain unsupported.

Message and enum bodies accept `option deprecated = true;`. Enum values accept
`ZERO = 0 [deprecated = true, debug_redact = false];`. These boolean generator
hints are checked and discarded; `debug_redact` does not enable Rut log
redaction. Duplicate, mistyped, custom and other declaration options are rejected.

The internal scalar helper can now distinguish an absent optional scalar from
an explicitly present default (for example, `count = 0`) and preserve explicit
defaults during encoding. This is a runtime building block; DSL codecs still
reject optional-presence fields until compiler wiring is complete.
