These proto3 inputs exercise the internal compiler descriptor loader. They do
not enable JSON/gRPC transcoding or expose protobuf functions to Rut programs.

`schema_descriptor.inc` contains the `FileDescriptorSet` produced by
`grpc_tools.protoc --include_imports`. Tests compile the checked-in byte array;
Python, protoc and protobuf libraries are not test/build dependencies.

To regenerate using the existing gRPC example development environment, from the
repository root:

```bash
python -m grpc_tools.protoc -Itests/protobuf --include_imports \
  --descriptor_set_out=/tmp/schema.pb tests/protobuf/schema.proto
```

Convert those bytes to the C++ `kDescriptor` array in `schema_descriptor.inc`;
the generated comment records the protobuf version. Keep both imported files
in the descriptor set. The tests compare normalized types, packing, JSON names,
recursive/imported references and all four RPC streaming shapes against these
inputs. Hand-built malformed descriptors separately cover rejection paths.

`codec.proto` is compiled directly by the built-in source loader for JIT tests.
`codec_message.inc` is an independent reference protobuf serialization of the
boundary values listed in `test_protobuf_value.cc`; it tests exact wire bytes,
including signed minima, uint32 maximum and embedded NUL/non-UTF-8 bytes. The
maximum-tag message also exercises field-operation immediates above 32 bits.
Neither fixture requires reference tools to run. The native-program regression
creates its own temporary proto source and deletes it after compilation.
