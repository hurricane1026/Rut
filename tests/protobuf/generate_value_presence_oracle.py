"""Optional reference generator using Google's protobuf runtime (6.33.5)."""
from pathlib import Path
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

file = descriptor_pb2.FileDescriptorProto(name="presence.proto", syntax="proto3")
message = file.message_type.add(name="Presence")
types = [3, 5, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18]
# A proto3 enum must declare zero first.
enum = file.enum_type.add(name="Choice")
enum.value.add(name="ZERO", number=0)
for index, kind in enumerate(types):
    name = f"field_{index}"
    message.oneof_decl.add(name="_" + name)
    field = message.field.add(name=name, number=index + 1, type=kind,
                              label=1, proto3_optional=True, oneof_index=index)
    if kind == 14:
        field.type_name = ".Choice"
pool = descriptor_pool.DescriptorPool()
pool.Add(file)
cls = message_factory.GetMessageClass(pool.FindMessageTypeByName("Presence"))
value = cls()
assert value.SerializeToString() == b""
for index, kind in enumerate(types):
    setattr(value, f"field_{index}", "" if kind == 9 else b"" if kind == 12 else False if kind == 8 else 0)
    assert value.HasField(f"field_{index}")
wire = value.SerializeToString(deterministic=True)
Path(__file__).with_name("value_presence_oracle.inc").write_text(
    "// Generated with Google's protobuf 6.33.5; all singular fields explicitly present.\n"
    "inline constexpr unsigned char kValuePresenceDefaults[] = {" + ", ".join(map(str, wire)) + "};\n")
